//! The source connector that reads Entra ID logs through Microsoft Graph.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aegis_contracts::common::TimeRange;
use aegis_contracts::event::EventSource;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use async_trait::async_trait;
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::client::{Feed, GraphClient};
use super::config::{EntraConfig, Settings};
use super::normalize::{NormalizeError, PRODUCT, VENDOR};

/// A source connector for Microsoft Entra ID.
///
/// The connector reads these logs through Microsoft Graph:
///
/// - User sign-ins: `GET {graph_base}/v1.0/auditLogs/signIns`.
/// - Service principal sign-ins (optional): `GET {graph_base}/beta/auditLogs/signIns` with
///   the `servicePrincipal` filter.
/// - Directory audits: `GET {graph_base}/v1.0/auditLogs/directoryAudits`.
///
/// The connector only reads. It gets its token with the OAuth 2.0 client credentials grant
/// and keeps the token until shortly before the expiry.
///
/// # Live stream
///
/// [`stream`](SourceConnector::stream) reads all feeds, waits for the poll interval, and
/// reads again. Each batch has the new events of all feeds in time order.
///
/// The cursor holds one time for each feed: the time of the newest record that the
/// connector read. Each read starts `lookback` before this time, because Entra ID can add a
/// record late. The connector does not emit a record two times in one stream. After a
/// restart, it can emit the records of the lookback period again. These events have the
/// same identifiers as before.
///
/// After a long stop, the connector reads the missed time in ranges of `max_window`. Then
/// the cursor of a feed is the end of the last range that the connector read completely.
///
/// A stream with no cursor starts at the present time. Its first batch is empty and holds
/// the start position as the cursor. Save this cursor, so that a stream that opens again
/// after an error continues from the same start.
///
/// A bare RFC 3339 time is also a valid stream cursor. It sets the start time of all feeds.
///
/// # Errors
///
/// | HTTP status | Error |
/// | --- | --- |
/// | 401, 403 | [`Error::Unauthorized`] |
/// | 429 | [`Error::RateLimited`], after the waits for `Retry-After` that the limits permit |
/// | 408, 504 | [`Error::Timeout`] |
/// | Other 5xx | [`Error::Unavailable`] |
///
/// A record that has no identifier or no valid time cannot become an event. The connector
/// writes a warning to the log, counts the record in
/// [`rejected_records`](Self::rejected_records), and continues. A live stream reports such
/// a record one time, although it reads the record again in the lookback period.
pub struct EntraSource {
    inner: Arc<Inner>,
}

struct Inner {
    settings: Arc<Settings>,
    client: GraphClient,
    event_source: EventSource,
    rejected: AtomicU64,
}

impl EntraSource {
    /// Makes the connector. The function does not send a request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the configuration is not valid or the client secret is
    /// missing.
    pub fn new(config: EntraConfig) -> Result<Self> {
        let settings = Arc::new(config.validate(|name| std::env::var(name).ok())?);
        let client = GraphClient::new(settings.clone())?;
        let event_source = EventSource::new(settings.name.clone(), VENDOR, PRODUCT)
            .with_tenant(settings.tenant_id.to_ascii_lowercase());
        Ok(Self {
            inner: Arc::new(Inner {
                settings,
                client,
                event_source,
                rejected: AtomicU64::new(0),
            }),
        })
    }

    /// Returns the number of records that the connector could not convert to events.
    #[must_use]
    pub fn rejected_records(&self) -> u64 {
        self.inner.rejected.load(Ordering::Relaxed)
    }
}

/// A record that cannot become an event.
struct Rejected {
    /// The SHA-256 digest of the record. It identifies a record that has no identifier.
    digest: [u8; 32],
    /// The identifier of the record, or an empty string.
    record_id: String,
    error: NormalizeError,
}

/// The result of the conversion of the records of one page or one read.
struct Normalized {
    /// The events. Each event comes with the identifier of its record.
    events: Vec<(String, Event)>,
    rejected: Vec<Rejected>,
}

impl Inner {
    /// Converts records to events. The caller reports the rejected records.
    fn normalize(&self, feed: Feed, records: &[Value]) -> Normalized {
        let mut events = Vec::with_capacity(records.len());
        let mut rejected = Vec::new();
        for record in records {
            let record_id = record.get("id").and_then(Value::as_str).unwrap_or_default();
            match feed.normalize(record, &self.event_source) {
                Ok(event) => events.push((record_id.to_owned(), event)),
                Err(error) => rejected.push(Rejected {
                    digest: Sha256::digest(record.to_string().as_bytes()).into(),
                    record_id: record_id.to_owned(),
                    error,
                }),
            }
        }
        Normalized { events, rejected }
    }

    /// Counts a rejected record and writes a warning to the log. The warning has no payload.
    fn report(&self, feed: Feed, rejected: &Rejected) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            connector = %self.settings.name,
            feed = feed.key(),
            record_id = %rejected.record_id,
            error = %rejected.error,
            "rejected a record that cannot become an event"
        );
    }

    /// Returns the feed that the backfill reads after `feed`.
    fn feed_after(&self, feed: Feed) -> Option<Feed> {
        self.settings
            .feeds
            .iter()
            .skip_while(|candidate| **candidate != feed)
            .nth(1)
            .copied()
    }
}

/// Rounds a time down to a whole second.
fn whole_second(time: DateTime<Utc>) -> DateTime<Utc> {
    time.duration_trunc(TimeDelta::seconds(1)).unwrap_or(time)
}

/// The position of the backfill: the feed and the link to its next page.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchCursor {
    feed: Feed,
    /// The `@odata.nextLink` of the last page. `None` selects the first page of the feed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
}

/// Reads the positions of the live stream from a cursor.
fn stream_positions(cursor: &str) -> Result<BTreeMap<Feed, DateTime<Utc>>> {
    let invalid = || {
        Error::InvalidInput(
            "the entra stream cursor is not an RFC 3339 time or a JSON object of feed times"
                .to_owned(),
        )
    };
    let cursor = cursor.trim();
    if let Ok(time) = DateTime::parse_from_rfc3339(cursor) {
        let time = time.with_timezone(&Utc);
        return Ok([
            Feed::SignIns,
            Feed::ServicePrincipalSignIns,
            Feed::DirectoryAudits,
        ]
        .into_iter()
        .map(|feed| (feed, time))
        .collect());
    }
    serde_json::from_str(cursor).map_err(|_| invalid())
}

/// The state of one live stream.
struct Poller {
    inner: Arc<Inner>,
    /// For each feed, the time through which the stream read the feed.
    positions: BTreeMap<Feed, DateTime<Utc>>,
    /// The stream does not emit records before this time.
    floor: DateTime<Utc>,
    /// For each feed, the records in the lookback period that the stream already emitted.
    seen: BTreeMap<Feed, HashMap<String, DateTime<Utc>>>,
    /// For each feed, the digests of the records that the last read rejected.
    rejected: BTreeMap<Feed, HashSet<[u8; 32]>>,
    /// `true` if the stream must wait for the poll interval before the next read.
    wait: bool,
    /// `true` if the stream must give its start position before the first read.
    announce: bool,
}

/// The result of the read of one feed, before the stream accepts it.
struct FeedRead {
    feed: Feed,
    position: DateTime<Utc>,
    fresh: Vec<(String, Event)>,
    rejected: Vec<Rejected>,
    catching_up: bool,
}

impl Poller {
    /// Returns the start of the next read of a feed at `position`.
    fn lower_bound(&self, position: DateTime<Utc>) -> DateTime<Utc> {
        let start = position
            .checked_sub_signed(self.inner.settings.lookback)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        whole_second(start.max(self.floor))
    }

    async fn read_feed(&self, feed: Feed, now: DateTime<Utc>) -> Result<FeedRead> {
        let settings = &self.inner.settings;
        let position = self.positions.get(&feed).copied().unwrap_or(self.floor);
        let lower = self.lower_bound(position);
        // After a long stop, read the missed time in ranges of `max_window`.
        let upper = lower
            .checked_add_signed(settings.max_window)
            .filter(|upper| *upper < now);
        let records = self.inner.client.list(feed, lower, upper).await?;

        let seen = self.seen.get(&feed);
        let mut newest = position;
        let mut fresh = Vec::new();
        // A new record can move the pages during the read. Then two pages hold one record.
        let mut in_this_read = HashSet::new();
        let normalized = self.inner.normalize(feed, &records);
        for (record_id, event) in normalized.events {
            if event.time < lower || upper.is_some_and(|upper| event.time > upper) {
                continue;
            }
            newest = newest.max(event.time);
            if !seen.is_some_and(|seen| seen.contains_key(&record_id))
                && in_this_read.insert(record_id.clone())
            {
                fresh.push((record_id, event));
            }
        }
        Ok(FeedRead {
            feed,
            position: upper.map_or(newest, |upper| position.max(upper)),
            fresh,
            rejected: normalized.rejected,
            catching_up: upper.is_some(),
        })
    }

    /// Reads all feeds one time. Returns `None` if there are no new events and no progress.
    async fn poll(&mut self) -> Result<Option<EventBatch>> {
        let now = Utc::now();
        // Read all feeds before the state changes. An error then changes nothing, and the
        // next read repeats the same ranges.
        let mut reads = Vec::with_capacity(self.inner.settings.feeds.len());
        for feed in &self.inner.settings.feeds {
            reads.push(self.read_feed(*feed, now).await?);
        }

        let mut events = Vec::new();
        let mut progressed = false;
        let mut catching_up = false;
        for read in reads {
            progressed |= self.positions.insert(read.feed, read.position) != Some(read.position);
            catching_up |= read.catching_up;
            let keep_from = self.lower_bound(read.position);
            let seen = self.seen.entry(read.feed).or_default();
            for (record_id, event) in read.fresh {
                seen.insert(record_id, event.time);
                events.push(event);
            }
            seen.retain(|_, time| *time >= keep_from);

            // The next read returns a rejected record again while the record is in the
            // lookback period. Report only a record that the last read did not reject.
            let known = self.rejected.entry(read.feed).or_default();
            let mut digests = HashSet::with_capacity(read.rejected.len());
            for rejected in &read.rejected {
                if digests.insert(rejected.digest) && !known.contains(&rejected.digest) {
                    self.inner.report(read.feed, rejected);
                }
            }
            *known = digests;
        }
        self.wait = !catching_up;
        if events.is_empty() && !progressed {
            return Ok(None);
        }
        events.sort_by_key(|event| event.time);
        Ok(Some(EventBatch {
            events,
            next_cursor: Some(self.cursor()?),
        }))
    }

    /// Returns the positions of all feeds as a stream cursor.
    fn cursor(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.positions)?)
    }

    /// Returns the next batch or the next error of the stream.
    async fn next(&mut self) -> Result<EventBatch> {
        if std::mem::take(&mut self.announce) {
            // A caller that saves this cursor continues from the start of this stream after
            // an error. Without it, a new stream starts at a later time and loses the
            // records between the two starts.
            return Ok(EventBatch {
                events: Vec::new(),
                next_cursor: Some(self.cursor()?),
            });
        }
        loop {
            if self.wait {
                tokio::time::sleep(self.inner.settings.poll_interval).await;
            }
            self.wait = true;
            if let Some(batch) = self.poll().await? {
                return Ok(batch);
            }
        }
    }
}

#[async_trait]
impl SourceConnector for EntraSource {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.inner.settings.name.clone(),
            vendor: VENDOR.to_owned(),
            product: PRODUCT.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Gets a token and reads one record of each enabled feed.
    async fn check(&self) -> Result<()> {
        self.inner.client.authenticate().await?;
        let since = whole_second(Utc::now())
            .checked_sub_signed(TimeDelta::minutes(5))
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        for feed in &self.inner.settings.feeds {
            let url = self.inner.client.first_page(*feed, since, None, 1)?;
            self.inner.client.get_page(*feed, &url).await?;
        }
        Ok(())
    }

    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        let opened_at = Utc::now();
        let (mut positions, floor) = match cursor.as_deref() {
            Some(cursor) => (stream_positions(cursor)?, DateTime::<Utc>::MIN_UTC),
            // With no cursor, the stream starts at the present time.
            None => (BTreeMap::new(), opened_at),
        };
        for feed in &self.inner.settings.feeds {
            positions.entry(*feed).or_insert(opened_at);
        }
        let poller = Poller {
            inner: self.inner.clone(),
            positions,
            floor,
            seen: BTreeMap::new(),
            rejected: BTreeMap::new(),
            wait: false,
            announce: cursor.is_none(),
        };
        Ok(Box::pin(futures::stream::unfold(
            poller,
            |mut poller| async move { Some((poller.next().await, poller)) },
        )))
    }

    /// Reads one page of one feed. The backfill reads the feeds one after the other.
    ///
    /// The events of one page are in time order. The pages of a feed go from the newest
    /// records to the oldest records, because Microsoft Graph sorts the logs in this order.
    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        let inner = &self.inner;
        let position = match cursor.as_deref() {
            Some(cursor) => serde_json::from_str::<FetchCursor>(cursor).map_err(|_| {
                Error::InvalidInput("the entra backfill cursor is not valid".to_owned())
            })?,
            None => FetchCursor {
                feed: inner.settings.feeds.first().copied().ok_or_else(|| {
                    Error::Config(format!(
                        "entra source {}: no feed is enabled",
                        inner.settings.name
                    ))
                })?,
                link: None,
            },
        };
        let feed = position.feed;
        if !inner.settings.feeds.contains(&feed) {
            return Err(Error::InvalidInput(format!(
                "the entra backfill cursor names the feed {}, which is not enabled",
                feed.key()
            )));
        }
        if range.start >= range.end {
            return Ok(EventBatch {
                events: Vec::new(),
                next_cursor: None,
            });
        }

        let url = match position.link.as_deref() {
            Some(link) => inner.client.checked_link(link).map_err(|problem| {
                Error::InvalidInput(format!("the entra backfill cursor is not valid: {problem}"))
            })?,
            None => {
                // The filter has whole seconds and includes its end. Round the end up, and
                // remove the records outside the range below.
                let upper = whole_second(range.end)
                    .checked_add_signed(TimeDelta::seconds(1))
                    .unwrap_or(range.end);
                inner.client.first_page(
                    feed,
                    whole_second(range.start),
                    Some(upper),
                    inner.settings.page_size,
                )?
            }
        };
        let page = inner.client.get_page(feed, &url).await?;

        let normalized = inner.normalize(feed, &page.records);
        for rejected in &normalized.rejected {
            inner.report(feed, rejected);
        }
        let mut events: Vec<Event> = normalized
            .events
            .into_iter()
            .map(|(_, event)| event)
            .filter(|event| range.contains(event.time))
            .collect();
        events.sort_by_key(|event| event.time);

        let next = match page.next_link {
            Some(link) => Some(FetchCursor {
                feed,
                link: Some(link.into()),
            }),
            None => inner
                .feed_after(feed)
                .map(|feed| FetchCursor { feed, link: None }),
        };
        Ok(EventBatch {
            events,
            next_cursor: next.map(|next| serde_json::to_string(&next)).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn a_bare_time_is_a_cursor_for_all_feeds() {
        let positions = stream_positions("2026-11-03T09:00:05.25Z").unwrap();
        let time =
            Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 5).unwrap() + TimeDelta::milliseconds(250);
        assert_eq!(
            positions,
            BTreeMap::from([
                (Feed::SignIns, time),
                (Feed::ServicePrincipalSignIns, time),
                (Feed::DirectoryAudits, time),
            ])
        );
    }

    #[test]
    fn a_json_cursor_gives_one_time_for_each_feed_and_round_trips() {
        let text = r#"{"sign_ins":"2026-11-03T09:10:31Z","directory_audits":"2026-11-03T09:10:46.123456700Z"}"#;
        let positions = stream_positions(text).unwrap();
        assert_eq!(positions.len(), 2);
        assert_eq!(
            positions[&Feed::SignIns],
            Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 31).unwrap()
        );
        assert_eq!(
            positions[&Feed::DirectoryAudits],
            Utc.with_ymd_and_hms(2026, 11, 3, 9, 10, 46).unwrap()
                + TimeDelta::nanoseconds(123_456_700)
        );
        let encoded = serde_json::to_string(&positions).unwrap();
        assert_eq!(stream_positions(&encoded).unwrap(), positions);
    }

    #[test]
    fn a_cursor_with_other_content_is_invalid_input() {
        for cursor in [
            "",
            "42",
            "yesterday",
            r#"{"sign_in":"2026-11-03T09:10:31Z"}"#,
            r#"{"sign_ins":"not a time"}"#,
            r#"{"feed":"sign_ins"}"#,
        ] {
            let error = stream_positions(cursor).unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{cursor:?}");
        }
    }

    #[test]
    fn whole_second_removes_the_fraction() {
        let time = Utc.with_ymd_and_hms(2026, 11, 3, 9, 0, 5).unwrap();
        assert_eq!(
            whole_second(time + TimeDelta::nanoseconds(999_999_999)),
            time
        );
        assert_eq!(whole_second(time), time);
    }
}
