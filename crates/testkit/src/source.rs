use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use async_trait::async_trait;

/// A source connector that serves a fixed list of events.
///
/// [`stream`](SourceConnector::stream) yields all events and then ends. The cursor of this
/// connector is the number of events that the caller already has.
pub struct StaticSource {
    name: String,
    events: Vec<Event>,
    page_size: usize,
}

impl StaticSource {
    /// Makes a connector that serves `events` in time order.
    pub fn new(name: impl Into<String>, mut events: Vec<Event>) -> Self {
        events.sort_by_key(|event| event.time);
        Self {
            name: name.into(),
            events,
            page_size: 100,
        }
    }

    /// Sets the number of events in one page of a batch read.
    #[must_use]
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size.max(1);
        self
    }

    fn offset(cursor: Option<&str>) -> Result<usize> {
        cursor.map_or(Ok(0), |text| {
            text.parse()
                .map_err(|_| Error::InvalidInput(format!("cursor {text:?} is not a number")))
        })
    }
}

#[async_trait]
impl SourceConnector for StaticSource {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.name.clone(),
            vendor: "aegis".to_owned(),
            product: "static".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    async fn check(&self) -> Result<()> {
        Ok(())
    }

    async fn stream(&self, cursor: Option<String>) -> Result<EventStream> {
        let offset = Self::offset(cursor.as_deref())?;
        let events: Vec<Result<Event>> = self.events.iter().skip(offset).cloned().map(Ok).collect();
        Ok(Box::pin(futures::stream::iter(events)))
    }

    async fn fetch(&self, range: TimeRange, cursor: Option<String>) -> Result<EventBatch> {
        let offset = Self::offset(cursor.as_deref())?;
        let in_range: Vec<&Event> = self
            .events
            .iter()
            .filter(|event| range.contains(event.time))
            .collect();
        let events: Vec<Event> = in_range
            .iter()
            .skip(offset)
            .take(self.page_size)
            .map(|event| (*event).clone())
            .collect();
        let next_offset = offset + events.len();
        Ok(EventBatch {
            events,
            next_cursor: (next_offset < in_range.len()).then(|| next_offset.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use futures::StreamExt;

    use super::*;
    use crate::fixtures;

    fn events(count: i64) -> Vec<Event> {
        (0..count)
            .rev()
            .map(|index| {
                fixtures::sign_in(
                    fixtures::base_time() + Duration::seconds(index),
                    "user-1",
                    fixtures::OFFICE_IP,
                    true,
                )
            })
            .collect()
    }

    fn all_time() -> TimeRange {
        TimeRange {
            start: DateTime::<Utc>::MIN_UTC,
            end: DateTime::<Utc>::MAX_UTC,
        }
    }

    #[tokio::test]
    async fn stream_yields_all_events_in_time_order_and_then_ends() {
        let source = StaticSource::new("static", events(5));
        let times: Vec<DateTime<Utc>> = source
            .stream(None)
            .await
            .unwrap()
            .map(|event| event.unwrap().time)
            .collect()
            .await;
        assert_eq!(times.len(), 5);
        assert!(times.is_sorted());
        let resumed = source
            .stream(Some("3".to_owned()))
            .await
            .unwrap()
            .count()
            .await;
        assert_eq!(resumed, 2);
    }

    #[tokio::test]
    async fn fetch_pages_through_the_range() {
        let source = StaticSource::new("static", events(5)).with_page_size(2);
        let mut cursor = None;
        let mut pages = Vec::new();
        loop {
            let batch = source.fetch(all_time(), cursor).await.unwrap();
            pages.push(batch.events.len());
            cursor = batch.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(pages, [2, 2, 1]);
    }

    #[tokio::test]
    async fn fetch_returns_only_events_in_the_range() {
        let source = StaticSource::new("static", events(5));
        let range = TimeRange {
            start: fixtures::base_time() + Duration::seconds(1),
            end: fixtures::base_time() + Duration::seconds(3),
        };
        let batch = source.fetch(range, None).await.unwrap();
        assert_eq!(batch.events.len(), 2);
        assert_eq!(batch.next_cursor, None);
        assert!(batch.events.iter().all(|event| range.contains(event.time)));
    }

    #[tokio::test]
    async fn a_cursor_that_is_not_a_number_is_invalid_input() {
        let source = StaticSource::new("static", events(1));
        let error = source
            .fetch(all_time(), Some("abc".to_owned()))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidInput(message) if message.contains("abc")));
        assert_eq!(source.info().name, "static");
        source.check().await.unwrap();
    }
}
