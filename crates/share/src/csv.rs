//! The CSV form of an indicator set.
//!
//! The file follows RFC 4180: one header line, lines that end with CR LF, and quotes
//! around a field that has a comma, a quote, or a line break.
//!
//! | Column | Contents |
//! | --- | --- |
//! | `type` | `ipv4`, `ipv6`, `domain`, or `user_agent` |
//! | `value` | The address, the domain, or the user agent |
//! | `basis` | `malicious_activity` or `anomalous_activity` |
//! | `first_seen` | The time of the first evidence, in UTC |
//! | `last_seen` | The time of the last evidence, in UTC |
//! | `events` | The number of evidence events that show the value |
//! | `detections` | The number of detections that give the value |
//! | `techniques` | The ATT&CK technique identifiers, with `;` between them |
//! | `tlp` | The TLP label of the row, for example `TLP:AMBER` |
//!
//! # Formulas
//!
//! A spreadsheet program runs a cell that starts with `=`, `+`, `-`, or `@` as a
//! formula. A user agent is text from an attacker. The writer thus puts an apostrophe
//! before such a value. A program that reads the file must remove that apostrophe.

use crate::indicator::IndicatorSet;
use crate::stix::Tlp;
use crate::text::{time_text, token};

/// The header line of the CSV export, without the line end.
pub const CSV_HEADER: &str =
    "type,value,basis,first_seen,last_seen,events,detections,techniques,tlp";

/// Returns one field in its CSV form.
fn field(text: &str) -> String {
    let guarded = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_owned()
    };
    if guarded.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

impl IndicatorSet {
    /// Returns the indicators as CSV text. Each row carries the TLP label `tlp`.
    #[must_use]
    pub fn to_csv(&self, tlp: Tlp) -> String {
        let mut text = String::from(CSV_HEADER);
        text.push_str("\r\n");
        for indicator in &self.indicators {
            let techniques: Vec<&str> = indicator
                .techniques
                .iter()
                .map(|technique| technique.id.as_str())
                .collect();
            let fields = [
                indicator.kind.name().to_owned(),
                indicator.value.clone(),
                token(&indicator.basis),
                time_text(indicator.first_seen),
                time_text(indicator.last_seen),
                indicator.events.to_string(),
                indicator.detections.to_string(),
                techniques.join(";"),
                tlp.label().to_owned(),
            ];
            let row: Vec<String> = fields.iter().map(|value| field(value)).collect();
            text.push_str(&row.join(","));
            text.push_str("\r\n");
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_field_stays_as_it_is() {
        assert_eq!(field("203.0.113.50"), "203.0.113.50");
        assert_eq!(field("python-httpx/0.27.0"), "python-httpx/0.27.0");
        assert_eq!(field("T1110.003;T1078"), "T1110.003;T1078");
        assert_eq!(field(""), "");
    }

    #[test]
    fn a_field_with_a_separator_gets_quotes() {
        assert_eq!(
            field("Mozilla/5.0 (X11; Linux, x64)"),
            "\"Mozilla/5.0 (X11; Linux, x64)\""
        );
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(field("two\r\nlines"), "\"two\r\nlines\"");
    }

    #[test]
    fn a_field_that_starts_a_formula_gets_an_apostrophe() {
        assert_eq!(
            field("=HYPERLINK(\"http://x\")"),
            "\"'=HYPERLINK(\"\"http://x\"\")\""
        );
        assert_eq!(field("+1"), "'+1");
        assert_eq!(field("-agent"), "'-agent");
        assert_eq!(field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(field("\tx"), "'\tx");
        // The character has an effect only at the start of a cell.
        assert_eq!(field("a=b"), "a=b");
    }

    #[test]
    fn an_empty_set_gives_only_the_header() {
        let set = IndicatorSet {
            indicators: Vec::new(),
            skipped: Vec::new(),
        };
        assert_eq!(
            set.to_csv(Tlp::Green),
            "type,value,basis,first_seen,last_seen,events,detections,techniques,tlp\r\n"
        );
    }
}
