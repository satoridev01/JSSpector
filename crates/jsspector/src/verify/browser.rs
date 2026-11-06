//! The browser phase of `--verify`: the URLs a DOM-source finding is loaded with, and how a hit
//! is recognized. Pure — the sandbox ([`super::sandbox`]) serves the app, drives a headless
//! browser to each URL, and reports whether the marker service was reached. A canary that runs
//! only calls the marker service (a benign same-token request), so execution is unambiguous and
//! nothing else happens.

use super::payload::Canary;
use super::plan::{BrowserProbe, BrowserSink, UrlVector};

/// One page load: a URL (relative to the served app) and the marker token that confirms the
/// canary executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAttempt {
    pub url: String,
    /// The marker service is reached carrying this token when the canary runs.
    pub token: String,
}

/// Param names a URL-sourced DOM sink commonly reads, tried when the exact one is unknown.
const PARAM_CANDIDATES: [&str; 11] = [
    "id", "q", "query", "search", "name", "redirect", "url", "next", "continue", "callback",
    "return",
];

/// The page loads worth trying for a browser probe: the canary placed in the URL vector the
/// source reads, across candidate parameter names, with the marker token tagged per attempt so
/// one finding's hit never confirms another's. `page` is the served path of the HTML document
/// that loads the vulnerable script.
pub fn browser_attempts(
    probe: &BrowserProbe,
    page: &str,
    canary: &Canary,
    nonce: u32,
) -> Vec<BrowserAttempt> {
    let token = format!("{}-{nonce}", canary.token);
    let payload = canary_payload(probe.sink, &token);
    let encoded = encode(&payload);
    let mut out = Vec::new();
    let mut push = |url: String| {
        out.push(BrowserAttempt {
            url,
            token: token.clone(),
        })
    };
    let params = param_names(probe);
    match probe.vector {
        UrlVector::Search => {
            for param in &params {
                push(format!("{page}?{param}={encoded}"));
            }
        }
        UrlVector::Hash => {
            push(format!("{page}#{encoded}"));
            for param in &params {
                push(format!("{page}#{param}={encoded}"));
            }
        }
        UrlVector::Href => {
            // The value is read from anywhere in the URL: try both query and hash.
            for param in &params {
                push(format!("{page}?{param}={encoded}"));
                push(format!("{page}#{param}={encoded}"));
            }
            push(format!("{page}#{encoded}"));
        }
        UrlVector::Referrer => {
            // The sandbox sets the referrer separately; the page itself carries no payload.
            push(page.to_owned());
        }
    }
    out
}

/// The parameter names to try for a URL-sourced probe: the ones the script actually reads off the
/// page URL (mined from its source) first, then the generic candidates for anything not already
/// covered. Trying the real name first means a page reading an uncommon parameter is driven on the
/// first relevant load rather than missed entirely.
fn param_names(probe: &BrowserProbe) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in &probe.params {
        if !out.iter().any(|n| n == name) {
            out.push(name.clone());
        }
    }
    for name in PARAM_CANDIDATES {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_owned());
        }
    }
    out
}

/// Whether a referrer-sourced probe needs the payload delivered as the Referer header rather than
/// in the URL.
pub fn via_referrer(probe: &BrowserProbe) -> bool {
    probe.vector == UrlVector::Referrer
}

/// The payload to carry on a referrer-sourced load, and the token it signals with.
pub fn referrer_payload(probe: &BrowserProbe, canary: &Canary, nonce: u32) -> (String, String) {
    let token = format!("{}-{nonce}", canary.token);
    (canary_payload(probe.sink, &token), token)
}

/// A canary that, if executed, calls the marker service carrying `token` — and does nothing else.
/// HTML context uses an image's error handler (runs even though `<script>` in `innerHTML` does
/// not); a navigation sink uses a `javascript:` URL.
fn canary_payload(sink: BrowserSink, token: &str) -> String {
    let call = format!("fetch('http://jss-marker/{token}')");
    match sink {
        BrowserSink::Html => format!("<img src=x onerror=\"{call}\">"),
        BrowserSink::Navigation => format!("javascript:{call}"),
    }
}

/// Percent-encodes a payload for a URL query or hash value: everything but the unreserved set.
fn encode(text: &str) -> String {
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

    fn probe(vector: UrlVector, sink: BrowserSink) -> BrowserProbe {
        BrowserProbe {
            file: "web/pages.js".to_owned(),
            vector,
            sink,
            params: Vec::new(),
        }
    }

    #[test]
    fn a_search_html_probe_tries_candidate_params_with_an_image_canary() {
        let canary = Canary::new("tok".to_owned());
        let a = browser_attempts(
            &probe(UrlVector::Search, BrowserSink::Html),
            "/index.html",
            &canary,
            1,
        );
        assert_eq!(a.len(), PARAM_CANDIDATES.len());
        assert!(a.iter().all(|x| x.url.starts_with("/index.html?")));
        assert!(a.iter().all(|x| x.token == "tok-1"));
        // The image onerror payload, percent-encoded, carries the marker call.
        assert!(a.iter().all(|x| x.url.contains("onerror")));
        assert!(a[0].url.contains("jss-marker") && a[0].url.contains("tok-1"));
    }

    #[test]
    fn a_mined_param_is_tried_before_the_generic_candidates() {
        let canary = Canary::new("tok".to_owned());
        let mut p = probe(UrlVector::Search, BrowserSink::Html);
        // A page that reads an uncommon parameter name off its URL.
        p.params = vec!["state".to_owned()];
        let a = browser_attempts(&p, "/index.html", &canary, 1);
        // The real parameter is driven first, ahead of the generic candidates, and is not dropped.
        assert!(a[0].url.starts_with("/index.html?state="));
        assert!(a.iter().filter(|x| x.url.contains("?state=")).count() == 1);
        // The generic candidates still follow, so an unknown name is not regressed.
        assert!(a.iter().any(|x| x.url.contains("?q=")));
    }

    #[test]
    fn a_navigation_probe_uses_a_javascript_url() {
        let canary = Canary::new("t".to_owned());
        let a = browser_attempts(
            &probe(UrlVector::Search, BrowserSink::Navigation),
            "/",
            &canary,
            2,
        );
        // javascript: scheme, encoded.
        assert!(a.iter().all(|x| x.url.contains("javascript")));
        assert!(a.iter().all(|x| x.token == "t-2"));
    }

    #[test]
    fn href_tries_both_query_and_hash() {
        let canary = Canary::new("t".to_owned());
        let a = browser_attempts(&probe(UrlVector::Href, BrowserSink::Html), "/p", &canary, 1);
        assert!(a.iter().any(|x| x.url.contains('?')));
        assert!(a.iter().any(|x| x.url.contains('#')));
    }

    #[test]
    fn referrer_is_delivered_out_of_band() {
        let p = probe(UrlVector::Referrer, BrowserSink::Html);
        assert!(via_referrer(&p));
        let canary = Canary::new("t".to_owned());
        let a = browser_attempts(&p, "/page", &canary, 3);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].url, "/page");
        let (payload, token) = referrer_payload(&p, &canary, 3);
        assert_eq!(token, "t-3");
        assert!(payload.contains("jss-marker"));
    }
}
