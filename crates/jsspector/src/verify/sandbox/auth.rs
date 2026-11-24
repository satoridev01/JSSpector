use super::*;
use crate::verify::plan;

impl Session {
    /// Mints a genuine authenticated session by exercising the app's own routes: registers a
    /// throwaway account on each candidate registration endpoint (failures ignored — the account may
    /// already exist, or the app may seed accounts), then logs in on each candidate login endpoint
    /// until one returns a bearer token. The returned token is a real server-issued session the
    /// gated request presents under the handler's own cookie; the verifier never forges a token or
    /// bypasses the authentication — it satisfies the precondition the way a user would. `None` when
    /// no login returns a token, leaving the gated request to be sent unauthenticated (and so, for a
    /// genuinely authenticated sink, honestly not reproduce).
    pub(super) fn obtain_session(&self, boot: &plan::AuthBootstrap) -> Option<SessionCred> {
        // A framework-middleware gate: mint a session against the app's own login route using the
        // deployment's first-run default credential, sent as a genuine loopback request (no synthetic
        // forwarding header) so a login that issues its session only to a local first-run client does
        // so honestly. Capture the session from the login's `Set-Cookie`, or a bearer token in its body.
        if boot.default_credentials {
            let restore = self.omit_forwarding.get();
            self.omit_forwarding.set(true);
            let result = self.obtain_default_session(boot);
            self.omit_forwarding.set(restore);
            return result;
        }
        // An in-handler session gate: register a throwaway account, log in with those generated
        // credentials, and carry the returned bearer token back under the handler's cookie.
        let email = format!("jss-{}@jsspector.test", self.canary.token);
        let password = format!("Jss!{}aA1", self.canary.token);
        if boot.route_gate {
            return self.obtain_registered_session(boot, &email, &password);
        }
        for path in &boot.register_paths {
            let _ = self.fetch(&payload::credential_post(path, &email, &password));
        }
        for path in &boot.login_paths {
            if let Some(body) = self.fetch(&payload::credential_post(path, &email, &password))
                && let Some(token) = payload::extract_bearer_token(&body)
            {
                return Some(SessionCred::Bearer {
                    cookie: boot.cookie.clone(),
                    token,
                });
            }
        }
        None
    }

    /// A session for a route behind login middleware: registers the throwaway account on each
    /// candidate registration endpoint and logs in on each login endpoint, each as JSON and as a form
    /// submission (apps parse one or the other). The session is the bearer token the login returns in
    /// its body, or the session cookie a successful (2xx/3xx) login sets. Registration failures are
    /// ignored; the caller's control request still checks the gate accepts what came back.
    pub(super) fn obtain_registered_session(
        &self,
        boot: &plan::AuthBootstrap,
        email: &str,
        password: &str,
    ) -> Option<SessionCred> {
        let both = |path: &str| {
            let json = payload::credential_post(path, email, password);
            let form = payload::urlencoded_twin(&json);
            std::iter::once(json).chain(form)
        };
        // The confirmation, display name and similar fields the app's signup requires.
        let fields = plan::registration_fields(&self.root);
        for path in &boot.register_paths {
            let json = payload::registration_post(path, email, password, &fields);
            let form = payload::urlencoded_twin(&json);
            for attempt in std::iter::once(json).chain(form) {
                let _ = self.fetch(&attempt);
            }
        }
        for path in &boot.login_paths {
            for attempt in both(path) {
                let Some((body, status, cookies)) = self.fetch_meta(&attempt) else {
                    continue;
                };
                if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                    eprintln!(
                        "[verify] user-login path={path} status={status:?} cookies={} body[{}]",
                        cookies.len(),
                        body.chars().take(200).collect::<String>()
                    );
                }
                if let Some(token) = payload::extract_bearer_token(&body) {
                    return Some(SessionCred::Bearer {
                        cookie: boot.cookie.clone(),
                        token,
                    });
                }
                if status.is_some_and(|code| (200..400).contains(&code))
                    && !redirects_back_to_auth(&body)
                    && let Some(pair) = payload::session_cookie_pair(&cookies)
                {
                    return Some(SessionCred::Cookie { pair });
                }
            }
        }
        None
    }

    pub(super) fn obtain_default_session(&self, boot: &plan::AuthBootstrap) -> Option<SessionCred> {
        // An app whose inbound Web-UI/login password is read from an environment variable runs, in the
        // sandbox, with that variable set to the strong filler the sandbox plants to satisfy the
        // credential precondition (see `credential_env`). The deployment is therefore configured with
        // that exact secret, so the app's own login route accepts it: log in with the credential the
        // running deployment was configured with, before the published first-run defaults. This is the
        // real secret the sandbox set, never a forged token, and it is tried first so a rate-limited
        // login route is not exhausted before the configured credential is reached.
        let mut passwords = vec![STRONG_FILLER_SECRET.to_owned()];
        passwords.extend(template_login_passwords(&self.root));
        for password in payload::default_login_passwords() {
            if !passwords.iter().any(|candidate| candidate == password) {
                passwords.push((*password).to_owned());
            }
        }
        for path in &boot.login_paths {
            for password in &passwords {
                let attempt = payload::default_login_post(path, password);
                let Some((body, status, cookies)) = self.fetch_meta(&attempt) else {
                    continue;
                };
                if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
                    eprintln!(
                        "[verify] default-login path={path} status={status:?} cookies={} body[{}]",
                        cookies.len(),
                        body.chars().take(300).collect::<String>()
                    );
                }
                if let Some(pair) = payload::session_cookie_pair(&cookies) {
                    return Some(SessionCred::Cookie { pair });
                }
                if let Some(token) = payload::extract_bearer_token(&body) {
                    return Some(SessionCred::Bearer {
                        cookie: if boot.cookie.is_empty() {
                            "token".to_owned()
                        } else {
                            boot.cookie.clone()
                        },
                        token,
                    });
                }
            }
        }
        None
    }

    /// Whether the app answers these probes with an authentication challenge (HTTP 401/403, a
    /// redirect commonly used to send anonymous clients to login, or an auth-shaped body). Used to
    /// attempt a login bootstrap only when the route is actually gated, so an app that returns a
    /// normal 2xx response receives no spurious login traffic.
    pub(super) fn auth_challenge(&self, attempts: &[Attempt]) -> bool {
        let Some(attempt) = attempts.first() else {
            return false;
        };
        let Some((body, status, _)) = self.fetch_meta(attempt) else {
            return false;
        };
        if std::env::var_os("JSS_VERIFY_DEBUG").is_some() {
            eprintln!(
                "[verify] anonymous-auth-probe status={status:?} body[{}]",
                body.chars().take(200).collect::<String>()
            );
        }
        response_is_auth_challenge(status, &body)
    }
}

/// Whether an anonymous response is the application's authentication refusal. Some applications
/// deliberately return a generic 5xx error instead of 401/403 so the route does not disclose its
/// authentication state (`Blocked illegal activity`, `session required`). Recognize those explicit
/// refusal messages without treating an arbitrary server error as an auth challenge.
fn response_is_auth_challenge(status: Option<u16>, body: &str) -> bool {
    if matches!(status, Some(300..=399) | Some(401) | Some(403)) {
        return true;
    }
    let lower = body.to_ascii_lowercase();
    lower.contains("unauthorized")
        || lower.contains("authentication required")
        || lower.contains("login required")
        || lower.contains("requirelogin")
        || (lower.contains("session")
            && (lower.contains("required")
                || lower.contains("missing")
                || lower.contains("invalid")))
        || lower.contains("blocked illegal activity")
}

#[cfg(test)]
mod tests {
    use super::response_is_auth_challenge;

    #[test]
    fn explicit_auth_refusals_are_recognized_without_classifying_arbitrary_failures() {
        assert!(response_is_auth_challenge(Some(401), ""));
        assert!(response_is_auth_challenge(
            Some(500),
            "Error: Blocked illegal activity by 127.0.0.1"
        ));
        assert!(response_is_auth_challenge(
            Some(400),
            "A valid session is required"
        ));
        assert!(!response_is_auth_challenge(
            Some(500),
            "database connection failed"
        ));
        assert!(!response_is_auth_challenge(Some(200), "login"));
    }
}
