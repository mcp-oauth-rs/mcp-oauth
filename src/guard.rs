//! Abuse protection for an internet-facing axum app (built for MCP servers
//! behind a front such as a tunnel or a CDN that absorbs volumetric DDoS but
//! offers no per-route rate limiting):
//!
//! - per-client-IP token bucket on every request (except [`Limits::exempt_paths`]),
//!   banned IPs included;
//! - per-IP ban after repeated authentication failures, answered with 429;
//! - body size cap, request timeout, global concurrency cap ([`protect`]).
//!
//! What counts as an authentication failure: a wrong or unknown bearer token,
//! a refused enrolment code (unknown address, wrong, expired or used code),
//! a wrong client secret or client assertion, a wrong PKCE verifier for a
//! live code, and whatever the app reports through the
//! [`AuthFailures`] request extension that [`protect`] inserts (or through
//! [`Guard::auth_failed`] on a clone of the same [`Guard`]): a wrong URL path
//! token, a wrong device token, ... While an IP is banned, its failures are
//! neither counted nor logged and do not extend the ban.
//!
//! Unknown paths (no route matched; the app's own fallback, if any, answers)
//! do **not** count unless [`Limits::count_unknown_path`] says so, and
//! [`harmless_probe`]s never do: MCP clients probe discovery URLs
//! (`/.well-known/openid-configuration`, path-suffixed variants, ...) before
//! and after registering, browsers ask for `/favicon.ico`, uptime monitors for
//! `/`, and a chatty client must not get its (often shared) IP banned. They
//! are rate-limited like everything else and logged as a `debug:` line.
//!
//! Shared IPs: a home or office network or a mobile carrier puts many clients
//! behind one public address, and a ban caused by one of them (a scanner, a
//! misconfigured tool) cuts all of them. With
//! [`Limits::serve_authenticated_when_banned`] a banned IP keeps being served
//! when it proves valid credentials: its requests still go through the token
//! bucket and run, but only a response marked [`Authenticated`] (see
//! [`authenticated`]) goes back; anything else becomes 429 (fail closed:
//! routes that do not authenticate, 404s, 405s and extractor rejections
//! included). The crate marks a valid bearer token and a successful token
//! request; it never checks an enrolment code for a banned IP (see the
//! threat model in `docs/threat-model.md`).
//!
//! Client IP: `CF-Connecting-IP` (set by Cloudflare; the front is assumed to
//! be the only ingress), else the leftmost `X-Forwarded-For`, else "unknown".
//! Spoofing the header only lets an attacker spread over buckets they could
//! already get by using more IPs; the global caps still bound the total.

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Limits {
    /// Sustained requests per minute per IP.
    pub per_ip_per_min: f64,
    /// Burst size per IP.
    pub per_ip_burst: f64,
    /// Auth failures per IP within `fail_window` that trigger a ban.
    pub max_failures: u32,
    pub fail_window: Duration,
    pub ban_for: Duration,
    /// Request body cap in bytes (axum `DefaultBodyLimit`).
    pub max_body_bytes: usize,
    /// Whole-request timeout (answered with 408).
    pub request_timeout: Duration,
    /// Requests served at once, all clients together.
    pub max_concurrency: usize,
    /// Paths exempt from rate limiting and bans (health probes).
    pub exempt_paths: Vec<String>,
    /// `false` (default): a banned IP gets 429 before any handler runs, even
    /// with valid credentials. `true`: a banned IP's request (within its
    /// token bucket) runs, and its response goes back only if it is marked
    /// [`Authenticated`]; anything else becomes 429. For IPs shared by many
    /// clients (NAT), so that a ban never cuts a client that proves valid
    /// credentials.
    pub serve_authenticated_when_banned: bool,
    /// Which unknown paths (no route matched) count as an authentication
    /// failure. `None` (default): none. `Some(f)`: those for which
    /// `f(method, path)` is true, except [`harmless_probe`]s, which never
    /// count. The app's own fallback, if it has one, still answers.
    pub count_unknown_path: Option<fn(&Method, &str) -> bool>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_ip_per_min: 120.0,
            per_ip_burst: 40.0,
            max_failures: 10,
            fail_window: Duration::from_secs(600),
            ban_for: Duration::from_secs(3600),
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(120),
            max_concurrency: 32,
            exempt_paths: vec!["/healthz".into()],
            serve_authenticated_when_banned: false,
            count_unknown_path: None,
        }
    }
}

#[derive(Debug)]
struct Client {
    tokens: f64,
    last: Instant,
    failures: Vec<Instant>,
    banned_until: Option<Instant>,
}

/// Rate limit and ban state, per client IP. Cheap to clone (shared state):
/// keep a clone to record failures from code that has no [`AuthFailures`].
#[derive(Clone)]
pub struct Guard {
    limits: Limits,
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

pub fn client_ip(h: &HeaderMap) -> String {
    let get = |k: &str| {
        h.get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    get("cf-connecting-ip")
        .map(String::from)
        .or_else(|| {
            get("x-forwarded-for")
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    /// Banned IP, within its token bucket.
    Banned,
    RateLimited,
}

/// Response extension: the request proved valid credentials. A banned IP
/// gets such responses (with [`Limits::serve_authenticated_when_banned`]);
/// any other response to a banned IP becomes 429.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Authenticated;

/// Mark `resp` as the answer to a request whose credentials were verified.
pub fn authenticated(mut resp: Response) -> Response {
    resp.extensions_mut().insert(Authenticated);
    resp
}

/// Response extension for answers that prove nothing but are safe and
/// needed by a client that holds credentials: the OAuth metadata documents
/// (clients rediscover them before refreshing a token) and the 401 for an
/// expired token issued here (tells the client to refresh).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ServeWhenBanned;

pub(crate) fn serve_when_banned(mut resp: Response) -> Response {
    resp.extensions_mut().insert(ServeWhenBanned);
    resp
}

/// Response extension set by [`protect`] on every response of a matched
/// route: its absence means the request fell through to the fallback.
#[derive(Clone, Copy, Debug)]
struct Routed;

/// Requests browsers, uptime monitors and MCP clients make on their own:
/// `GET`/`HEAD` on `/`, `/favicon.ico`, `/robots.txt`, and anything under
/// `/.well-known/` (discovery). Never counted as authentication failures.
pub fn harmless_probe(method: &Method, path: &str) -> bool {
    path.starts_with("/.well-known/")
        || ((method == Method::GET || method == Method::HEAD)
            && matches!(path, "/" | "/favicon.ico" | "/robots.txt"))
}

impl Guard {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn client<'a>(
        &self,
        m: &'a mut HashMap<String, Client>,
        ip: &str,
        now: Instant,
    ) -> &'a mut Client {
        m.entry(ip.to_string()).or_insert(Client {
            tokens: self.limits.per_ip_burst,
            last: now,
            failures: Vec::new(),
            banned_until: None,
        })
    }

    /// Account one request from `ip`: the token bucket first, banned or not
    /// (a banned IP is rate-limited like any other), then the ban.
    pub fn admit(&self, ip: &str, now: Instant) -> Verdict {
        let mut m = self.clients.lock().expect("guard lock");
        // Bound memory under a flood of distinct IPs: drop idle entries.
        if m.len() > 50_000 {
            m.retain(|_, c| {
                now.duration_since(c.last) < Duration::from_secs(600)
                    || c.banned_until.is_some_and(|b| b > now)
            });
        }
        let lim = self.limits.clone();
        let c = self.client(&mut m, ip, now);
        let mut banned = false;
        if let Some(b) = c.banned_until {
            if b > now {
                banned = true;
            } else {
                c.banned_until = None;
                c.failures.clear();
            }
        }
        let elapsed = now.duration_since(c.last).as_secs_f64();
        c.tokens = (c.tokens + elapsed * lim.per_ip_per_min / 60.0).min(lim.per_ip_burst);
        c.last = now;
        if c.tokens < 1.0 {
            return Verdict::RateLimited;
        }
        c.tokens -= 1.0;
        if banned { Verdict::Banned } else { Verdict::Ok }
    }

    /// Whether `ip` is banned at `now`.
    pub fn is_banned(&self, ip: &str, now: Instant) -> bool {
        let m = self.clients.lock().expect("guard lock");
        m.get(ip)
            .and_then(|c| c.banned_until)
            .is_some_and(|b| b > now)
    }

    /// Tests: end of the ban of `ip` and failures in its window.
    #[cfg(test)]
    pub(crate) fn state(&self, ip: &str) -> (Option<Instant>, usize) {
        let m = self.clients.lock().expect("guard lock");
        m.get(ip)
            .map_or((None, 0), |c| (c.banned_until, c.failures.len()))
    }

    /// Record an authentication failure; returns true if the IP is now banned.
    /// While a ban runs, failures are neither counted nor logged (the request
    /// gets 429 anyway) and do not extend it.
    pub fn auth_failed(&self, ip: &str, what: &str, now: Instant) -> bool {
        let mut m = self.clients.lock().expect("guard lock");
        let lim = self.limits.clone();
        let c = self.client(&mut m, ip, now);
        if c.banned_until.is_some_and(|b| b > now) {
            return true;
        }
        c.failures
            .retain(|t| now.duration_since(*t) < lim.fail_window);
        c.failures.push(now);
        let n = c.failures.len() as u32;
        eprintln!(
            "auth failure ({what}) from {ip} [{n}/{} in window]",
            lim.max_failures
        );
        if n >= lim.max_failures {
            c.banned_until = Some(now + lim.ban_for);
            eprintln!(
                "banning {ip} for {}s after {n} auth failures",
                lim.ban_for.as_secs()
            );
            return true;
        }
        false
    }

    /// A request matched no route: log it, and count it if
    /// [`Limits::count_unknown_path`] says so.
    fn unknown_path(&self, method: &Method, path: &str, ip: &str) {
        let shown: String = path.chars().take(200).collect();
        eprintln!("debug: unknown path {method} {shown} from {ip}");
        if let Some(count) = self.limits.count_unknown_path
            && !harmless_probe(method, path)
            && count(method, path)
        {
            self.auth_failed(ip, "unknown path", Instant::now());
        }
    }
}

/// Request extension inserted by [`protect`]: lets a handler (or a layer
/// such as [`crate::BearerLayer`]) count an authentication failure against
/// the client IP the guard resolved for the current request. Apps with their
/// own middleware can build one with [`AuthFailures::new`].
#[derive(Clone)]
pub struct AuthFailures {
    guard: Guard,
    ip: String,
    banned: bool,
}

impl AuthFailures {
    /// Failures of `ip`, counted in `guard` (the same ban state as
    /// [`protect`] when it is a clone of its guard).
    pub fn new(guard: Guard, ip: impl Into<String>) -> Self {
        let ip = ip.into();
        let banned = guard.is_banned(&ip, Instant::now());
        Self { guard, ip, banned }
    }

    /// Count one failure (`what` is logged); returns true if the IP is now
    /// banned. Not counted while the IP is banned.
    pub fn record(&self, what: &str) -> bool {
        self.guard.auth_failed(&self.ip, what, Instant::now())
    }

    /// Client IP the failure is counted against.
    pub fn ip(&self) -> &str {
        &self.ip
    }

    /// Whether the IP was banned when the request was admitted (only seen
    /// by handlers with [`Limits::serve_authenticated_when_banned`]): the
    /// response goes back only if marked [`Authenticated`], so a handler may
    /// skip work it would not mark (the crate never checks an enrolment
    /// code for a banned IP).
    pub fn banned(&self) -> bool {
        self.banned
    }
}

/// 429 for a banned IP.
pub(crate) fn banned_response() -> Response {
    (StatusCode::TOO_MANY_REQUESTS, "banned").into_response()
}

/// Rate limit and ban check on every request except the exempt paths; puts
/// [`AuthFailures`] in the request extensions; counts unknown paths (see
/// [`Limits::count_unknown_path`]).
async fn guard_layer(State(g): State<Guard>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if g.limits.exempt_paths.iter().any(|p| p == path) {
        return next.run(req).await;
    }
    let path = path.to_string();
    let method = req.method().clone();
    let ip = client_ip(req.headers());
    let banned = match g.admit(&ip, Instant::now()) {
        Verdict::Ok => false,
        Verdict::Banned if g.limits.serve_authenticated_when_banned => true,
        Verdict::Banned => return banned_response(),
        Verdict::RateLimited => {
            return (
                [("retry-after", "30")],
                (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            )
                .into_response();
        }
    };
    req.extensions_mut().insert(AuthFailures {
        guard: g.clone(),
        ip: ip.clone(),
        banned,
    });
    let mut resp = next.run(req).await;
    let routed = resp.extensions_mut().remove::<Routed>().is_some();
    if banned {
        let ext = resp.extensions();
        if ext.get::<Authenticated>().is_some() || ext.get::<ServeWhenBanned>().is_some() {
            return resp;
        }
        return banned_response();
    }
    if !routed {
        g.unknown_path(&method, &path, &ip);
    }
    resp
}

async fn mark_routed(mut resp: Response) -> Response {
    resp.extensions_mut().insert(Routed);
    resp
}

/// Wrap a complete app in the abuse protection layers: per-IP rate limit and
/// ban (see [`Limits`]); body cap; request timeout (408); global
/// concurrency cap. The app's fallback is kept (axum's default answers 404);
/// requests that match no route are logged and counted as
/// [`Limits::count_unknown_path`] says.
pub fn protect(router: Router, guard: Guard) -> Router {
    let lim = guard.limits.clone();
    // route_layer wraps the routes only, not the fallback: a response
    // without the mark matched no route.
    let router = if router.has_routes() {
        router.route_layer(axum::middleware::map_response(mark_routed))
    } else {
        router
    };
    router
        .layer(axum::extract::DefaultBodyLimit::max(lim.max_body_bytes))
        .layer(axum::middleware::from_fn_with_state(guard, guard_layer))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            lim.request_timeout,
        ))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            lim.max_concurrency,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::get};
    use tower::ServiceExt;

    fn small() -> Guard {
        Guard::new(Limits {
            per_ip_per_min: 60.0,
            per_ip_burst: 3.0,
            max_failures: 3,
            fail_window: Duration::from_secs(60),
            ban_for: Duration::from_secs(100),
            ..Default::default()
        })
    }

    #[test]
    fn bucket_refills() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(matches!(g.admit("192.0.2.10", t0), Verdict::Ok));
        }
        assert!(matches!(g.admit("192.0.2.10", t0), Verdict::RateLimited));
        assert!(
            matches!(g.admit("192.0.2.20", t0), Verdict::Ok),
            "other IPs unaffected"
        );
        assert!(
            matches!(
                g.admit("192.0.2.10", t0 + Duration::from_secs(1)),
                Verdict::Ok
            ),
            "1 token/s refill"
        );
    }

    #[test]
    fn ban_after_failures_then_expires() {
        let g = small();
        let t0 = Instant::now();
        assert!(!g.auth_failed("192.0.2.99", "t", t0));
        assert!(!g.auth_failed("192.0.2.99", "t", t0));
        assert!(g.auth_failed("192.0.2.99", "t", t0));
        assert!(matches!(
            g.admit("192.0.2.99", t0 + Duration::from_secs(50)),
            Verdict::Banned
        ));
        assert!(matches!(
            g.admit("192.0.2.99", t0 + Duration::from_secs(101)),
            Verdict::Ok
        ));
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let g = small();
        let t0 = Instant::now();
        g.auth_failed("192.0.2.88", "t", t0);
        g.auth_failed("192.0.2.88", "t", t0);
        assert!(
            !g.auth_failed("192.0.2.88", "t", t0 + Duration::from_secs(61)),
            "old failures expired"
        );
    }

    #[test]
    fn ip_from_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1, 172.16.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "10.0.0.1");
        h.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
        assert_eq!(client_ip(&HeaderMap::new()), "unknown");
    }

    /// `/t/{token}`: "good" is 200, anything else 404 + an auth failure
    /// reported through the extension (like a URL path token).
    fn app(lim: Limits) -> Router {
        let r = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/t/{token}",
                get(
                    |axum::extract::Path(t): axum::extract::Path<String>,
                     f: Option<axum::Extension<AuthFailures>>| async move {
                        if t == "good" {
                            StatusCode::OK
                        } else {
                            if let Some(axum::Extension(f)) = f {
                                f.record("path token");
                            }
                            StatusCode::NOT_FOUND
                        }
                    },
                ),
            );
        protect(r, Guard::new(lim))
    }

    async fn get_(app: &Router, path: &str, ip: &str) -> StatusCode {
        let req = axum::http::Request::get(path)
            .header("cf-connecting-ip", ip)
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn ban_after_bad_tokens_only() {
        let a = app(Limits {
            max_failures: 3,
            ..Default::default()
        });
        assert_eq!(get_(&a, "/t/good", "192.0.2.11").await, StatusCode::OK);
        // Scanner and discovery probes: 404, never counted.
        for p in [
            "/.env",
            "/wp-login.php",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/mcp",
            "/foo?x=1",
        ] {
            assert_eq!(
                get_(&a, p, "192.0.2.66").await,
                StatusCode::NOT_FOUND,
                "{p}"
            );
        }
        assert_eq!(
            get_(&a, "/t/good", "192.0.2.66").await,
            StatusCode::OK,
            "unknown paths do not ban"
        );
        for _ in 0..3 {
            assert_eq!(
                get_(&a, "/t/bad", "192.0.2.66").await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            get_(&a, "/t/good", "192.0.2.66").await,
            StatusCode::TOO_MANY_REQUESTS,
            "bad tokens ban"
        );
        assert_eq!(get_(&a, "/t/good", "192.0.2.11").await, StatusCode::OK);
        assert_eq!(
            get_(&a, "/healthz", "192.0.2.66").await,
            StatusCode::OK,
            "probes stay exempt"
        );
    }

    #[tokio::test]
    async fn unknown_paths_are_rate_limited() {
        let a = app(Limits {
            per_ip_burst: 3.0,
            per_ip_per_min: 1.0,
            max_failures: 1,
            ..Default::default()
        });
        for _ in 0..3 {
            assert_eq!(get_(&a, "/nope", "192.0.2.44").await, StatusCode::NOT_FOUND);
        }
        assert_eq!(
            get_(&a, "/nope", "192.0.2.44").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn rate_limited_per_ip() {
        let a = app(Limits {
            per_ip_burst: 3.0,
            per_ip_per_min: 1.0,
            ..Default::default()
        });
        for _ in 0..3 {
            assert_eq!(get_(&a, "/t/good", "192.0.2.22").await, StatusCode::OK);
        }
        assert_eq!(
            get_(&a, "/t/good", "192.0.2.22").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(get_(&a, "/t/good", "192.0.2.33").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn body_limit_and_timeout() {
        let r = Router::new()
            .route(
                "/echo",
                axum::routing::post(|b: axum::body::Bytes| async move { b.len().to_string() }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            );
        let a = protect(
            r,
            Guard::new(Limits {
                max_body_bytes: 16,
                request_timeout: Duration::from_millis(50),
                ..Default::default()
            }),
        );
        let post = |n: usize| {
            axum::http::Request::post("/echo")
                .body(Body::from(vec![b'x'; n]))
                .unwrap()
        };
        assert_eq!(
            a.clone().oneshot(post(16)).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            a.clone().oneshot(post(17)).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            get_(&a, "/slow", "192.0.2.77").await,
            StatusCode::REQUEST_TIMEOUT
        );
    }

    // ------------------------------------------------ shared IPs and bans

    #[test]
    fn banned_ip_is_still_rate_limited() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            g.auth_failed("192.0.2.99", "t", t0);
        }
        // A banned IP is admitted (to let authenticated clients through) but
        // still pays the token bucket like everyone else.
        for _ in 0..3 {
            assert_eq!(g.admit("192.0.2.99", t0), Verdict::Banned);
        }
        assert_eq!(g.admit("192.0.2.99", t0), Verdict::RateLimited);
        assert_eq!(
            g.admit("192.0.2.99", t0 + Duration::from_secs(1)),
            Verdict::Banned,
            "refilled, still banned"
        );
    }

    #[test]
    fn failures_while_banned_do_not_extend_the_ban() {
        let g = small();
        let t0 = Instant::now();
        for _ in 0..3 {
            g.auth_failed("192.0.2.99", "t", t0);
        }
        assert!(g.is_banned("192.0.2.99", t0 + Duration::from_secs(50)));
        for _ in 0..10 {
            assert!(
                g.auth_failed("192.0.2.99", "t", t0 + Duration::from_secs(50)),
                "still banned"
            );
        }
        assert!(!g.is_banned("192.0.2.99", t0 + Duration::from_secs(101)));
        assert_eq!(
            g.admit("192.0.2.99", t0 + Duration::from_secs(101)),
            Verdict::Ok,
            "ban ends on time"
        );
        assert!(
            !g.auth_failed("192.0.2.99", "t", t0 + Duration::from_secs(102)),
            "failures while banned were not kept: a fresh window"
        );
    }

    #[test]
    fn harmless_probe_rule() {
        for m in [Method::GET, Method::HEAD] {
            for p in ["/", "/favicon.ico", "/robots.txt"] {
                assert!(harmless_probe(&m, p), "{m} {p}");
            }
        }
        for m in [Method::GET, Method::POST, Method::OPTIONS] {
            for p in [
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server/mcp",
            ] {
                assert!(harmless_probe(&m, p), "{m} {p}");
            }
        }
        assert!(!harmless_probe(&Method::POST, "/"));
        assert!(!harmless_probe(&Method::DELETE, "/favicon.ico"));
        for p in ["/wp-login.php", "/.env", "/.well-known", "/x/.well-known/y"] {
            assert!(!harmless_probe(&Method::GET, p), "{p}");
        }
    }

    async fn send(app: &Router, method: &str, path: &str, ip: &str, body: &str) -> Response {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("cf-connecting-ip", ip)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    async fn status(app: &Router, method: &str, path: &str, ip: &str) -> StatusCode {
        send(app, method, path, ip, "").await.status()
    }

    async fn body(r: Response) -> String {
        let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        String::from_utf8_lossy(&b).into_owned()
    }

    fn count_all(_: &Method, _: &str) -> bool {
        true
    }

    #[tokio::test]
    async fn harmless_probes_never_count_as_failures() {
        // Every unknown path counts, except the harmless probes; production
        // failure threshold; a big bucket so only the ban is tested.
        let a = app(Limits {
            per_ip_burst: 1000.0,
            count_unknown_path: Some(count_all),
            ..Default::default()
        });
        for path in ["/", "/favicon.ico", "/robots.txt"] {
            for method in ["GET", "HEAD"] {
                for _ in 0..20 {
                    let code = status(&a, method, path, "192.0.2.55").await;
                    assert_eq!(code, StatusCode::NOT_FOUND, "{method} {path}");
                }
            }
        }
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/mcp",
        ] {
            for method in ["GET", "POST"] {
                for _ in 0..20 {
                    let code = status(&a, method, path, "192.0.2.55").await;
                    assert_eq!(code, StatusCode::NOT_FOUND, "{method} {path}");
                }
            }
        }
        assert_eq!(
            status(&a, "GET", "/t/good", "192.0.2.55").await,
            StatusCode::OK,
            "200 harmless requests later, not banned"
        );
        // Scanner probes count: banned at the 10th.
        for i in 0..10 {
            let p = if i % 2 == 0 { "/wp-login.php" } else { "/.env" };
            assert_eq!(
                status(&a, "GET", p, "192.0.2.55").await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            status(&a, "GET", "/t/good", "192.0.2.55").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status(&a, "GET", "/t/good", "192.0.2.56").await,
            StatusCode::OK,
            "other IPs unaffected"
        );
    }

    fn count_wp(_: &Method, path: &str) -> bool {
        path.starts_with("/wp-")
    }

    #[tokio::test]
    async fn unknown_path_counting_hook() {
        let lim = Limits {
            max_failures: 3,
            count_unknown_path: Some(count_wp),
            ..Default::default()
        };
        let a = app(lim);
        for _ in 0..5 {
            for p in ["/.env", "/admin", "/t"] {
                assert_eq!(
                    status(&a, "GET", p, "192.0.2.44").await,
                    StatusCode::NOT_FOUND
                );
            }
        }
        assert_eq!(
            status(&a, "GET", "/t/good", "192.0.2.44").await,
            StatusCode::OK,
            "paths the hook rejects are not counted"
        );
        // A known route never counts, whatever the hook says, even a 405.
        for _ in 0..5 {
            assert_eq!(
                status(&a, "POST", "/t/good", "192.0.2.44").await,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        for _ in 0..3 {
            assert_eq!(
                status(&a, "GET", "/wp-login.php", "192.0.2.44").await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            status(&a, "GET", "/t/good", "192.0.2.44").await,
            StatusCode::TOO_MANY_REQUESTS,
            "paths the hook accepts are counted"
        );
    }

    /// `protect` keeps the app's fallback (and its counting, if it does any);
    /// the hook still applies to what reaches it.
    #[tokio::test]
    async fn app_fallback_is_kept() {
        let g = Guard::new(Limits {
            max_failures: 3,
            ..Default::default()
        });
        let r = Router::new().route("/x", get(|| async { "x" })).fallback(
            |f: Option<axum::Extension<AuthFailures>>, uri: axum::http::Uri| async move {
                if uri.path() == "/scanner"
                    && let Some(axum::Extension(f)) = f
                {
                    f.record("app fallback");
                }
                (StatusCode::IM_A_TEAPOT, "app fallback")
            },
        );
        let a = protect(r, g.clone());
        let r = send(&a, "GET", "/nope", "192.0.2.77", "").await;
        assert_eq!(r.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(body(r).await, "app fallback");
        assert!(!g.is_banned("192.0.2.77", Instant::now()), "not counted");
        for _ in 0..3 {
            assert_eq!(
                status(&a, "GET", "/scanner", "192.0.2.77").await,
                StatusCode::IM_A_TEAPOT
            );
        }
        assert!(g.is_banned("192.0.2.77", Instant::now()), "the app counted");
        assert_eq!(
            status(&a, "GET", "/x", "192.0.2.77").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // An app with no route at all: protect still works (no route_layer).
        let empty = protect(Router::new(), Guard::new(Limits::default()));
        assert_eq!(
            status(&empty, "GET", "/", "192.0.2.78").await,
            StatusCode::NOT_FOUND
        );
    }

    /// Routes of a shared-IP app: `/auth/{token}` marks its answer
    /// [`Authenticated`] for "good" (404 otherwise, counted); `/plain` and
    /// `/json` never authenticate; every handler run is counted in `hits`.
    fn shared_ip_app(lim: Limits) -> (Router, Guard, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let (h1, h2, h3) = (hits.clone(), hits.clone(), hits.clone());
        let g = Guard::new(lim);
        let r = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(
                "/auth/{token}",
                get(
                    move |axum::extract::Path(t): axum::extract::Path<String>,
                          axum::Extension(f): axum::Extension<AuthFailures>| async move {
                        h1.fetch_add(1, Ordering::SeqCst);
                        if t == "good" {
                            authenticated(format!("hello, banned={}", f.banned()).into_response())
                        } else {
                            f.record("token");
                            StatusCode::NOT_FOUND.into_response()
                        }
                    },
                ),
            )
            .route(
                "/plain",
                get(move || async move {
                    h2.fetch_add(1, Ordering::SeqCst);
                    "plain"
                }),
            )
            .route(
                "/json",
                axum::routing::post(move |_: axum::Json<serde_json::Value>| async move {
                    h3.fetch_add(1, Ordering::SeqCst);
                    authenticated(StatusCode::OK.into_response())
                }),
            );
        (protect(r, g.clone()), g, hits)
    }

    fn shared(max_failures: u32) -> Limits {
        Limits {
            max_failures,
            serve_authenticated_when_banned: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn authenticated_responses_pass_during_a_ban() {
        use std::sync::atomic::Ordering;
        let (a, g, hits) = shared_ip_app(shared(3));
        let ip = "192.0.2.66";
        let r = send(&a, "GET", "/auth/good", ip, "").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body(r).await, "hello, banned=false");
        for _ in 0..3 {
            assert_eq!(
                status(&a, "GET", "/auth/bad", ip).await,
                StatusCode::NOT_FOUND
            );
        }
        assert!(g.is_banned(ip, Instant::now()));
        // Valid credentials: served, and the handler knows the IP is banned.
        let r = send(&a, "GET", "/auth/good", ip, "").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body(r).await, "hello, banned=true");
        assert_eq!(
            status(&a, "GET", "/healthz", ip).await,
            StatusCode::OK,
            "exempt"
        );
        assert_eq!(
            status(&a, "GET", "/plain", "192.0.2.11").await,
            StatusCode::OK,
            "other IPs unaffected"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 6);
        drop(g);
    }

    #[tokio::test]
    async fn unmarked_responses_to_a_banned_ip_become_429() {
        use std::sync::atomic::Ordering;
        let (a, g, hits) = shared_ip_app(shared(1));
        let ip = "192.0.2.66";
        g.auth_failed(ip, "t", Instant::now());
        let before = hits.load(Ordering::SeqCst);
        let cases: [(&str, &str, &str, &str); 7] = [
            ("GET", "/auth/bad", "", "wrong credentials (404)"),
            (
                "GET",
                "/plain",
                "",
                "a route that does not authenticate (200)",
            ),
            ("POST", "/plain", "", "405"),
            ("POST", "/json", "{", "extractor rejection (400)"),
            ("GET", "/wp-login.php", "", "unknown path (404)"),
            ("GET", "/", "", "harmless probe (404)"),
            ("GET", "/favicon.ico", "", "harmless probe (404)"),
        ];
        for (m, p, b, why) in cases {
            let r = send(&a, m, p, ip, b).await;
            assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "{why}");
            assert_eq!(body(r).await, "banned", "{why}");
        }
        assert_eq!(
            hits.load(Ordering::SeqCst) - before,
            2,
            "the handlers of /auth/bad and GET /plain ran (fail closed on the response)"
        );
        // The same requests from (fresh) other IPs are not 429s.
        for (i, (m, p, b, why)) in cases.into_iter().enumerate() {
            let other = send(&a, m, p, &format!("198.51.100.{i}"), b).await.status();
            assert_ne!(other, StatusCode::TOO_MANY_REQUESTS, "{why}");
        }
        assert_eq!(
            status(&a, "POST", "/json", ip).await,
            StatusCode::TOO_MANY_REQUESTS,
            "empty body: rejected"
        );
        let r = send(&a, "POST", "/json", ip, "{}").await;
        assert_eq!(r.status(), StatusCode::OK, "valid body, marked handler");
    }

    #[tokio::test]
    async fn default_ban_stops_requests_before_any_handler() {
        use std::sync::atomic::Ordering;
        let (a, g, hits) = shared_ip_app(Limits {
            max_failures: 1,
            ..Default::default()
        });
        assert!(
            !g.limits().serve_authenticated_when_banned,
            "off by default"
        );
        g.auth_failed("192.0.2.66", "t", Instant::now());
        let r = send(&a, "GET", "/auth/good", "192.0.2.66", "").await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body(r).await, "banned");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "handler never ran");
    }

    #[tokio::test]
    async fn banned_ip_is_rate_limited_through_the_middleware() {
        let (a, g, _) = shared_ip_app(Limits {
            per_ip_burst: 3.0,
            per_ip_per_min: 1.0,
            ..shared(1)
        });
        g.auth_failed("192.0.2.66", "t", Instant::now());
        for _ in 0..3 {
            assert_eq!(
                status(&a, "GET", "/auth/good", "192.0.2.66").await,
                StatusCode::OK
            );
        }
        let r = send(&a, "GET", "/auth/good", "192.0.2.66", "").await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()["retry-after"], "30");
        assert_eq!(body(r).await, "rate limited");
    }

    /// Wrong credentials sent during the ban do not push its end back.
    #[tokio::test]
    async fn failures_while_banned_do_not_extend_the_ban_through_the_middleware() {
        let (a, g, _) = shared_ip_app(Limits {
            ban_for: Duration::from_millis(600),
            count_unknown_path: Some(count_all),
            ..shared(3)
        });
        let t0 = Instant::now();
        for _ in 0..3 {
            g.auth_failed("192.0.2.66", "t", t0);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        for _ in 0..10 {
            assert_eq!(
                status(&a, "GET", "/auth/bad", "192.0.2.66").await,
                StatusCode::TOO_MANY_REQUESTS
            );
            assert_eq!(
                status(&a, "GET", "/wp-login.php", "192.0.2.66").await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        tokio::time::sleep(Duration::from_millis(600) - t0.elapsed() + Duration::from_millis(50))
            .await;
        // Extended, the ban would last until about t0 + 900 ms.
        assert!(t0.elapsed() < Duration::from_millis(850), "test too slow");
        assert_eq!(
            status(&a, "GET", "/plain", "192.0.2.66").await,
            StatusCode::OK
        );
        // And nothing was kept: a fresh window, two failures are no ban.
        for _ in 0..2 {
            assert_eq!(
                status(&a, "GET", "/auth/bad", "192.0.2.66").await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            status(&a, "GET", "/plain", "192.0.2.66").await,
            StatusCode::OK
        );
    }

    /// Failures the app records itself (request extension, a clone of the
    /// guard, or an `AuthFailures` it builds) feed the same ban as the
    /// crate's own.
    #[tokio::test]
    async fn app_recorded_failures_share_the_ban() {
        let (a, g, _) = shared_ip_app(shared(3));
        let ip = "192.0.2.88";
        // 1: through the extension protect inserts (handler).
        assert_eq!(
            status(&a, "GET", "/auth/bad", ip).await,
            StatusCode::NOT_FOUND
        );
        // 2: through a clone of the guard (e.g. kept in the app state).
        assert!(!g.clone().auth_failed(ip, "device token", Instant::now()));
        // 3: through an AuthFailures built by the app (its own middleware).
        let f = AuthFailures::new(g.clone(), ip);
        assert_eq!(f.ip(), ip);
        assert!(!f.banned());
        assert!(f.record("legacy URL token"), "third failure: banned");
        assert!(AuthFailures::new(g.clone(), ip).banned());
        assert_eq!(
            status(&a, "GET", "/plain", ip).await,
            StatusCode::TOO_MANY_REQUESTS,
            "protect sees the ban"
        );
        assert_eq!(status(&a, "GET", "/auth/good", ip).await, StatusCode::OK);
    }
}
