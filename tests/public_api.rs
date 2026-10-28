//! The guard API as another crate sees it: an app with its own credentials
//! (a device token, a URL token) and its own fallback, behind a shared IP.

use axum::{
    Extension, Router,
    body::Body,
    http::{Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use mcp_oauth_server::{
    AuthFailures, Authenticated, Guard, Limits, Verdict, authenticated, client_ip, harmless_probe,
    protect,
};
use std::time::Instant;
use tower::ServiceExt;

const DEVICE_TOKEN: &str = "device-token";

fn count_unknown(_: &Method, _: &str) -> bool {
    true
}

/// `/sync` checks a device token and records failures itself; a fallback of
/// its own answers unknown paths.
fn app(guard: Guard) -> Router {
    let r = Router::new()
        .route(
            "/sync",
            post(
                |Extension(f): Extension<AuthFailures>, headers: axum::http::HeaderMap| async move {
                    if headers.get("authorization").and_then(|v| v.to_str().ok())
                        == Some(&format!("Bearer {DEVICE_TOKEN}"))
                    {
                        authenticated("synced".into_response())
                    } else {
                        f.record("device token");
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                },
            ),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "nothing here") });
    protect(r, guard)
}

async fn send(app: &Router, method: &str, path: &str, ip: &str, token: Option<&str>) -> Response {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("cf-connecting-ip", ip);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn shared_ip_app_outside_the_crate() {
    let guard = Guard::new(Limits {
        max_failures: 3,
        per_ip_burst: 1000.0,
        serve_authenticated_when_banned: true,
        count_unknown_path: Some(count_unknown),
        ..Limits::default()
    });
    let a = app(guard.clone());
    let ip = "203.0.113.9";
    // Harmless probes: the app's own 404, never counted.
    for _ in 0..20 {
        for p in [
            "/",
            "/favicon.ico",
            "/robots.txt",
            "/.well-known/openid-configuration",
        ] {
            let r = send(&a, "GET", p, ip, None).await;
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{p}");
            let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
            assert_eq!(&body[..], b"nothing here", "the app's fallback answered");
        }
    }
    assert!(!guard.is_banned(ip, Instant::now()));
    // One scanner path (counted by the hook), one bad device token (counted
    // by the handler), one failure from the app's own middleware code.
    assert_eq!(
        send(&a, "GET", "/wp-login.php", ip, None).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&a, "POST", "/sync", ip, Some("bad")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let f = AuthFailures::new(
        guard.clone(),
        client_ip(&{
            let mut h = axum::http::HeaderMap::new();
            h.insert("cf-connecting-ip", ip.parse().unwrap());
            h
        }),
    );
    assert!(f.record("legacy URL token"), "third failure: banned");
    assert!(guard.is_banned(ip, Instant::now()));
    // Banned: the valid device token is still served, anything else is 429.
    let r = send(&a, "POST", "/sync", ip, Some(DEVICE_TOKEN)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.extensions().get::<Authenticated>(), Some(&Authenticated));
    for (m, p, t) in [
        ("POST", "/sync", Some("bad")),
        ("POST", "/sync", None),
        ("GET", "/sync", None),
        ("GET", "/", None),
    ] {
        assert_eq!(
            send(&a, m, p, ip, t).await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{m} {p}"
        );
    }
    assert_eq!(guard.admit("198.51.100.1", Instant::now()), Verdict::Ok);
    assert!(harmless_probe(&Method::HEAD, "/favicon.ico"));
    assert!(!harmless_probe(&Method::GET, "/wp-login.php"));
}

/// The README's example: a closure without captures as the hook.
#[test]
fn closure_hook_compiles() {
    let lim = Limits {
        count_unknown_path: Some(|_, _| true),
        ..Limits::default()
    };
    let f = lim.count_unknown_path.unwrap();
    assert!(f(&Method::GET, "/wp-login.php"));
    assert!(!Limits::default().serve_authenticated_when_banned);
    assert!(Limits::default().count_unknown_path.is_none());
}
