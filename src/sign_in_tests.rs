//! End-to-end sign-in flows: allowlist, enrolment codes (expiry, single
//! use, bound to one address), the subject in the grant, revocation by
//! another process (bearer and refresh), the ban on code failures, and the
//! migration of version 0.1 grants.

use crate::cimd::tests::{CLAUDE, CLAUDE_DOC};
use crate::oauth::tests::{config, tmp_dir};
use crate::{ENROL_CODE_TTL, Grant, Guard, Limits, OAuth, Users, protect};
use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::any,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tower::ServiceExt;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const IP: &str = "198.51.100.20";
const CB: &str = "https://claude.ai/api/mcp/auth_callback";
const ADA: &str = "ada@example.org";
const BOB: &str = "bob@example.org";

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
    let r = app.clone().oneshot(req).await.unwrap();
    let status = r.status();
    let headers = r.headers().clone();
    let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn form_at(ip: &str, path: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("cf-connecting-ip", ip)
        .body(Body::from(serde_urlencoded::to_string(pairs).unwrap()))
        .unwrap()
}

fn form(path: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    form_at(IP, path, pairs)
}

fn mcp(bearer: &str) -> Request<Body> {
    Request::post("/mcp")
        .header("cf-connecting-ip", IP)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

fn hidden_value(html: &str, name: &str) -> String {
    let pat = format!("name=\"{name}\" value=\"");
    let i = html
        .find(&pat)
        .unwrap_or_else(|| panic!("no hidden {name} in {html}"))
        + pat.len();
    html[i..i + html[i..].find('"').unwrap()].to_string()
}

fn query_param(url: &str, k: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(q)
        .ok()?
        .into_iter()
        .find(|(a, _)| a == k)
        .map(|(_, v)| v)
}

/// `/mcp` echoes `client_id subject` of the grant.
fn app_with(o: &OAuth, lim: Limits) -> Router {
    let r = Router::new()
        .route(
            "/mcp",
            any(|Extension(g): Extension<Grant>| async move {
                format!("{} {}", g.client_id, g.subject.as_deref().unwrap_or("-"))
            })
            .layer(o.bearer_layer()),
        )
        .merge(o.router());
    protect(r, Guard::new(lim))
}

/// A server with the Claude CIMD client allowlisted.
fn server(dir: &Path, lim: Limits) -> (OAuth, Router) {
    let mut c = config(dir);
    c.cimd_allowlist = Some(vec![CLAUDE.into()]);
    let o = OAuth::new_for_tests(c).unwrap();
    o.cimd().serve(CLAUDE, 200, CLAUDE_DOC.as_bytes());
    let app = app_with(&o, lim);
    (o, app)
}

fn setup(tag: &str) -> (PathBuf, OAuth, Router) {
    let dir = tmp_dir(tag);
    let (o, app) = server(&dir, Limits::default());
    (dir, o, app)
}

fn authz_params(ch: &str) -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".into()),
        ("client_id", CLAUDE.into()),
        ("redirect_uri", CB.into()),
        ("state", "st-1".into()),
        ("code_challenge", ch.into()),
        ("code_challenge_method", "S256".into()),
        ("scope", "mcp".into()),
        ("resource", "https://issuer.test/mcp".into()),
    ]
}

/// The login step with `email` and `code` from `ip`.
async fn login_at(app: &Router, ip: &str, email: &str, code: &str) -> Resp {
    let ch = B64.encode(Sha256::digest(VERIFIER.as_bytes()));
    let mut f = authz_params(&ch);
    f.extend([
        ("step", "login".into()),
        ("email", email.into()),
        ("code", code.into()),
    ]);
    let pairs: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    send(app, form_at(ip, "/oauth/authorize", &pairs)).await
}

/// Consent on the ticket of a successful login; the authorization code.
async fn consent(app: &Router, login: &Resp) -> String {
    assert_eq!(login.status, StatusCode::OK, "{}", login.body);
    let ticket = hidden_value(&login.body, "ticket");
    let r = send(
        app,
        form(
            "/oauth/authorize",
            &[
                ("step", "consent"),
                ("ticket", ticket.as_str()),
                ("decision", "allow"),
            ],
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{}", r.body);
    let loc = r.headers[header::LOCATION].to_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{CB}?")), "{loc}");
    query_param(&loc, "code").unwrap()
}

async fn exchange(app: &Router, code: &str) -> Resp {
    send(
        app,
        form(
            "/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", CB),
                ("client_id", CLAUDE),
                ("code_verifier", VERIFIER),
                ("resource", "https://issuer.test/mcp"),
            ],
        ),
    )
    .await
}

async fn refresh(app: &Router, token: &str) -> Resp {
    send(
        app,
        form(
            "/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", CLAUDE),
            ],
        ),
    )
    .await
}

/// `(access, refresh)` of a token response.
fn tokens(r: &Resp) -> (String, String) {
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let j = r.json();
    (
        j["access_token"].as_str().unwrap().to_string(),
        j["refresh_token"].as_str().unwrap().to_string(),
    )
}

/// Full sign-in of `email` with `code`: `(access, refresh)`.
async fn sign_in(app: &Router, email: &str, code: &str) -> (String, String) {
    let l = login_at(app, IP, email, code).await;
    assert!(l.body.contains("Signed in as <b>"), "{}", l.body);
    let c = consent(app, &l).await;
    tokens(&exchange(app, &c).await)
}

fn assert_refused(r: &Resp) {
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(
        r.body
            .contains("Unknown address, or wrong, expired or already used code."),
        "{}",
        r.body
    );
    assert!(!r.body.contains("name=\"ticket\""), "no ticket: {}", r.body);
}

/// The login page asks for an address and a code, never a password; the
/// subject reaches the app in the grant; the token file keeps no secret.
#[tokio::test]
async fn sign_in_puts_the_subject_in_the_grant() {
    let (dir, o, app) = setup("mu-subject");
    assert_eq!(o.refresh_ttl(), crate::REFRESH_TTL);
    let ch = B64.encode(Sha256::digest(VERIFIER.as_bytes()));
    let q = serde_urlencoded::to_string(authz_params(&ch)).unwrap();
    let r = send(
        &app,
        Request::get(format!("/oauth/authorize?{q}"))
            .header("cf-connecting-ip", IP)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("name=\"email\"") && r.body.contains("name=\"code\""));
    assert!(!r.body.contains("type=\"password\""), "{}", r.body);

    // The admin API, here through the server's handle; mixed case typed.
    let users = o.users();
    users.allow("Ada@Example.org").unwrap();
    let code = users.enrol_code(ADA).unwrap();
    let (access, refresh_token) = sign_in(&app, " ADA@example.ORG ", &code.to_lowercase()).await;
    let r = send(&app, mcp(&access)).await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, format!("{CLAUDE} {ADA}").as_str())
    );
    let g = o.validate(&access).unwrap();
    assert_eq!(g.subject.as_deref(), Some(ADA));
    assert_eq!((g.client_id.as_str(), g.scope.as_str()), (CLAUDE, "mcp"));

    // Refresh keeps the subject.
    let (access2, _) = tokens(&refresh(&app, &refresh_token).await);
    assert_eq!(o.validate(&access2).unwrap().subject.as_deref(), Some(ADA));

    // At rest: the subject, never a token or the code.
    let raw = std::fs::read_to_string(dir.join("oauth-tokens.json")).unwrap();
    assert!(raw.contains(ADA) && !raw.contains(&access2) && !raw.contains(&refresh_token));
    let raw = std::fs::read_to_string(dir.join("oauth-users.json")).unwrap();
    assert!(!raw.contains(&code) && !raw.contains(&code.replace('-', "")));
    let l = users.list().unwrap();
    assert_eq!(l.len(), 1);
    assert!(l[0].last_sign_in_at.is_some() && l[0].code_expires_at.is_none());

    // A restart keeps the grant and its subject.
    drop((o, app));
    let (o, _app) = server(&dir, Limits::default());
    assert_eq!(o.validate(&access2).unwrap().subject.as_deref(), Some(ADA));
    let _ = std::fs::remove_dir_all(dir);
}

/// Only allowlisted addresses sign in; expired, reused and other people's
/// codes are refused, all with the same answer.
#[tokio::test]
async fn allowlist_expiry_single_use_and_binding() {
    let (dir, o, app) = setup("mu-codes");
    let users = o.users().clone();
    users.allow(ADA).unwrap();
    users.allow(BOB).unwrap();

    // Not on the allowlist (with a real code of someone else).
    let code = users.enrol_code(ADA).unwrap();
    assert_refused(&login_at(&app, IP, "eve@example.org", &code).await);
    assert!(users.enrol_code("eve@example.org").is_err());

    // Ada's code is no use to Bob (who holds a live code of his own),
    // and a wrong attempt does not burn it.
    let bob_code = users.enrol_code(BOB).unwrap();
    assert_refused(&login_at(&app, IP, BOB, &code).await);
    assert_refused(&login_at(&app, IP, ADA, &bob_code).await);
    assert_refused(&login_at(&app, IP, ADA, "0000-0000-0000-0000").await);
    assert_refused(&login_at(&app, IP, ADA, "").await);
    let first = login_at(&app, IP, ADA, &code).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);

    // Single use: the same code again, even before the first sign-in is
    // finished.
    let again = login_at(&app, IP, ADA, &code).await;
    assert_refused(&again);
    assert!(
        again.body.contains(&format!("value=\"{ADA}\"")),
        "address refilled"
    );
    let c = consent(&app, &first).await;
    tokens(&exchange(&app, &c).await);
    assert_refused(&login_at(&app, IP, ADA, &code).await);

    // Expired: issued 24 h ago.
    let now = crate::oauth::unix_now();
    let old = users.enrol_code_at(BOB, now - ENROL_CODE_TTL).unwrap();
    assert_refused(&login_at(&app, IP, BOB, &old).await);
    let fresh = users
        .enrol_code_at(BOB, now - ENROL_CODE_TTL + 120)
        .unwrap();
    let (access, _) = sign_in(&app, BOB, &fresh).await;
    assert_eq!(o.validate(&access).unwrap().subject.as_deref(), Some(BOB));
    let _ = std::fs::remove_dir_all(dir);
}

/// Two sign-ins racing with one code: exactly one gets a ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_sign_ins_use_a_code_once() {
    let (dir, o, app) = setup("mu-race");
    let users = o.users();
    users.allow(ADA).unwrap();
    for _ in 0..5 {
        let code = users.enrol_code(ADA).unwrap();
        let mut tasks = Vec::new();
        for i in 0..8 {
            let (app, code) = (app.clone(), code.clone());
            tasks.push(tokio::spawn(async move {
                login_at(&app, &format!("203.0.113.{i}"), ADA, &code).await
            }));
        }
        let mut ok = 0;
        for t in tasks {
            let r = t.await.unwrap();
            if r.status == StatusCode::OK {
                ok += 1;
            } else {
                assert_refused(&r);
            }
        }
        assert_eq!(ok, 1, "one winner");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The admin tool (another `Users` handle, as another process would have)
/// revokes a user: their access token stops at once (401 invalid_token,
/// not counted), refresh fails and removes the grant, other users are not
/// affected, and allowing the address again does not bring the old tokens
/// back.
#[tokio::test]
async fn revocation_cuts_access_and_refresh() {
    let (dir, o, app) = setup("mu-revoke");
    let admin = Users::open(&dir).unwrap();
    admin.allow(ADA).unwrap();
    admin.allow(BOB).unwrap();
    let (a_access, a_refresh) = sign_in(&app, ADA, &admin.enrol_code(ADA).unwrap()).await;
    let (b_access, b_refresh) = sign_in(&app, BOB, &admin.enrol_code(BOB).unwrap()).await;
    // A second connection of Ada (another client session).
    let (a2_access, a2_refresh) = sign_in(&app, ADA, &admin.enrol_code(ADA).unwrap()).await;
    for t in [&a_access, &a2_access, &b_access] {
        assert_eq!(send(&app, mcp(t)).await.status, StatusCode::OK);
    }

    assert!(admin.revoke(ADA).unwrap());
    for t in [&a_access, &a2_access] {
        let r = send(&app, mcp(t)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
        assert!(
            r.headers[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("error=\"invalid_token\"")
        );
        assert!(o.validate(t).is_none());
    }
    assert_eq!(
        send(&app, mcp(&b_access)).await.status,
        StatusCode::OK,
        "Bob unaffected"
    );

    // Refresh after revocation: refused, and the grant is gone.
    let r = refresh(&app, &a_refresh).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    assert_eq!(r.json()["error"], "invalid_grant");
    let raw = std::fs::read_to_string(dir.join("oauth-tokens.json")).unwrap();
    assert_eq!(
        raw.matches(ADA).count(),
        1,
        "one of Ada's two grants removed: {raw}"
    );

    // Allowed again: the old tokens stay dead; a new code works.
    assert!(admin.allow(ADA).unwrap());
    assert!(o.validate(&a2_access).is_none());
    assert_eq!(
        refresh(&app, &a2_refresh).await.json()["error"],
        "invalid_grant"
    );
    let (new_access, _) = sign_in(&app, ADA, &admin.enrol_code(ADA).unwrap()).await;
    assert_eq!(
        o.validate(&new_access).unwrap().subject.as_deref(),
        Some(ADA)
    );
    tokens(&refresh(&app, &b_refresh).await);

    // Revoked between sign-in and code exchange: no tokens.
    let l = login_at(&app, IP, BOB, &admin.enrol_code(BOB).unwrap()).await;
    let c = consent(&app, &l).await;
    admin.revoke(BOB).unwrap();
    let r = exchange(&app, &c).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    assert_eq!(r.json()["error"], "invalid_grant");
    let _ = std::fs::remove_dir_all(dir);
}

/// Wrong codes count as authentication failures: the IP is banned after
/// `max_failures`, and a banned IP's code is not even checked (no oracle,
/// and the code is not consumed: it still works from elsewhere).
#[tokio::test]
async fn code_failures_ban_the_ip() {
    let dir = tmp_dir("mu-ban");
    let lim = Limits {
        max_failures: 3,
        per_ip_burst: 1000.0,
        ..Limits::default()
    };
    let (o, app) = server(&dir, lim.clone());
    let users = o.users();
    users.allow(ADA).unwrap();
    let code = users.enrol_code(ADA).unwrap();
    let bad = "198.51.100.66";
    assert_refused(&login_at(&app, bad, "eve@example.org", &code).await);
    assert_refused(&login_at(&app, bad, ADA, "1111-2222-3333-4444").await);
    assert_refused(&login_at(&app, bad, ADA, "nope").await);
    let r = login_at(&app, bad, ADA, &code).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    assert!(
        users.list().unwrap()[0].code_expires_at.is_some(),
        "not consumed"
    );
    let r = login_at(&app, IP, ADA, &code).await;
    assert_eq!(r.status, StatusCode::OK, "another IP: {}", r.body);

    // Shared-IP mode: the login step is still not answered for a banned IP.
    let dir2 = tmp_dir("mu-ban-shared");
    let (o2, app2) = server(
        &dir2,
        Limits {
            serve_authenticated_when_banned: true,
            ..lim
        },
    );
    let u2 = o2.users();
    u2.allow(ADA).unwrap();
    let code = u2.enrol_code(ADA).unwrap();
    for _ in 0..3 {
        assert_refused(&login_at(&app2, bad, ADA, "0000-0000-0000-0000").await);
    }
    let r = login_at(&app2, bad, ADA, &code).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    assert!(
        u2.list().unwrap()[0].code_expires_at.is_some(),
        "not consumed"
    );
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}

/// Migration from version 0.1: its token families have no user and are
/// not honoured, until `adopt_unowned_grants` gives them to the former
/// owner's address (which must be allowed); then they work, survive a
/// restart, and a revocation cuts them like any other.
#[tokio::test]
async fn unowned_grants_from_0_1_are_adopted() {
    let dir = tmp_dir("mu-adopt");
    let (o, app) = server(&dir, Limits::default());
    let (old_access, old_refresh) = o.unowned_grant_for_tests(CLAUDE);
    assert!(o.validate(&old_access).is_none(), "no user: not honoured");
    let r = send(&app, mcp(&old_access)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{}", r.body);
    assert!(o.adopt_unowned_grants(ADA).is_err(), "not allowed yet");
    o.users().allow(ADA).unwrap();
    assert_eq!(o.adopt_unowned_grants(" Ada@Example.org").unwrap(), 1);
    assert_eq!(o.adopt_unowned_grants(ADA).unwrap(), 0, "once");
    let r = send(&app, mcp(&old_access)).await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (StatusCode::OK, format!("{CLAUDE} {ADA}").as_str())
    );
    drop((o, app));
    let (o, app) = server(&dir, Limits::default());
    assert_eq!(
        o.validate(&old_access).unwrap().subject.as_deref(),
        Some(ADA),
        "persisted"
    );
    let (fresh, _) = tokens(&refresh(&app, &old_refresh).await);
    o.users().revoke(ADA).unwrap();
    assert!(o.validate(&fresh).is_none());
    // Configuration.
    assert_eq!(o.refresh_ttl(), crate::REFRESH_TTL);
    let o = o.with_refresh_ttl(10);
    assert_eq!(
        o.refresh_ttl(),
        crate::ACCESS_TTL,
        "at least the access TTL"
    );
    let _ = std::fs::remove_dir_all(dir);
}
