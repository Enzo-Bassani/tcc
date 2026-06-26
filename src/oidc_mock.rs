//! In-process mock OIDC provider. Stands in for the university SSO during
//! testing. After validating credentials it short-circuits straight to minting
//! an OAuth authorization code.

use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::crypto::random_b64url;
use crate::db;
use crate::state::AppState;

pub struct MockUser {
    pub sub: &'static str,
    pub username: &'static str,
    pub password: &'static str,
}

/// Hardcoded test students. Their `sub` matches `students.external_sub`.
pub const USERS: &[MockUser] = &[
    MockUser {
        sub: "alice",
        username: "alice",
        password: "alice",
    },
    MockUser {
        sub: "bob",
        username: "bob",
        password: "bob",
    },
];

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub session: String,
}

/// `GET /mock-idp/login` — render the login form.
pub async fn login_form(Query(q): Query<LoginQuery>) -> Html<String> {
    Html(render_form(&q.session, None))
}

fn render_form(session: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p style=\"color:#c00\">{e}</p>"))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>University SSO (mock)</title></head>
<body style="font-family:sans-serif;max-width:24rem;margin:3rem auto">
<h2>University SSO (mock)</h2>
{err}
<form method="post" action="/mock-idp/login">
  <input type="hidden" name="session" value="{session}"/>
  <p><label>Username<br/><input name="username" autofocus/></label></p>
  <p><label>Password<br/><input name="password" type="password"/></label></p>
  <button type="submit">Sign in</button>
</form>
<p style="color:#888">Test users: alice/alice, bob/bob</p>
</body></html>"#
    )
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub session: String,
    pub username: String,
    pub password: String,
}

enum LoginError {
    BadCredentials,
    Server(String),
}

/// `POST /mock-idp/login` — validate credentials, mint an authorization code,
/// and redirect back to the wallet's `redirect_uri`.
pub async fn login_submit(State(st): State<AppState>, Form(f): Form<LoginForm>) -> Response {
    match try_login(&st, &f).await {
        Ok(redirect) => redirect.into_response(),
        Err(LoginError::BadCredentials) => {
            Html(render_form(&f.session, Some("Invalid username or password"))).into_response()
        }
        Err(LoginError::Server(msg)) => {
            crate::error::AppError::Internal(anyhow::anyhow!(msg)).into_response()
        }
    }
}

async fn try_login(st: &AppState, f: &LoginForm) -> Result<Redirect, LoginError> {
    let user = USERS
        .iter()
        .find(|u| u.username == f.username && u.password == f.password)
        .ok_or(LoginError::BadCredentials)?;

    let session = db::get_auth_session(&st.db, &f.session)
        .await
        .map_err(|e| LoginError::Server(e.to_string()))?
        .ok_or_else(|| LoginError::Server("unknown auth session".into()))?;

    let student = db::student_by_sub(&st.db, user.sub)
        .await
        .map_err(|e| LoginError::Server(e.to_string()))?
        .ok_or_else(|| LoginError::Server("no student record for user".into()))?;

    let code = random_b64url(24);
    db::insert_authorization_code(
        &st.db,
        &code,
        student.id,
        &session.redirect_uri,
        &session.code_challenge,
        &session.code_challenge_method,
        &session.credential_config_id,
    )
    .await
    .map_err(|e| LoginError::Server(e.to_string()))?;

    let sep = if session.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut url = format!("{}{}code={}", session.redirect_uri, sep, code);
    if let Some(state) = &session.state {
        url.push_str(&format!("&state={state}"));
    }
    // RFC 9207 (HAIP §4): the authorization server MUST return its issuer
    // identifier as `iss` in the authorization response so the wallet can detect
    // mix-up attacks. The identifier is the AS `issuer` (see `as_metadata`).
    let iss: String = url::form_urlencoded::byte_serialize(st.config.issuer().as_bytes()).collect();
    url.push_str(&format!("&iss={iss}"));
    Ok(Redirect::to(&url))
}
