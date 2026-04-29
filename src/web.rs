use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::Router;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Json, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::{SinkExt, StreamExt as FuturesStreamExt};
use portable_pty::{ChildKiller, CommandBuilder, PtySize, native_pty_system};
use qrcode::{QrCode, render::svg};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::once;
use tokio_stream::wrappers::BroadcastStream;
use tower_http::trace::TraceLayer;
use url::{Host, Url};
use uuid::Uuid;

const DESKTOP_CLIENT_ID: &str = "portal-desktop";
const ANDROID_CLIENT_ID: &str = "portal-android";
const ANDROID_REDIRECT_SCHEME: &str = "com.digitalpals.portal.android";
const ANDROID_REDIRECT_PATH: &str = "/oauth2redirect";
const ACCESS_TOKEN_TTL_HOURS: i64 = 24;
const REFRESH_TOKEN_TTL_DAYS: i64 = 90;
const AUTH_CODE_TTL_MINUTES: i64 = 5;
const MIN_PASSWORD_LEN: usize = 12;

const PORTAL_ASCII_LOGO: &str = r#"                                  .             oooo
                                .o8             `888
oo.ooooo.   .ooooo.  oooo d8b .o888oo  .oooo.    888
 888' `88b d88' `88b `888""8P   888   `P  )88b   888
 888   888 888   888  888       888    .oP"888   888
 888   888 888   888  888       888 . d8(  888   888
 888bod8P' `Y8bod8P' d888b      "888" `Y888""8o o888o
 888
o888o"#;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    state_dir: PathBuf,
    public_url: String,
    ssh_port: u16,
    sync_events: broadcast::Sender<SyncRevisionEvent>,
}

#[derive(Debug, Deserialize)]
struct VaultEnrollmentCreateRequest {
    device_name: String,
    public_key_algorithm: String,
    public_key_der_base64: String,
}

#[derive(Debug, Deserialize)]
struct VaultEnrollmentApproveRequest {
    encrypted_secret_base64: String,
}

#[derive(Debug, Deserialize)]
struct VaultEnrollmentListQuery {
    status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct VaultEnrollment {
    id: String,
    device_name: String,
    public_key_algorithm: String,
    public_key_der_base64: String,
    status: String,
    encrypted_secret_base64: Option<String>,
    created_at: String,
    updated_at: String,
    approved_at: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    oauth: AuthorizeQuery,
}

#[derive(Debug, Serialize)]
struct LoginFinishResponse {
    redirect_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    id: String,
    username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncState {
    revision: String,
    profile: Value,
    vault: Value,
}

#[derive(Debug, Deserialize)]
struct SyncPutRequest {
    expected_revision: String,
    profile: Value,
    vault: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncServiceState {
    revision: String,
    payload: Value,
    tombstones: Value,
}

#[derive(Debug, Clone)]
struct SyncRevisionEvent {
    user_id: String,
    services: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SyncV2PutRequest {
    services: HashMap<String, SyncV2ServicePut>,
}

#[derive(Debug, Deserialize)]
struct SyncV2ServicePut {
    expected_revision: String,
    payload: Value,
    #[serde(default = "default_tombstones")]
    tombstones: Value,
}

#[derive(Debug, Deserialize)]
struct SessionsQuery {
    #[serde(default)]
    active: bool,
    #[serde(default)]
    include_preview: bool,
    #[serde(default = "default_preview_bytes")]
    preview_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct WebTerminalStart {
    session_id: Uuid,
    target_host: String,
    target_port: u16,
    target_user: String,
    cols: u16,
    rows: u16,
    #[serde(default)]
    private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WebTerminalControl {
    Resize { cols: u16, rows: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionMetadata {
    schema_version: u16,
    session_id: Uuid,
    session_name: String,
    target_host: String,
    target_port: u16,
    target_user: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_group_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_id: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ListedSession {
    #[serde(flatten)]
    metadata: SessionMetadata,
    active: bool,
    last_output_at: Option<DateTime<Utc>>,
    preview_base64: Option<String>,
    preview_truncated: bool,
}

pub fn run(state_dir: PathBuf, bind: String, public_url: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("failed to start Tokio runtime")?;
    let ssh_port = std::env::var("PORTAL_HUB_SSH_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(2222);
    rt.block_on(run_async(state_dir, bind, public_url, ssh_port))
}

async fn run_async(
    state_dir: PathBuf,
    bind: String,
    public_url: Option<String>,
    ssh_port: u16,
) -> Result<()> {
    std::fs::create_dir_all(&state_dir).context("failed to create Portal Hub state dir")?;
    let db_path = state_dir.join("hub.db");
    let db = Connection::open(db_path).context("failed to open Portal Hub database")?;
    init_db(&db)?;

    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid bind address: {}", bind))?;
    let public_url = match public_url {
        Some(public_url) => canonicalize_public_url(&public_url)?,
        None => {
            if bind_addr.ip().is_loopback() {
                format!("http://portal-hub.localhost:{}", bind_addr.port())
            } else {
                format!("http://{}", bind_addr)
            }
        }
    };
    let (sync_events, _) = broadcast::channel(256);
    let state = AppState {
        db: Arc::new(Mutex::new(db)),
        state_dir,
        public_url,
        ssh_port,
        sync_events,
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/admin", get(admin_page))
        .route("/pair/android", get(android_pairing_page))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/oauth/authorize", get(authorize_page))
        .route("/oauth/token", post(token))
        .route("/api/info", get(api_info))
        .route("/api/me", get(api_me))
        .route("/api/sessions", get(api_sessions))
        .route("/api/sessions/:id", delete(api_session_delete))
        .route("/api/sessions/terminal", get(api_session_terminal))
        .route("/api/sync", get(api_sync_get).put(api_sync_put))
        .route("/api/sync/v2", get(api_sync_v2_get).put(api_sync_v2_put))
        .route("/api/sync/v2/events", get(api_sync_v2_events))
        .route(
            "/api/vault/enrollments",
            get(api_vault_enrollments).post(api_vault_enrollment_create),
        )
        .route("/api/vault/enrollments/:id", get(api_vault_enrollment_get))
        .route(
            "/api/vault/enrollments/:id/approve",
            post(api_vault_enrollment_approve),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", bind_addr))?;
    eprintln!("Portal Hub web listening on {}", bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_db(db: &Connection) -> Result<()> {
    db.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS access_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS profiles (
            user_id TEXT PRIMARY KEY,
            revision TEXT NOT NULL,
            profile TEXT NOT NULL,
            vault TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_services (
            user_id TEXT NOT NULL,
            service TEXT NOT NULL,
            revision TEXT NOT NULL,
            payload TEXT NOT NULL,
            tombstones TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(user_id, service)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            user_id TEXT,
            detail TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault_enrollments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            public_key_algorithm TEXT NOT NULL,
            public_key_der_base64 TEXT NOT NULL,
            encrypted_secret_base64 TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            approved_at TEXT
        );
        "#,
    )?;
    ensure_password_hash_column(db)?;
    Ok(())
}

async fn root(State(state): State<AppState>) -> Response {
    if user_count(&state).unwrap_or(0) == 0 {
        Redirect::to("/admin").into_response()
    } else {
        Html(page(
            "Portal Hub",
            &format!(
                r#"<section class="panel">
                    <p class="eyebrow">Hub online</p>
                    <h1>Portal Hub is running.</h1>
                    <p class="lead">Desktop clients can authenticate and sync through <code>{}</code>.</p>
                    {}
                  </section>"#,
                html_escape(&state.public_url),
                android_pairing_panel(&state.public_url)
            ),
        ))
        .into_response()
    }
}

async fn admin_page(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let continue_url = admin_continue_url(&params).unwrap_or_default();
    if user_count(&state).unwrap_or(0) > 0 {
        if let Ok(Some(username)) = owner_missing_password(&state) {
            return Html(page(
                "Set Portal Hub Password",
                &format!(
                    r#"<section class="panel setup-panel">
                        <div id="setup-error" class="error" hidden></div>
                        <form id="owner-form" class="flow" autocomplete="off" data-password-only="true" data-continue-url="{}">
                          <p class="eyebrow">Owner password</p>
                          <h1>Set a password.</h1>
                          <p class="lead">This existing owner account needs a password before Portal desktop can sign in.</p>
                          <label>Account name<input id="username" name="username" autocomplete="username" required minlength="2" maxlength="64" readonly value="{}"></label>
                          <label>Password<input id="password" name="password" type="password" autocomplete="new-password" required minlength="{}" maxlength="256"></label>
                          <label>Confirm password<input id="password-confirm" name="password-confirm" type="password" autocomplete="new-password" required minlength="{}" maxlength="256"></label>
                          <button type="submit" id="create-button">Set password</button>
                        </form>
                      </section>"#,
                    html_escape(&continue_url),
                    html_escape(&username),
                    MIN_PASSWORD_LEN,
                    MIN_PASSWORD_LEN
                ),
            ))
            .into_response();
        }
        return Html(page(
            "Portal Hub",
            &format!(
                r#"<section class="panel">
                <p class="eyebrow">Owner exists</p>
                <h1>Portal Hub is ready.</h1>
                <p class="lead">Continue through Portal desktop sign-in to authenticate with your password.</p>
                {}
                {}
              </section>"#,
                continue_button_html(&continue_url),
                android_pairing_panel(&state.public_url)
            ),
        ))
        .into_response();
    }

    Html(page(
        "Create Portal Hub Owner",
        &format!(
            r#"<section class="panel setup-panel">
            <div class="steps" aria-label="Setup progress">
              <span class="step-dot active" data-step-dot="1">1</span>
              <span class="step-line"></span>
              <span class="step-dot" data-step-dot="2">2</span>
            </div>
            <div id="setup-error" class="error" hidden></div>
            <form id="owner-form" class="flow" autocomplete="off" data-continue-url="{}">
              <div class="wizard-step" data-step="1">
                <p class="eyebrow">First owner</p>
                <h1>Name this account.</h1>
                <p class="lead">This name is stored on the Hub and shown in Portal after sign-in.</p>
                <label>Account name<input id="username" name="username" autocomplete="username" required minlength="2" maxlength="64" autofocus></label>
                <button type="button" id="next-button">Next</button>
              </div>
              <div class="wizard-step" data-step="2" hidden>
                <p class="eyebrow">Password</p>
                <h1>Create a password.</h1>
                <p class="lead">This password protects Portal desktop sign-in to this Hub.</p>
                <label>Password<input id="password" name="password" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
                <label>Confirm password<input id="password-confirm" name="password-confirm" type="password" autocomplete="new-password" required minlength="12" maxlength="256"></label>
                <div class="security-callout">
                  <span class="security-icon" aria-hidden="true"></span>
                  <div>
                    <strong>Use a unique password.</strong>
                    <p>The Hub stores only an Argon2 password hash.</p>
                  </div>
                </div>
                <div class="actions">
                  <button type="button" class="secondary" id="back-button">Back</button>
                  <button type="submit" id="create-button">Create owner</button>
                </div>
              </div>
            </form>
          </section>"#,
            html_escape(&continue_url)
        ),
    ))
    .into_response()
}

async fn android_pairing_page(State(state): State<AppState>) -> Response {
    Html(page(
        "Pair Portal Android",
        &format!(
            r#"<section class="panel">
                <p class="eyebrow">Android pairing</p>
                <h1>Pair Portal Android.</h1>
                <p class="lead">Scan this QR code on Android to select this Hub, sign in, and request vault access automatically.</p>
                {}
              </section>"#,
            android_pairing_panel(&state.public_url)
        ),
    ))
    .into_response()
}

async fn authorize_page(
    State(state): State<AppState>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    if let Err(error) = validate_authorize_query(&query) {
        return (
            StatusCode::BAD_REQUEST,
            Html(page("Invalid Request", &error_panel(&error.to_string()))),
        )
            .into_response();
    }
    if user_count(&state).unwrap_or(0) == 0 {
        let location = authorize_path("/admin", &query);
        return Redirect::to(&location).into_response();
    }

    Html(page(
        "Sign In To Portal Hub",
        r#"<section class="panel auth-panel">
            <p class="eyebrow">Portal desktop sign-in</p>
            <h1>Sign in.</h1>
            <p class="lead">Portal Hub will confirm your password, then return you to Portal.</p>
            <div id="login-error" class="error" hidden></div>
            <form id="login-form" class="flow" autocomplete="on">
              <label>Account name<input id="username" name="username" autocomplete="username" required autofocus></label>
              <label>Password<input id="password" name="password" type="password" autocomplete="current-password" required></label>
              <button type="submit" id="login-button">Sign in</button>
            </form>
          </section>"#,
    ))
    .into_response()
}

async fn register(State(state): State<AppState>, Json(request): Json<RegisterRequest>) -> Response {
    match register_inner(&state, request) {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn register_inner(state: &AppState, request: RegisterRequest) -> Result<()> {
    validate_username(&request.username)?;
    validate_password(&request.password)?;
    let username = request.username.trim().to_string();
    let user_id = Uuid::new_v4();
    let password_hash = hash_password(&request.password)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;

    let count: i64 = db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    if count == 0 {
        insert_user(&db, user_id, &username, &password_hash)?;
        audit_db(
            &db,
            "owner_created",
            Some(&user_id.to_string()),
            json!({"username": username, "auth_method": "password"}),
        )?;
        return Ok(());
    }

    let existing = db
        .query_row(
            "SELECT id, COALESCE(password_hash, '') FROM users WHERE username = ?1",
            [username.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((existing_user_id, existing_password_hash)) = existing else {
        bail!("owner account already exists");
    };
    if !existing_password_hash.is_empty() {
        bail!("owner account already exists");
    }
    db.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![password_hash, existing_user_id],
    )?;
    audit_db(
        &db,
        "owner_password_set",
        Some(&existing_user_id),
        json!({"username": username, "auth_method": "password"}),
    )?;
    Ok(())
}

async fn login(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Response {
    match login_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::UNAUTHORIZED, error),
    }
}

fn login_inner(state: &AppState, request: LoginRequest) -> Result<LoginFinishResponse> {
    validate_authorize_query(&request.oauth)?;
    validate_username(&request.username)?;
    if request.password.is_empty() {
        bail!("missing password");
    }
    let username = request.username.trim().to_string();
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some((user_id, password_hash)) = db
        .query_row(
            "SELECT id, COALESCE(password_hash, '') FROM users WHERE username = ?1",
            [username.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        audit_db(
            &db,
            "login_failed",
            None,
            json!({"username": username, "reason": "unknown_user"}),
        )?;
        bail!("unknown account");
    };
    if password_hash.is_empty() {
        audit_db(
            &db,
            "login_failed",
            Some(&user_id),
            json!({"username": username, "reason": "password_not_set"}),
        )?;
        bail!("this account needs a password");
    }
    if !verify_password(&request.password, &password_hash)? {
        audit_db(
            &db,
            "login_failed",
            Some(&user_id),
            json!({"username": username, "reason": "invalid_password"}),
        )?;
        bail!("invalid password");
    }

    let code = random_token();
    let expires_at = (Utc::now() + ChronoDuration::minutes(AUTH_CODE_TTL_MINUTES)).to_rfc3339();
    db.execute(
        "INSERT INTO auth_codes (code, user_id, client_id, redirect_uri, code_challenge, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            code,
            user_id,
            request.oauth.client_id,
            request.oauth.redirect_uri,
            request.oauth.code_challenge,
            expires_at
        ],
    )?;
    audit_db(
        &db,
        "login_success",
        Some(&user_id),
        json!({"client_id": request.oauth.client_id, "auth_method": "password"}),
    )?;

    Ok(LoginFinishResponse {
        redirect_uri: format!(
            "{}?code={}&state={}",
            request.oauth.redirect_uri,
            urlencoding::encode(&code),
            urlencoding::encode(&request.oauth.state)
        ),
    })
}

async fn token(
    State(state): State<AppState>,
    axum::Form(request): axum::Form<TokenRequest>,
) -> Response {
    match token_inner(&state, request) {
        Ok(response) => Json(response).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn token_inner(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    match request.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(state, request),
        "refresh_token" => exchange_refresh_token(state, request),
        _ => bail!("unsupported grant_type"),
    }
}

fn exchange_authorization_code(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    let code = request.code.ok_or_else(|| anyhow!("missing code"))?;
    let verifier = request
        .code_verifier
        .ok_or_else(|| anyhow!("missing code_verifier"))?;
    let redirect_uri = request
        .redirect_uri
        .ok_or_else(|| anyhow!("missing redirect_uri"))?;
    let client_id = request
        .client_id
        .ok_or_else(|| anyhow!("missing client_id"))?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some((user_id, stored_client_id, stored_redirect_uri, challenge, expires_at)) = db
        .query_row(
            "SELECT user_id, client_id, redirect_uri, code_challenge, expires_at FROM auth_codes WHERE code = ?1",
            [&code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    else {
        bail!("invalid code");
    };
    if stored_client_id != client_id || stored_redirect_uri != redirect_uri {
        bail!("invalid code binding");
    }
    if DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&Utc) < Utc::now() {
        bail!("authorization code expired");
    }
    if pkce_challenge(&verifier) != challenge {
        bail!("invalid code_verifier");
    }
    db.execute("DELETE FROM auth_codes WHERE code = ?1", [&code])?;
    issue_tokens(&db, &user_id, &client_id)
}

fn exchange_refresh_token(state: &AppState, request: TokenRequest) -> Result<TokenResponse> {
    let client_id = request.client_id.unwrap_or_else(|| "unknown".to_string());
    if client_id != "unknown" && !is_supported_client_id(&client_id) {
        bail!("unknown client_id");
    }
    let refresh_token = request
        .refresh_token
        .ok_or_else(|| anyhow!("missing refresh_token"))?;
    let refresh_hash = token_hash(&refresh_token);
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let Some((user_id, expires_at)) = db
        .query_row(
            "SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?1",
            [&refresh_hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    else {
        bail!("invalid refresh_token");
    };
    if DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&Utc) < Utc::now() {
        bail!("refresh_token expired");
    }
    db.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = ?1",
        [&refresh_hash],
    )?;
    issue_tokens(&db, &user_id, &client_id)
}

async fn api_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authenticated_user(&state, &headers) {
        Ok((id, username)) => Json(MeResponse { id, username }).into_response(),
        Err(response) => response,
    }
}

async fn api_info(State(state): State<AppState>) -> Response {
    Json(json!({
        "api_version": 2,
        "version": env!("CARGO_PKG_VERSION"),
        "public_url": state.public_url,
        "capabilities": {
            "sync_v2": true,
            "sync_events": true,
            "web_proxy": true,
            "key_vault": true,
            "vault_enrollment": true
        },
        "ssh_port": state.ssh_port,
        "ssh_username": "portal-hub",
    }))
    .into_response()
}

async fn api_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SessionsQuery>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match listed_sessions(&state.state_dir, query) {
        Ok(sessions) => {
            audit(
                &state,
                "sessions_list",
                &user_id,
                json!({"count": sessions.len()}),
            );
            Json(json!({
                "api_version": 2,
                "generated_at": Utc::now(),
                "sessions": sessions,
            }))
            .into_response()
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_session_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<Uuid>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };

    match delete_session(&state.state_dir, session_id) {
        Ok(killed) => {
            audit(
                &state,
                "session_delete",
                &user_id,
                json!({"session_id": session_id, "process_signaled": killed}),
            );
            Json(json!({
                "api_version": 2,
                "session_id": session_id,
                "deleted": true,
                "process_signaled": killed,
            }))
            .into_response()
        }
        Err(error) if error.to_string().contains("not found") => {
            json_error(StatusCode::NOT_FOUND, error)
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_sync_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match load_profile(&state, &user_id) {
        Ok(profile) => Json(json!({
            "api_version": 1,
            "generated_at": Utc::now(),
            "revision": profile.revision,
            "profile": profile.profile,
            "vault": profile.vault,
        }))
        .into_response(),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_sync_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncPutRequest>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match save_profile(&state, &user_id, request) {
        Ok(profile) => Json(json!({
            "api_version": 1,
            "generated_at": Utc::now(),
            "revision": profile.revision,
            "profile": profile.profile,
            "vault": profile.vault,
        }))
        .into_response(),
        Err(error) if error.to_string().contains("revision conflict") => {
            json_error(StatusCode::CONFLICT, error)
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_session_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Err(response) = authenticated_user(&state, &headers) {
        return response;
    }

    ws.on_upgrade(move |socket| handle_terminal_socket(state, socket))
        .into_response()
}

async fn handle_terminal_socket(state: AppState, socket: WebSocket) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let Some(Ok(WsMessage::Text(start_message))) = ws_rx.next().await else {
        let _ = ws_tx
            .send(WsMessage::Text(
                json!({"type": "error", "message": "missing terminal start request"}).to_string(),
            ))
            .await;
        return;
    };

    let start: WebTerminalStart = match serde_json::from_str(&start_message) {
        Ok(start) => start,
        Err(error) => {
            let _ = ws_tx
                .send(WsMessage::Text(
                    json!({"type": "error", "message": format!("invalid terminal start request: {}", error)})
                        .to_string(),
                ))
                .await;
            return;
        }
    };

    let mut terminal = match spawn_terminal_pty(&state, &start) {
        Ok(terminal) => terminal,
        Err(error) => {
            eprintln!("Portal Hub terminal spawn failed: {error}");
            let _ = ws_tx
                .send(WsMessage::Text(
                    json!({"type": "error", "message": error.to_string()}).to_string(),
                ))
                .await;
            return;
        }
    };

    let _ = ws_tx
        .send(WsMessage::Text(
            json!({"type": "started", "session_id": start.session_id}).to_string(),
        ))
        .await;

    loop {
        tokio::select! {
            output = terminal.output_rx.recv() => {
                let Some(output) = output else {
                    let _ = ws_tx
                        .send(WsMessage::Text(json!({"type": "closed"}).to_string()))
                        .await;
                    let _ = ws_tx.send(WsMessage::Close(None)).await;
                    break;
                };
                if ws_tx.send(WsMessage::Binary(output)).await.is_err() {
                    break;
                }
            }
            child_exit = terminal.child_exit_rx.recv() => {
                if child_exit.is_some() {
                    let _ = ws_tx
                        .send(WsMessage::Text(json!({"type": "closed"}).to_string()))
                        .await;
                    let _ = ws_tx.send(WsMessage::Close(None)).await;
                    break;
                }
            }
            message = ws_rx.next() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    Ok(WsMessage::Binary(data)) => {
                        if let Err(error) = terminal.writer.write_all(&data) {
                            let _ = ws_tx
                                .send(WsMessage::Text(
                                    json!({"type": "error", "message": format!("terminal write failed: {}", error)})
                                        .to_string(),
                                ))
                                .await;
                            break;
                        }
                    }
                    Ok(WsMessage::Text(text)) => {
                        if let Ok(WebTerminalControl::Resize { cols, rows }) =
                            serde_json::from_str::<WebTerminalControl>(&text)
                        {
                            let _ = terminal.master.resize(PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                    }
                    Ok(WsMessage::Close(_)) => break,
                    Ok(WsMessage::Ping(data)) => {
                        let _ = ws_tx.send(WsMessage::Pong(data)).await;
                    }
                    Ok(WsMessage::Pong(_)) => {}
                    Err(_) => break,
                }
            }
        }
    }

    let _ = terminal.child_killer.kill();
}

struct TerminalPty {
    master: Box<dyn portable_pty::MasterPty + Send>,
    child_killer: Box<dyn ChildKiller + Send + Sync>,
    writer: Box<dyn std::io::Write + Send>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    child_exit_rx: mpsc::Receiver<()>,
    identity_file: Option<PathBuf>,
}

fn spawn_terminal_pty(state: &AppState, start: &WebTerminalStart) -> Result<TerminalPty> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: start.rows,
            cols: start.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("failed to open terminal pty")?;

    let identity_file = write_web_identity_file(state, start.private_key.as_deref())?;
    let child = match spawn_attach_command(&*pair.slave, state, start, identity_file.as_ref(), true)
    {
        Ok(child) => child,
        Err(primary_error) => {
            eprintln!(
                "Portal Hub terminal controlling-tty spawn failed: {primary_error:#}; retrying without controlling tty"
            );
            spawn_attach_command(&*pair.slave, state, start, identity_file.as_ref(), false)
                .inspect_err(|_| {
                    if let Some(path) = &identity_file {
                        let _ = fs::remove_file(path);
                    }
                })
                .with_context(|| {
                    format!(
                        "failed to start Portal Hub terminal session after controlling-tty retry; first error: {primary_error:#}"
                    )
                })?
        }
    };
    let child_killer = child.clone_killer();
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .context("failed to read terminal pty")?;
    let writer = pair
        .master
        .take_writer()
        .context("failed to write terminal pty")?;
    let (output_tx, output_rx) = mpsc::channel(256);
    thread::spawn(move || {
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if output_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let (child_exit_tx, child_exit_rx) = mpsc::channel(1);
    thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
        let _ = child_exit_tx.blocking_send(());
    });

    Ok(TerminalPty {
        master: pair.master,
        child_killer,
        writer,
        output_rx,
        child_exit_rx,
        identity_file,
    })
}

fn spawn_attach_command(
    slave: &dyn portable_pty::SlavePty,
    state: &AppState,
    start: &WebTerminalStart,
    identity_file: Option<&PathBuf>,
    controlling_tty: bool,
) -> Result<Box<dyn portable_pty::Child + Send + Sync>> {
    let mut command =
        CommandBuilder::new(portal_hub_executable().context("failed to resolve executable")?);
    command.set_controlling_tty(controlling_tty);
    command.arg("--state-dir");
    command.arg(state.state_dir.to_string_lossy().to_string());
    command.arg("attach");
    command.arg("--session-id");
    command.arg(start.session_id.to_string());
    command.arg("--target-host");
    command.arg(start.target_host.clone());
    command.arg("--target-port");
    command.arg(start.target_port.to_string());
    command.arg("--target-user");
    command.arg(start.target_user.clone());
    command.arg("--cols");
    command.arg(start.cols.to_string());
    command.arg("--rows");
    command.arg(start.rows.to_string());
    command.arg("--interactive-auth");
    if let Some(identity_file) = identity_file {
        command.arg("--identity-file");
        command.arg(identity_file.to_string_lossy().to_string());
    }

    slave
        .spawn_command(command)
        .context("failed to start Portal Hub terminal session")
}

fn portal_hub_executable() -> Result<PathBuf> {
    let current =
        std::env::current_exe().context("failed to resolve current portal-hub executable")?;
    if current.exists() {
        return Ok(current);
    }

    if let Some(path) = current
        .to_string_lossy()
        .strip_suffix(" (deleted)")
        .map(PathBuf::from)
    {
        if path.exists() {
            return Ok(path);
        }
    }

    if let Some(argv0) = std::env::args_os().next() {
        let path = PathBuf::from(argv0);
        if path.is_absolute() && path.exists() {
            return Ok(path);
        }
        if path.components().count() > 1 {
            let absolute = std::env::current_dir()
                .context("failed to resolve current directory")?
                .join(&path);
            if absolute.exists() {
                return Ok(absolute);
            }
        }
    }

    let installed = PathBuf::from("/usr/local/bin/portal-hub");
    if installed.exists() {
        return Ok(installed);
    }

    Ok(current)
}

impl Drop for TerminalPty {
    fn drop(&mut self) {
        if let Some(path) = self.identity_file.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn write_web_identity_file(state: &AppState, private_key: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(private_key) = private_key else {
        return Ok(None);
    };
    let key_dir = state.state_dir.join("web-identities");
    fs::create_dir_all(&key_dir).context("failed to create web identity directory")?;
    let path = key_dir.join(format!("{}.key", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .context("failed to create web identity file")?;
    file.write_all(private_key.as_bytes())
        .context("failed to write web identity file")?;
    if !private_key.ends_with('\n') {
        file.write_all(b"\n")
            .context("failed to finish web identity file")?;
    }
    Ok(Some(path))
}

async fn api_sync_v2_get(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match load_sync_v2(&state, &user_id) {
        Ok(services) => Json(json!({
            "api_version": 2,
            "generated_at": Utc::now(),
            "services": services,
        }))
        .into_response(),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_sync_v2_put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SyncV2PutRequest>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match save_sync_v2(&state, &user_id, request) {
        Ok(services) => {
            broadcast_sync_revisions(&state, &user_id, &services);
            Json(json!({
                "api_version": 2,
                "generated_at": Utc::now(),
                "services": services,
            }))
            .into_response()
        }
        Err(error) if error.to_string().contains("revision conflict") => {
            json_error(StatusCode::CONFLICT, error)
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_sync_v2_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };

    let initial_services = match load_sync_v2(&state, &user_id) {
        Ok(services) => revision_map(&services),
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let initial = once(Ok::<Event, Infallible>(
        sync_event(initial_services).unwrap_or_else(|error| error_event(error.to_string())),
    ));

    let stream_user_id = user_id;
    let update_state = state.clone();
    let updates = BroadcastStream::new(state.sync_events.subscribe()).filter_map(move |event| {
        let stream_user_id = stream_user_id.clone();
        let update_state = update_state.clone();
        async move {
            match event {
                Ok(event) if event.user_id == stream_user_id => {
                    Some(Ok(sync_event(event.services)
                        .unwrap_or_else(|error| error_event(error.to_string()))))
                }
                Ok(_) => None,
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => {
                    let event = load_sync_v2(&update_state, &stream_user_id)
                        .map(|services| revision_map(&services))
                        .and_then(|revisions| sync_event(revisions).map_err(Into::into))
                        .unwrap_or_else(|error| error_event(error.to_string()));
                    Some(Ok(event))
                }
            }
        }
    });

    let stream = initial.chain(updates);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn api_vault_enrollment_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultEnrollmentCreateRequest>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match create_vault_enrollment(&state, &user_id, request) {
        Ok(enrollment) => Json(enrollment).into_response(),
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

async fn api_vault_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<VaultEnrollmentListQuery>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match list_vault_enrollments(&state, &user_id, query.status.as_deref()) {
        Ok(enrollments) => Json(json!({ "enrollments": enrollments })).into_response(),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_vault_enrollment_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match load_vault_enrollment(&state, &user_id, &id) {
        Ok(Some(enrollment)) => Json(enrollment).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            anyhow!("vault enrollment was not found"),
        ),
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn api_vault_enrollment_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<VaultEnrollmentApproveRequest>,
) -> Response {
    let (user_id, _) = match authenticated_user(&state, &headers) {
        Ok(user) => user,
        Err(response) => return response,
    };
    match approve_vault_enrollment(&state, &user_id, &id, request) {
        Ok(enrollment) => Json(enrollment).into_response(),
        Err(error) if error.to_string().contains("not found") => {
            json_error(StatusCode::NOT_FOUND, error)
        }
        Err(error) => json_error(StatusCode::BAD_REQUEST, error),
    }
}

fn listed_sessions(
    state_dir: &std::path::Path,
    query: SessionsQuery,
) -> Result<Vec<ListedSession>> {
    ensure_session_dirs(state_dir)?;
    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(sessions_dir(state_dir))? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let metadata: SessionMetadata = serde_json::from_str(&content)?;
        let active = metadata.ended_at.is_none()
            && sessions_socket_path(state_dir, metadata.session_id).exists();
        if query.active && !active {
            continue;
        }
        let (preview_base64, preview_truncated, last_output_at) = if query.include_preview {
            session_preview(state_dir, metadata.session_id, query.preview_bytes)?
        } else {
            (None, false, None)
        };
        sessions.push(ListedSession {
            metadata,
            active,
            last_output_at,
            preview_base64,
            preview_truncated,
        });
    }
    sessions.sort_by_key(|session| session.metadata.updated_at);
    sessions.reverse();
    Ok(sessions)
}

fn delete_session(state_dir: &std::path::Path, session_id: Uuid) -> Result<bool> {
    ensure_session_dirs(state_dir)?;
    let mut metadata = load_session_metadata(state_dir, session_id)?
        .with_context(|| format!("session {} not found", session_id))?;
    let socket_path = sessions_socket_path(state_dir, session_id);
    let was_active = metadata.ended_at.is_none() && socket_path.exists();

    let mut process_signaled = false;
    if was_active {
        if let Some(process_group_id) = metadata.process_group_id {
            process_signaled = signal_process_group(process_group_id)?;
            thread::sleep(Duration::from_millis(100));
        } else if let Some(process_id) = metadata.process_id {
            process_signaled = signal_process(process_id)?;
            thread::sleep(Duration::from_millis(100));
        }
        remove_file_if_exists(&socket_path)?;
    }

    let now = Utc::now();
    metadata.updated_at = now;
    metadata.ended_at = Some(now);
    metadata.process_group_id = None;
    metadata.process_id = None;
    save_session_metadata(state_dir, &metadata)?;

    Ok(process_signaled)
}

fn load_session_metadata(
    state_dir: &std::path::Path,
    session_id: Uuid,
) -> Result<Option<SessionMetadata>> {
    let path = sessions_dir(state_dir).join(format!("{}.json", session_id));
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Some(serde_json::from_str(&content)?))
}

fn save_session_metadata(state_dir: &std::path::Path, metadata: &SessionMetadata) -> Result<()> {
    let path = sessions_dir(state_dir).join(format!("{}.json", metadata.session_id));
    let temp = with_temp_extension(&path);
    std::fs::write(&temp, serde_json::to_vec_pretty(metadata)?)
        .with_context(|| format!("failed to write {}", temp.display()))?;
    std::fs::rename(&temp, &path).with_context(|| format!("failed to move {}", path.display()))?;
    Ok(())
}

fn with_temp_extension(path: &std::path::Path) -> PathBuf {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!("{ext}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    path.with_extension(extension)
}

fn signal_process_group(process_group_id: i32) -> Result<bool> {
    if process_group_id <= 0 {
        bail!("invalid session process group id {}", process_group_id);
    }
    let output = Command::new("kill")
        .arg("-TERM")
        .arg("--")
        .arg(format!("-{}", process_group_id))
        .output()
        .context("failed to signal session process group")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such process") {
            return Ok(false);
        }
        bail!(
            "failed to signal session process group {}: {}",
            process_group_id,
            stderr.trim()
        );
    }
    Ok(true)
}

fn signal_process(process_id: i32) -> Result<bool> {
    if process_id <= 0 {
        bail!("invalid session process id {}", process_id);
    }
    let output = Command::new("kill")
        .arg("-TERM")
        .arg("--")
        .arg(process_id.to_string())
        .output()
        .context("failed to signal session process")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such process") {
            return Ok(false);
        }
        bail!(
            "failed to signal session process {}: {}",
            process_id,
            stderr.trim()
        );
    }
    Ok(true)
}

fn remove_file_if_exists(path: impl AsRef<std::path::Path>) -> Result<()> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove {}", path.as_ref().display()))
        }
    }
}

fn session_preview(
    state_dir: &std::path::Path,
    session_id: Uuid,
    preview_bytes: u64,
) -> Result<(Option<String>, bool, Option<DateTime<Utc>>)> {
    let path = logs_dir(state_dir).join(format!("{}.typescript", session_id));
    if !path.exists() {
        return Ok((None, false, None));
    }
    let metadata = std::fs::metadata(&path)?;
    let modified = metadata.modified().ok().map(DateTime::<Utc>::from);
    let len = metadata.len();
    let take = preview_bytes.min(len);
    let mut file = std::fs::File::open(&path)?;
    use std::io::Seek;
    if len > take {
        file.seek(std::io::SeekFrom::Start(len - take))?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if len <= take {
        strip_script_header(&mut bytes);
    }
    Ok((Some(BASE64_STANDARD.encode(bytes)), len > take, modified))
}

fn strip_script_header(bytes: &mut Vec<u8>) {
    if !bytes.starts_with(b"Script started on ") {
        return;
    }

    if let Some(line_end) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=line_end);
    }
}

fn default_preview_bytes() -> u64 {
    512 * 1024
}

fn ensure_session_dirs(state_dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(sessions_dir(state_dir))?;
    std::fs::create_dir_all(logs_dir(state_dir))?;
    std::fs::create_dir_all(sockets_dir(state_dir))?;
    std::fs::create_dir_all(ssh_dir(state_dir))?;
    Ok(())
}

fn sessions_dir(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("sessions")
}

fn logs_dir(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("logs")
}

fn sockets_dir(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("sockets")
}

fn ssh_dir(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("ssh")
}

fn sessions_socket_path(state_dir: &std::path::Path, id: Uuid) -> PathBuf {
    sockets_dir(state_dir).join(id.to_string())
}

#[allow(clippy::result_large_err)]
fn authenticated_user(
    state: &AppState,
    headers: &HeaderMap,
) -> std::result::Result<(String, String), Response> {
    let Some(header) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing bearer token"})),
        )
            .into_response());
    };
    let Ok(value) = header.to_str() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid authorization header"})),
        )
            .into_response());
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid authorization scheme"})),
        )
            .into_response());
    };
    let hash = token_hash(token);
    let db = state.db.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "database lock failed"})),
        )
            .into_response()
    })?;
    let row = db
        .query_row(
            "SELECT users.id, users.username, access_tokens.expires_at FROM access_tokens JOIN users ON users.id = access_tokens.user_id WHERE access_tokens.token_hash = ?1",
            [&hash],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "token lookup failed"}))).into_response())?;
    let Some((user_id, username, expires_at)) = row else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid bearer token"})),
        )
            .into_response());
    };
    if DateTime::parse_from_rfc3339(&expires_at)
        .map(|date| date.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "expired bearer token"})),
        )
            .into_response());
    }
    Ok((user_id, username))
}

fn load_profile(state: &AppState, user_id: &str) -> Result<SyncState> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let row = db
        .query_row(
            "SELECT revision, profile, vault FROM profiles WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((revision, profile, vault)) = row {
        return Ok(SyncState {
            revision,
            profile: serde_json::from_str(&profile)?,
            vault: serde_json::from_str(&vault)?,
        });
    }
    Ok(SyncState {
        revision: "0".to_string(),
        profile: json!({"hosts": {"hosts": [], "groups": []}, "settings": {}, "snippets": {"snippets": []}}),
        vault: json!({"keys": []}),
    })
}

fn save_profile(state: &AppState, user_id: &str, request: SyncPutRequest) -> Result<SyncState> {
    let current = load_profile(state, user_id)?;
    if current.revision != request.expected_revision {
        bail!(
            "revision conflict: expected {}, current {}",
            request.expected_revision,
            current.revision
        );
    }
    let next = SyncState {
        revision: Uuid::new_v4().to_string(),
        profile: request.profile,
        vault: request.vault,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    db.execute(
        "INSERT INTO profiles (user_id, revision, profile, vault, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET revision = excluded.revision, profile = excluded.profile, vault = excluded.vault, updated_at = excluded.updated_at",
        params![
            user_id,
            next.revision,
            serde_json::to_string(&next.profile)?,
            serde_json::to_string(&next.vault)?,
            Utc::now().to_rfc3339()
        ],
    )?;
    audit_db(
        &db,
        "sync_put",
        Some(user_id),
        json!({"revision": next.revision, "vault_key_count": vault_key_count(&next.vault)}),
    )?;
    Ok(next)
}

fn load_sync_v2(state: &AppState, user_id: &str) -> Result<HashMap<String, SyncServiceState>> {
    let legacy = load_profile(state, user_id)?;
    let mut services = default_sync_v2_from_legacy(&legacy);
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let mut stmt = db.prepare(
        "SELECT service, revision, payload, tombstones FROM sync_services WHERE user_id = ?1",
    )?;
    let rows = stmt.query_map([user_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (service, revision, payload, tombstones) = row?;
        let state = SyncServiceState {
            revision,
            payload: serde_json::from_str(&payload)?,
            tombstones: serde_json::from_str(&tombstones)?,
        };
        services.insert(service, state);
    }
    Ok(services)
}

fn save_sync_v2(
    state: &AppState,
    user_id: &str,
    request: SyncV2PutRequest,
) -> Result<HashMap<String, SyncServiceState>> {
    validate_sync_service_names(request.services.keys())?;
    let mut services = load_sync_v2(state, user_id)?;
    for (service, put) in &request.services {
        let current = services
            .get(service)
            .cloned()
            .unwrap_or_else(|| default_service_state(service));
        if current.revision != put.expected_revision {
            bail!(
                "revision conflict for {}: expected {}, current {}",
                service,
                put.expected_revision,
                current.revision
            );
        }
    }

    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let now = Utc::now().to_rfc3339();
    for (service, put) in request.services {
        let next = SyncServiceState {
            revision: Uuid::new_v4().to_string(),
            payload: put.payload,
            tombstones: put.tombstones,
        };
        db.execute(
            "INSERT INTO sync_services (user_id, service, revision, payload, tombstones, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id, service) DO UPDATE SET
               revision = excluded.revision,
               payload = excluded.payload,
               tombstones = excluded.tombstones,
               updated_at = excluded.updated_at",
            params![
                user_id,
                service,
                next.revision,
                serde_json::to_string(&next.payload)?,
                serde_json::to_string(&next.tombstones)?,
                now,
            ],
        )?;
        services.insert(service, next);
    }

    save_legacy_profile_from_services(&db, user_id, &services)?;
    audit_db(
        &db,
        "sync_v2_put",
        Some(user_id),
        json!({"services": services.keys().cloned().collect::<Vec<_>>()}),
    )?;
    Ok(services)
}

fn create_vault_enrollment(
    state: &AppState,
    user_id: &str,
    request: VaultEnrollmentCreateRequest,
) -> Result<VaultEnrollment> {
    let device_name = request.device_name.trim();
    if device_name.is_empty() || device_name.len() > 100 {
        bail!("device_name must be between 1 and 100 characters");
    }
    if request.public_key_algorithm != "RSA-OAEP-SHA256" {
        bail!("unsupported vault enrollment public key algorithm");
    }
    BASE64_STANDARD
        .decode(request.public_key_der_base64.as_bytes())
        .context("public_key_der_base64 is not valid base64")?;

    let now = Utc::now().to_rfc3339();
    let enrollment = VaultEnrollment {
        id: Uuid::new_v4().to_string(),
        device_name: device_name.to_string(),
        public_key_algorithm: request.public_key_algorithm,
        public_key_der_base64: request.public_key_der_base64,
        status: "pending".to_string(),
        encrypted_secret_base64: None,
        created_at: now.clone(),
        updated_at: now,
        approved_at: None,
    };
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    db.execute(
        "INSERT INTO vault_enrollments
         (id, user_id, device_name, public_key_algorithm, public_key_der_base64, encrypted_secret_base64, status, created_at, updated_at, approved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, NULL)",
        params![
            enrollment.id,
            user_id,
            enrollment.device_name,
            enrollment.public_key_algorithm,
            enrollment.public_key_der_base64,
            enrollment.status,
            enrollment.created_at,
            enrollment.updated_at,
        ],
    )?;
    audit_db(
        &db,
        "vault_enrollment_create",
        Some(user_id),
        json!({"enrollment_id": enrollment.id, "device_name": enrollment.device_name}),
    )?;
    Ok(enrollment)
}

fn list_vault_enrollments(
    state: &AppState,
    user_id: &str,
    status: Option<&str>,
) -> Result<Vec<VaultEnrollment>> {
    let status = status.unwrap_or("pending");
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let mut stmt = db.prepare(
        "SELECT id, device_name, public_key_algorithm, public_key_der_base64, status,
                encrypted_secret_base64, created_at, updated_at, approved_at
         FROM vault_enrollments
         WHERE user_id = ?1 AND status = ?2
         ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map(params![user_id, status], vault_enrollment_from_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn load_vault_enrollment(
    state: &AppState,
    user_id: &str,
    id: &str,
) -> Result<Option<VaultEnrollment>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    db.query_row(
        "SELECT id, device_name, public_key_algorithm, public_key_der_base64, status,
                encrypted_secret_base64, created_at, updated_at, approved_at
         FROM vault_enrollments
         WHERE user_id = ?1 AND id = ?2",
        params![user_id, id],
        vault_enrollment_from_row,
    )
    .optional()
    .map_err(Into::into)
}

fn approve_vault_enrollment(
    state: &AppState,
    user_id: &str,
    id: &str,
    request: VaultEnrollmentApproveRequest,
) -> Result<VaultEnrollment> {
    BASE64_STANDARD
        .decode(request.encrypted_secret_base64.as_bytes())
        .context("encrypted_secret_base64 is not valid base64")?;
    let existing = load_vault_enrollment(state, user_id, id)?
        .ok_or_else(|| anyhow!("vault enrollment was not found"))?;
    if existing.status != "pending" {
        bail!("vault enrollment is already {}", existing.status);
    }

    let now = Utc::now().to_rfc3339();
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    db.execute(
        "UPDATE vault_enrollments
         SET encrypted_secret_base64 = ?1, status = 'approved', updated_at = ?2, approved_at = ?2
         WHERE user_id = ?3 AND id = ?4 AND status = 'pending'",
        params![request.encrypted_secret_base64, now, user_id, id],
    )?;
    audit_db(
        &db,
        "vault_enrollment_approve",
        Some(user_id),
        json!({"enrollment_id": id}),
    )?;
    drop(db);
    load_vault_enrollment(state, user_id, id)?
        .ok_or_else(|| anyhow!("vault enrollment was not found"))
}

fn vault_enrollment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultEnrollment> {
    Ok(VaultEnrollment {
        id: row.get(0)?,
        device_name: row.get(1)?,
        public_key_algorithm: row.get(2)?,
        public_key_der_base64: row.get(3)?,
        status: row.get(4)?,
        encrypted_secret_base64: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        approved_at: row.get(8)?,
    })
}

fn broadcast_sync_revisions(
    state: &AppState,
    user_id: &str,
    services: &HashMap<String, SyncServiceState>,
) {
    let _ = state.sync_events.send(SyncRevisionEvent {
        user_id: user_id.to_string(),
        services: revision_map(services),
    });
}

fn revision_map(services: &HashMap<String, SyncServiceState>) -> HashMap<String, String> {
    services
        .iter()
        .map(|(service, state)| (service.clone(), state.revision.clone()))
        .collect()
}

fn sync_event(services: HashMap<String, String>) -> Result<Event, serde_json::Error> {
    serde_json::to_string(&json!({
        "api_version": 2,
        "generated_at": Utc::now(),
        "services": services,
    }))
    .map(|data| Event::default().event("sync").data(data))
}

fn error_event(message: String) -> Event {
    Event::default().event("error").data(message)
}

fn default_sync_v2_from_legacy(legacy: &SyncState) -> HashMap<String, SyncServiceState> {
    let mut services = HashMap::new();
    services.insert(
        "hosts".to_string(),
        SyncServiceState {
            revision: legacy.revision.clone(),
            payload: legacy
                .profile
                .get("hosts")
                .cloned()
                .unwrap_or_else(|| json!({"hosts": [], "groups": []})),
            tombstones: default_tombstones(),
        },
    );
    services.insert(
        "settings".to_string(),
        SyncServiceState {
            revision: legacy.revision.clone(),
            payload: legacy
                .profile
                .get("settings")
                .cloned()
                .unwrap_or_else(|| json!({})),
            tombstones: default_tombstones(),
        },
    );
    services.insert(
        "snippets".to_string(),
        SyncServiceState {
            revision: legacy.revision.clone(),
            payload: legacy
                .profile
                .get("snippets")
                .cloned()
                .unwrap_or_else(|| json!({"snippets": []})),
            tombstones: default_tombstones(),
        },
    );
    services.insert(
        "vault".to_string(),
        SyncServiceState {
            revision: legacy.revision.clone(),
            payload: legacy.vault.clone(),
            tombstones: default_tombstones(),
        },
    );
    services
}

fn default_service_state(service: &str) -> SyncServiceState {
    SyncServiceState {
        revision: "0".to_string(),
        payload: match service {
            "hosts" => json!({"hosts": [], "groups": []}),
            "settings" => json!({}),
            "snippets" => json!({"snippets": []}),
            "vault" => json!({"keys": []}),
            _ => json!(null),
        },
        tombstones: default_tombstones(),
    }
}

fn save_legacy_profile_from_services(
    db: &Connection,
    user_id: &str,
    services: &HashMap<String, SyncServiceState>,
) -> Result<()> {
    let revision = Uuid::new_v4().to_string();
    let profile = json!({
        "hosts": services.get("hosts").map(|service| service.payload.clone()).unwrap_or_else(|| json!({"hosts": [], "groups": []})),
        "settings": services.get("settings").map(|service| service.payload.clone()).unwrap_or_else(|| json!({})),
        "snippets": services.get("snippets").map(|service| service.payload.clone()).unwrap_or_else(|| json!({"snippets": []})),
    });
    let vault = services
        .get("vault")
        .map(|service| service.payload.clone())
        .unwrap_or_else(|| json!({"keys": []}));
    db.execute(
        "INSERT INTO profiles (user_id, revision, profile, vault, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(user_id) DO UPDATE SET revision = excluded.revision, profile = excluded.profile, vault = excluded.vault, updated_at = excluded.updated_at",
        params![
            user_id,
            revision,
            serde_json::to_string(&profile)?,
            serde_json::to_string(&vault)?,
            Utc::now().to_rfc3339()
        ],
    )?;
    Ok(())
}

fn validate_sync_service_names<'a>(services: impl Iterator<Item = &'a String>) -> Result<()> {
    for service in services {
        if !matches!(
            service.as_str(),
            "hosts" | "settings" | "snippets" | "vault"
        ) {
            bail!("unknown sync service: {}", service);
        }
    }
    Ok(())
}

fn default_tombstones() -> Value {
    json!([])
}

fn issue_tokens(db: &Connection, user_id: &str, client_id: &str) -> Result<TokenResponse> {
    let access_token = random_token();
    let refresh_token = random_token();
    let now = Utc::now();
    let access_expires = now + ChronoDuration::hours(ACCESS_TOKEN_TTL_HOURS);
    let refresh_expires = now + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
    db.execute(
        "INSERT INTO access_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&access_token), user_id, access_expires.to_rfc3339(), now.to_rfc3339()],
    )?;
    db.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![token_hash(&refresh_token), user_id, refresh_expires.to_rfc3339(), now.to_rfc3339()],
    )?;
    audit_db(
        db,
        "token_issued",
        Some(user_id),
        json!({"client_id": client_id}),
    )?;
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_HOURS * 3600,
        refresh_token,
    })
}

fn user_count(state: &AppState) -> Result<i64> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    Ok(db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?)
}

fn validate_authorize_query(query: &AuthorizeQuery) -> Result<()> {
    if query.response_type != "code" {
        bail!("unsupported response_type");
    }
    if !is_supported_client_id(&query.client_id) {
        bail!("unknown client_id");
    }
    if query.code_challenge_method != "S256" {
        bail!("unsupported code_challenge_method");
    }
    if query.code_challenge.len() < 32 || query.state.len() < 16 {
        bail!("invalid OAuth request");
    }
    let redirect = Url::parse(&query.redirect_uri)?;
    if query.client_id == DESKTOP_CLIENT_ID {
        if redirect.scheme() != "http" {
            bail!("redirect_uri must use loopback http");
        }
        let host = redirect.host_str().unwrap_or_default();
        if host != "127.0.0.1" && host != "localhost" && host != "::1" {
            bail!("redirect_uri must be loopback");
        }
    } else if redirect.scheme() != ANDROID_REDIRECT_SCHEME
        || redirect.path() != ANDROID_REDIRECT_PATH
    {
        bail!("redirect_uri is not registered for Portal Android");
    }
    Ok(())
}

fn is_supported_client_id(client_id: &str) -> bool {
    client_id == DESKTOP_CLIENT_ID || client_id == ANDROID_CLIENT_ID
}

fn canonicalize_public_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("public_url must not be empty");
    }
    let url = Url::parse(trimmed).context("public_url must be an absolute URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("public_url must use http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("public_url must not include credentials");
    }
    let host = match url
        .host()
        .ok_or_else(|| anyhow!("public_url must include a host"))?
    {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{}]", ip),
    };
    Ok(match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    })
}

fn admin_continue_url(params: &HashMap<String, String>) -> Option<String> {
    let query = AuthorizeQuery {
        response_type: params.get("response_type")?.clone(),
        client_id: params.get("client_id")?.clone(),
        redirect_uri: params.get("redirect_uri")?.clone(),
        code_challenge: params.get("code_challenge")?.clone(),
        code_challenge_method: params.get("code_challenge_method")?.clone(),
        state: params.get("state")?.clone(),
    };
    validate_authorize_query(&query).ok()?;
    Some(authorize_path("/oauth/authorize", &query))
}

fn authorize_path(path: &str, query: &AuthorizeQuery) -> String {
    format!(
        "{}?response_type={}&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method={}&state={}",
        path,
        urlencoding::encode(&query.response_type),
        urlencoding::encode(&query.client_id),
        urlencoding::encode(&query.redirect_uri),
        urlencoding::encode(&query.code_challenge),
        urlencoding::encode(&query.code_challenge_method),
        urlencoding::encode(&query.state)
    )
}

fn continue_button_html(continue_url: &str) -> String {
    if continue_url.is_empty() {
        return String::new();
    }
    format!(
        r#"<a class="button-link" href="{}">Continue to sign in</a>"#,
        html_escape(continue_url)
    )
}

fn android_pairing_link(public_url: &str) -> String {
    format!(
        "com.digitalpals.portal.android:/pair?hub_url={}",
        urlencoding::encode(public_url)
    )
}

fn android_pairing_panel(public_url: &str) -> String {
    let link = android_pairing_link(public_url);
    let qr_svg = QrCode::new(link.as_bytes())
        .map(|code| {
            code.render::<svg::Color<'_>>()
                .min_dimensions(224, 224)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_else(|_| String::new());
    format!(
        r#"<div class="pairing-panel">
            <div class="qr-code" aria-label="Portal Android pairing QR code">{}</div>
            <div class="pairing-copy">
              <strong>Portal Android</strong>
              <p>Open this on your Android device. After sign-in, Portal Android creates a vault access request and waits for desktop approval.</p>
              <a class="button-link compact" href="{}">Open Portal Android</a>
              <code>{}</code>
            </div>
          </div>"#,
        qr_svg,
        html_escape(&link),
        html_escape(&link)
    )
}

fn validate_username(username: &str) -> Result<()> {
    let username = username.trim();
    if username.len() < 2 || username.len() > 64 {
        bail!("account name must be 2-64 characters");
    }
    if !username
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        bail!("account name may only contain letters, numbers, dots, dashes, underscores, and @");
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        bail!("password must be at least {} characters", MIN_PASSWORD_LEN);
    }
    if password.len() > 256 {
        bail!("password must be 256 characters or fewer");
    }
    Ok(())
}

fn insert_user(db: &Connection, user_id: Uuid, username: &str, password_hash: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    if user_table_has_column(db, "totp_secret")? {
        db.execute(
            "INSERT INTO users (id, username, password_hash, totp_secret, created_at) VALUES (?1, ?2, ?3, '', ?4)",
            params![user_id.to_string(), username.trim(), password_hash, now],
        )?;
    } else {
        db.execute(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user_id.to_string(), username.trim(), password_hash, now],
        )?;
    }
    Ok(())
}

fn ensure_password_hash_column(db: &Connection) -> Result<()> {
    if !user_table_has_column(db, "password_hash")? {
        db.execute(
            "ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

fn user_table_has_column(db: &Connection, name: &str) -> Result<bool> {
    let mut statement = db.prepare("PRAGMA table_info(users)")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let column_name: String = row.get(1)?;
        if column_name == name {
            return Ok(true);
        }
    }
    Ok(false)
}

fn owner_missing_password(state: &AppState) -> Result<Option<String>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow!("database lock poisoned"))?;
    let mut statement = db.prepare("SELECT username, COALESCE(password_hash, '') FROM users")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut missing = None;
    for row in rows {
        let (username, password_hash) = row?;
        if password_hash.is_empty() {
            if missing.is_some() {
                return Ok(None);
            }
            missing = Some(username);
        }
    }
    Ok(missing)
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow!("failed to hash password: {}", error))?
        .to_string())
}

fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|error| anyhow!("stored password hash is invalid: {}", error))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn token_hash(token: &str) -> String {
    hex_lower(&Sha256::digest(token.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn audit(state: &AppState, event: &str, user_id: &str, detail: Value) {
    if let Ok(db) = state.db.lock() {
        let _ = audit_db(&db, event, Some(user_id), detail);
    }
}

fn audit_db(db: &Connection, event: &str, user_id: Option<&str>, detail: Value) -> Result<()> {
    db.execute(
        "INSERT INTO audit_events (timestamp, event, user_id, detail) VALUES (?1, ?2, ?3, ?4)",
        params![
            Utc::now().to_rfc3339(),
            event,
            user_id,
            serde_json::to_string(&detail)?
        ],
    )?;
    Ok(())
}

fn vault_key_count(vault: &Value) -> usize {
    vault
        .get("keys")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to a string should not fail");
    }
    hex
}

fn json_error(status: StatusCode, error: anyhow::Error) -> Response {
    (status, Json(json!({"error": error.to_string()}))).into_response()
}

fn error_panel(error: &str) -> String {
    format!(
        r#"<section class="panel"><p class="eyebrow">Request failed</p><h1>Something needs attention.</h1><p class="lead">{}</p></section>"#,
        html_escape(error)
    )
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{title}</title>
          <style>
            :root {{
              color-scheme: dark;
              --bg: #090b10;
              --surface: #121720;
              --surface-2: #171d28;
              --line: #2a3444;
              --line-strong: #4b5b70;
              --text: #edf2f7;
              --muted: #aab7c8;
              --soft: #7f8da3;
              --accent: #63d2ff;
              --accent-2: #9be564;
              --danger: #ff8f8f;
              --shadow: rgba(0, 0, 0, 0.45);
            }}
            * {{ box-sizing: border-box; }}
            body {{
              margin: 0;
              min-height: 100vh;
              background:
                radial-gradient(circle at top left, rgba(99, 210, 255, 0.11), transparent 34rem),
                linear-gradient(145deg, #080a0f 0%, #0d1118 48%, #101620 100%);
              color: var(--text);
              font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }}
            body::before {{
              content: "";
              position: fixed;
              inset: 0;
              pointer-events: none;
              background-image: linear-gradient(rgba(255,255,255,0.035) 1px, transparent 1px);
              background-size: 100% 4px;
              opacity: 0.18;
            }}
            main {{
              width: min(1120px, calc(100vw - 32px));
              min-height: 100vh;
              margin: 0 auto;
              display: grid;
              grid-template-columns: minmax(0, 1fr) minmax(360px, 480px);
              align-items: center;
              gap: clamp(28px, 6vw, 88px);
              padding: 56px 0;
              position: relative;
            }}
            .brand {{
              min-width: 0;
            }}
            .logo {{
              margin: 0;
              color: #c7f4ff;
              font: 700 clamp(7px, 0.92vw, 12px) / 1.05 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
              white-space: pre;
              text-shadow: 0 0 26px rgba(99, 210, 255, 0.22);
            }}
            .brand-copy {{
              max-width: 520px;
              margin-top: 34px;
              color: var(--muted);
              font-size: 17px;
              line-height: 1.65;
            }}
            .shell-label {{
              display: inline-flex;
              align-items: center;
              gap: 8px;
              margin-bottom: 28px;
              color: var(--accent-2);
              font: 700 12px / 1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              letter-spacing: 0;
            }}
            .shell-label::before {{
              content: "";
              width: 8px;
              height: 8px;
              border-radius: 50%;
              background: var(--accent-2);
              box-shadow: 0 0 16px rgba(155, 229, 100, 0.7);
            }}
            .panel {{
              width: 100%;
              border: 1px solid var(--line);
              background: rgba(18, 23, 32, 0.88);
              box-shadow: 0 24px 80px var(--shadow);
              border-radius: 8px;
              padding: clamp(26px, 4vw, 38px);
              backdrop-filter: blur(18px);
            }}
            .eyebrow {{
              margin: 0 0 14px;
              color: var(--accent);
              font: 700 12px / 1.3 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            }}
            h1 {{
              margin: 0;
              font-size: clamp(31px, 4.4vw, 48px);
              line-height: 1.04;
              letter-spacing: 0;
            }}
            .lead {{
              margin: 18px 0 0;
              color: var(--muted);
              font-size: 16px;
              line-height: 1.55;
            }}
            label {{
              display: block;
              margin-top: 28px;
              color: var(--muted);
              font-weight: 700;
              font-size: 13px;
            }}
            input {{
              width: 100%;
              margin-top: 9px;
              padding: 14px 14px;
              border: 1px solid var(--line-strong);
              border-radius: 7px;
              background: #0b1017;
              color: var(--text);
              font: inherit;
              outline: none;
            }}
            input:focus {{
              border-color: var(--accent);
              box-shadow: 0 0 0 3px rgba(99, 210, 255, 0.14);
            }}
            button {{
              width: 100%;
              margin-top: 22px;
              min-height: 48px;
              border: 1px solid rgba(99, 210, 255, 0.4);
              border-radius: 7px;
              background: var(--accent);
              color: #061017;
              font: 800 15px / 1 system-ui, sans-serif;
              cursor: pointer;
            }}
            button:hover {{ filter: brightness(1.04); }}
            button:disabled {{ opacity: 0.58; cursor: wait; }}
            button.secondary {{
              background: transparent;
              border-color: var(--line-strong);
              color: var(--text);
            }}
            .button-link {{
              display: grid;
              place-items: center;
              width: 100%;
              min-height: 48px;
              margin-top: 22px;
              border: 1px solid rgba(99, 210, 255, 0.4);
              border-radius: 7px;
              background: var(--accent);
              color: #061017;
              font: 800 15px / 1 system-ui, sans-serif;
              text-decoration: none;
            }}
            .button-link:hover {{ filter: brightness(1.04); }}
            .button-link.compact {{
              min-height: 42px;
              margin-top: 14px;
              font-size: 14px;
            }}
            .pairing-panel {{
              display: grid;
              grid-template-columns: 224px minmax(0, 1fr);
              gap: 18px;
              align-items: start;
              margin-top: 26px;
              padding: 16px;
              border: 1px solid var(--line);
              border-radius: 8px;
              background: var(--surface-2);
            }}
            .qr-code {{
              display: grid;
              place-items: center;
              width: 224px;
              height: 224px;
              border-radius: 7px;
              background: #ffffff;
              overflow: hidden;
            }}
            .qr-code svg {{
              display: block;
              width: 224px;
              height: 224px;
            }}
            .pairing-copy strong {{
              display: block;
              color: var(--text);
              margin-bottom: 8px;
            }}
            .pairing-copy p {{
              margin: 0;
              color: var(--muted);
              line-height: 1.5;
            }}
            .pairing-copy code {{
              display: block;
              margin-top: 14px;
              font-size: 12px;
            }}
            .actions {{
              display: grid;
              grid-template-columns: 1fr 1fr;
              gap: 12px;
              margin-top: 6px;
            }}
            .actions button {{ margin-top: 16px; }}
            .steps {{
              display: flex;
              align-items: center;
              gap: 12px;
              margin-bottom: 28px;
            }}
            .step-dot {{
              display: grid;
              place-items: center;
              width: 30px;
              height: 30px;
              border: 1px solid var(--line-strong);
              border-radius: 50%;
              color: var(--soft);
              font: 800 12px / 1 ui-monospace, monospace;
            }}
            .step-dot.active {{
              border-color: var(--accent);
              color: var(--accent);
              box-shadow: 0 0 0 3px rgba(99, 210, 255, 0.11);
            }}
            .step-line {{
              height: 1px;
              flex: 1;
              background: var(--line);
            }}
            .security-callout {{
              display: grid;
              grid-template-columns: 42px 1fr;
              gap: 14px;
              align-items: start;
              margin-top: 24px;
              padding: 16px;
              border: 1px solid var(--line);
              border-radius: 8px;
              background: var(--surface-2);
              color: var(--muted);
            }}
            .security-callout strong {{
              display: block;
              color: var(--text);
              margin-bottom: 5px;
            }}
            .security-callout p {{ margin: 0; line-height: 1.45; }}
            .security-icon {{
              width: 42px;
              height: 42px;
              border-radius: 8px;
              border: 1px solid rgba(155, 229, 100, 0.35);
              background:
                linear-gradient(135deg, rgba(155, 229, 100, 0.2), rgba(99, 210, 255, 0.08)),
              #0c1219;
              position: relative;
            }}
            .security-icon::before {{
              content: "";
              position: absolute;
              left: 13px;
              top: 9px;
              width: 16px;
              height: 16px;
              border: 2px solid var(--accent-2);
              border-radius: 50%;
            }}
            .security-icon::after {{
              content: "";
              position: absolute;
              left: 20px;
              top: 24px;
              width: 2px;
              height: 11px;
              background: var(--accent-2);
              box-shadow: 6px 5px 0 var(--accent-2), 11px 1px 0 var(--accent-2);
            }}
            .error {{
              margin-bottom: 18px;
              padding: 12px 14px;
              border: 1px solid rgba(255, 143, 143, 0.38);
              border-radius: 7px;
              background: rgba(255, 143, 143, 0.08);
              color: var(--danger);
            }}
            code {{
              color: var(--accent-2);
              word-break: break-all;
            }}
            @media (max-width: 840px) {{
              main {{
                grid-template-columns: 1fr;
                align-items: start;
                padding: 32px 0;
              }}
              .brand-copy {{ margin-top: 20px; }}
              .panel {{ padding: 24px; }}
              .pairing-panel {{ grid-template-columns: 1fr; }}
              .qr-code {{ margin: 0 auto; }}
            }}
            @media (max-width: 480px) {{
              main {{ width: min(100vw - 24px, 1120px); }}
              .actions {{ grid-template-columns: 1fr; }}
              .logo {{ font-size: 6px; }}
            }}
          </style>
        </head>
        <body>
          <main>
            <section class="brand" aria-label="Portal Hub">
              <div class="shell-label">PORTAL HUB</div>
              <pre class="logo">{}</pre>
              <p class="brand-copy">A private command center for persistent sessions, synced SSH profiles, and encrypted key material.</p>
            </section>
            {}
          </main>
          <script>
            {}
          </script>
        </body>
        </html>"#,
        html_escape(PORTAL_ASCII_LOGO),
        body,
        password_script()
    )
}

fn password_script() -> &'static str {
    r#"
      function showError(id, message) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = message;
        node.hidden = false;
      }
      function clearError(id) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = "";
        node.hidden = true;
      }
      async function postJSON(url, body) {
        const response = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        const json = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(json.error || "Request failed");
        return json;
      }
      function setSetupStep(step) {
        document.querySelectorAll("[data-step]").forEach((node) => {
          node.hidden = node.dataset.step !== String(step);
        });
        document.querySelectorAll("[data-step-dot]").forEach((node) => {
          node.classList.toggle("active", node.dataset.stepDot === String(step));
        });
      }
      function ownerSetupSuccessHTML(continueUrl) {
        const lead = continueUrl
          ? "Continue to sign in with the password you just created."
          : "Return to Portal and sign in to Portal Hub.";
        const action = continueUrl
          ? `<a class="button-link" href="${continueUrl}">Continue to sign in</a>`
          : "";
        return `<p class="eyebrow">Owner ready</p><h1>Password saved.</h1><p class="lead">${lead}</p>${action}`;
      }
      function initOwnerWizard() {
        const form = document.getElementById("owner-form");
        const username = document.getElementById("username");
        const password = document.getElementById("password");
        const confirmation = document.getElementById("password-confirm");
        const next = document.getElementById("next-button");
        const back = document.getElementById("back-button");
        const submit = document.getElementById("create-button");
        if (!form || !username || !password || !confirmation || !submit) return;
        if (next && back) {
          next.addEventListener("click", () => {
            clearError("setup-error");
            if (!username.reportValidity()) return;
            setSetupStep(2);
            password.focus();
          });
          back.addEventListener("click", () => {
            clearError("setup-error");
            setSetupStep(1);
            username.focus();
          });
        }
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          clearError("setup-error");
          if (!username.reportValidity() || !password.reportValidity() || !confirmation.reportValidity()) return;
          if (password.value !== confirmation.value) {
            showError("setup-error", "Passwords do not match");
            confirmation.focus();
            return;
          }
          submit.disabled = true;
          const originalText = submit.textContent;
          submit.textContent = "Saving...";
          try {
            await postJSON("/auth/register", { username: username.value, password: password.value });
            document.querySelector(".setup-panel").innerHTML =
              ownerSetupSuccessHTML(form.dataset.continueUrl || "");
          } catch (error) {
            showError("setup-error", error.message || String(error));
          } finally {
            submit.disabled = false;
            submit.textContent = originalText;
          }
        });
      }
      function initPasswordLogin() {
        const form = document.getElementById("login-form");
        const username = document.getElementById("username");
        const password = document.getElementById("password");
        const submit = document.getElementById("login-button");
        if (!form || !username || !password || !submit) return;
        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          clearError("login-error");
          if (!username.reportValidity() || !password.reportValidity()) return;
          submit.disabled = true;
          const originalText = submit.textContent;
          submit.textContent = "Signing in...";
          try {
            const oauth = Object.fromEntries(new URLSearchParams(window.location.search).entries());
            const finish = await postJSON("/auth/login", { username: username.value, password: password.value, oauth });
            window.location.assign(finish.redirect_uri);
          } catch (error) {
            showError("login-error", error.message || String(error));
          } finally {
            submit.disabled = false;
            submit.textContent = originalText;
          }
        });
      }
      if (document.getElementById("owner-form")) {
        initOwnerWizard();
      }
      if (document.getElementById("login-form")) {
        initPasswordLogin();
      }
    "#
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        let db = Connection::open_in_memory().unwrap();
        init_db(&db).unwrap();
        let (sync_events, _) = broadcast::channel(16);
        AppState {
            db: Arc::new(Mutex::new(db)),
            state_dir: std::env::temp_dir().join(format!("portal-hub-test-{}", Uuid::new_v4())),
            public_url: "http://portal-hub.localhost:8080".to_string(),
            ssh_port: 2222,
            sync_events,
        }
    }

    fn test_oauth() -> AuthorizeQuery {
        AuthorizeQuery {
            response_type: "code".to_string(),
            client_id: DESKTOP_CLIENT_ID.to_string(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            code_challenge: "abcdefghijklmnopqrstuvwxyz123456".to_string(),
            code_challenge_method: "S256".to_string(),
            state: "state-state-state".to_string(),
        }
    }

    #[test]
    fn password_hash_verifies_only_original_password() {
        let hash = hash_password("correct horse battery staple").unwrap();

        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong horse battery staple", &hash).unwrap());
    }

    #[test]
    fn password_login_issues_oauth_redirect() {
        let state = test_state();
        register_inner(
            &state,
            RegisterRequest {
                username: "owner".to_string(),
                password: "correct horse battery staple".to_string(),
            },
        )
        .unwrap();

        let response = login_inner(
            &state,
            LoginRequest {
                username: "owner".to_string(),
                password: "correct horse battery staple".to_string(),
                oauth: test_oauth(),
            },
        )
        .unwrap();

        assert!(
            response
                .redirect_uri
                .starts_with("http://127.0.0.1:49152/callback?code=")
        );
        assert!(response.redirect_uri.contains("&state=state-state-state"));
    }

    #[test]
    fn android_oauth_redirect_is_accepted() {
        let mut query = test_oauth();
        query.client_id = ANDROID_CLIENT_ID.to_string();
        query.redirect_uri = format!("{ANDROID_REDIRECT_SCHEME}:{ANDROID_REDIRECT_PATH}");

        validate_authorize_query(&query).unwrap();
    }

    #[test]
    fn android_pairing_link_encodes_hub_url() {
        let link = android_pairing_link("https://portal-hub.example.ts.net:8080");

        assert_eq!(
            link,
            "com.digitalpals.portal.android:/pair?hub_url=https%3A%2F%2Fportal-hub.example.ts.net%3A8080"
        );
    }

    #[test]
    fn android_vault_pairing_flow_smoke() {
        let state = test_state();
        register_inner(
            &state,
            RegisterRequest {
                username: "owner".to_string(),
                password: "correct horse battery staple".to_string(),
            },
        )
        .unwrap();
        let user_id: String = state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT id FROM users WHERE username = 'owner'", [], |row| {
                row.get(0)
            })
            .unwrap();

        let pairing_link = android_pairing_link(&state.public_url);
        assert!(pairing_link.starts_with("com.digitalpals.portal.android:/pair?hub_url="));

        let enrollment = create_vault_enrollment(
            &state,
            &user_id,
            VaultEnrollmentCreateRequest {
                device_name: "Pixel Smoke Test".to_string(),
                public_key_algorithm: "RSA-OAEP-SHA256".to_string(),
                public_key_der_base64: BASE64_STANDARD.encode(b"public-key-der"),
            },
        )
        .unwrap();
        assert_eq!(enrollment.status, "pending");
        assert!(enrollment.encrypted_secret_base64.is_none());

        let pending = list_vault_enrollments(&state, &user_id, Some("pending")).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, enrollment.id);

        let approved = approve_vault_enrollment(
            &state,
            &user_id,
            &enrollment.id,
            VaultEnrollmentApproveRequest {
                encrypted_secret_base64: BASE64_STANDARD.encode(b"encrypted-vault-secret"),
            },
        )
        .unwrap();
        assert_eq!(approved.status, "approved");
        assert_eq!(
            approved.encrypted_secret_base64.as_deref(),
            Some(BASE64_STANDARD.encode(b"encrypted-vault-secret").as_str())
        );
        assert!(approved.approved_at.is_some());

        assert!(
            list_vault_enrollments(&state, &user_id, Some("pending"))
                .unwrap()
                .is_empty()
        );
        let loaded = load_vault_enrollment(&state, &user_id, &enrollment.id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.status, "approved");
    }

    #[test]
    fn android_oauth_rejects_loopback_redirect() {
        let mut query = test_oauth();
        query.client_id = ANDROID_CLIENT_ID.to_string();

        let error = validate_authorize_query(&query).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("redirect_uri is not registered for Portal Android")
        );
    }

    #[test]
    fn admin_continue_url_preserves_valid_oauth_query() {
        let query = test_oauth();
        let params = HashMap::from([
            ("response_type".to_string(), query.response_type),
            ("client_id".to_string(), query.client_id),
            ("redirect_uri".to_string(), query.redirect_uri),
            ("code_challenge".to_string(), query.code_challenge),
            (
                "code_challenge_method".to_string(),
                query.code_challenge_method,
            ),
            ("state".to_string(), query.state),
        ]);

        let continue_url = admin_continue_url(&params).unwrap();

        assert!(continue_url.starts_with("/oauth/authorize?"));
        assert!(continue_url.contains("client_id=portal-desktop"));
        assert!(continue_url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback"));
    }

    #[test]
    fn public_url_is_canonicalized_to_origin() {
        assert_eq!(
            canonicalize_public_url("https://portal-hub.example.ts.net/").unwrap(),
            "https://portal-hub.example.ts.net"
        );
        assert_eq!(
            canonicalize_public_url("https://portal-hub.example.ts.net:8443/path?x=1").unwrap(),
            "https://portal-hub.example.ts.net:8443"
        );
    }

    #[test]
    fn public_url_rejects_non_http_urls() {
        assert!(canonicalize_public_url("portal-hub.example.ts.net").is_err());
        assert!(canonicalize_public_url("ssh://portal-hub.example.ts.net").is_err());
    }

    #[test]
    fn session_preview_strips_script_recorder_header() {
        let state_dir = std::env::temp_dir().join(format!("portal-hub-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(logs_dir(&state_dir)).unwrap();
        let session_id = Uuid::new_v4();
        std::fs::write(
            logs_dir(&state_dir).join(format!("{}.typescript", session_id)),
            b"Script started on 2026-04-27 14:29:29+00:00 [COMMAND=\"ssh host\"]\nreal motd\n",
        )
        .unwrap();

        let (preview_base64, truncated, _) = session_preview(&state_dir, session_id, 1024).unwrap();
        let preview = BASE64_STANDARD.decode(preview_base64.unwrap()).unwrap();
        let _ = std::fs::remove_dir_all(&state_dir);

        assert!(!truncated);
        assert_eq!(preview, b"real motd\n");
    }

    #[test]
    fn delete_session_marks_metadata_ended_and_removes_socket() {
        let state_dir = std::env::temp_dir().join(format!("portal-hub-test-{}", Uuid::new_v4()));
        ensure_session_dirs(&state_dir).unwrap();
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let metadata = SessionMetadata {
            schema_version: 1,
            session_id,
            session_name: format!("portal-{}", session_id),
            target_host: "example.internal".to_string(),
            target_port: 22,
            target_user: "john".to_string(),
            created_at: now,
            updated_at: now,
            ended_at: None,
            process_group_id: None,
            process_id: None,
        };
        save_session_metadata(&state_dir, &metadata).unwrap();
        std::fs::write(sessions_socket_path(&state_dir, session_id), b"").unwrap();

        let signaled = delete_session(&state_dir, session_id).unwrap();
        let metadata = load_session_metadata(&state_dir, session_id)
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&state_dir);

        assert!(!signaled);
        assert!(metadata.ended_at.is_some());
        assert!(metadata.process_group_id.is_none());
        assert!(metadata.process_id.is_none());
        assert!(!sessions_socket_path(&state_dir, session_id).exists());
    }

    #[test]
    fn owner_registration_supports_legacy_totp_column() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        init_db(&db).unwrap();
        let (sync_events, _) = broadcast::channel(16);
        let state = AppState {
            db: Arc::new(Mutex::new(db)),
            state_dir: std::env::temp_dir().join(format!("portal-hub-test-{}", Uuid::new_v4())),
            public_url: "http://portal-hub.localhost:8080".to_string(),
            ssh_port: 2222,
            sync_events,
        };

        register_inner(
            &state,
            RegisterRequest {
                username: "owner".to_string(),
                password: "correct horse battery staple".to_string(),
            },
        )
        .unwrap();

        let db = state.db.lock().unwrap();
        let (password_hash, totp_secret): (String, String) = db
            .query_row(
                "SELECT password_hash, totp_secret FROM users WHERE username = 'owner'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!password_hash.is_empty());
        assert!(totp_secret.is_empty());
    }

    #[test]
    fn sync_v2_defaults_to_service_payloads() {
        let state = test_state();
        let services = load_sync_v2(&state, "user-1").unwrap();

        assert_eq!(services.get("hosts").unwrap().revision, "0");
        assert!(
            services
                .get("hosts")
                .unwrap()
                .payload
                .get("hosts")
                .is_some()
        );
        assert!(services.get("settings").unwrap().payload.is_object());
        assert!(
            services
                .get("snippets")
                .unwrap()
                .payload
                .get("snippets")
                .is_some()
        );
        assert!(services.get("vault").unwrap().payload.get("keys").is_some());
    }

    #[test]
    fn sync_v2_updates_one_service_and_rejects_stale_revision() {
        let state = test_state();
        let mut services = HashMap::new();
        services.insert(
            "hosts".to_string(),
            SyncV2ServicePut {
                expected_revision: "0".to_string(),
                payload: json!({"hosts": [{"id": "host-1"}], "groups": []}),
                tombstones: json!([]),
            },
        );

        let updated = save_sync_v2(&state, "user-1", SyncV2PutRequest { services }).unwrap();
        let revision = updated.get("hosts").unwrap().revision.clone();
        assert_ne!(revision, "0");

        let mut stale = HashMap::new();
        stale.insert(
            "hosts".to_string(),
            SyncV2ServicePut {
                expected_revision: "0".to_string(),
                payload: json!({"hosts": [], "groups": []}),
                tombstones: json!([]),
            },
        );
        let error = save_sync_v2(&state, "user-1", SyncV2PutRequest { services: stale })
            .unwrap_err()
            .to_string();
        assert!(error.contains("revision conflict for hosts"));
    }

    #[test]
    fn sync_revision_map_contains_service_revisions_only() {
        let mut services = HashMap::new();
        services.insert(
            "hosts".to_string(),
            SyncServiceState {
                revision: "rev-hosts".to_string(),
                payload: json!({"hosts": []}),
                tombstones: json!([]),
            },
        );

        let revisions = revision_map(&services);

        assert_eq!(revisions.get("hosts"), Some(&"rev-hosts".to_string()));
        assert_eq!(revisions.len(), 1);
    }

    #[test]
    fn sync_event_serializes_revision_payload() {
        let mut revisions = HashMap::new();
        revisions.insert("settings".to_string(), "rev-settings".to_string());

        let event = sync_event(revisions).unwrap();
        let debug = format!("{:?}", event);

        assert!(debug.contains("sync"));
        assert!(debug.contains("rev-settings"));
    }
}
