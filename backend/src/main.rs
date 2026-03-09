use axum::{
    extract::{ConnectInfo, Path, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use governor::{DefaultKeyedRateLimiter, Quota};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tokio::fs;
use tower_http::cors::{Any, CorsLayer};

type Db = Arc<Mutex<Connection>>;
type Limiter = Arc<DefaultKeyedRateLimiter<IpAddr>>;

#[derive(Clone)]
struct AppState {
    db: Db,
    limiter: Limiter,
}

// ─── Models ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct AsymRecord {
    id: String,
    serial: String,
    public_text: String,
    secret_text: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateAsymRecord {
    serial: String,
    public_text: String,
    secret_text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SymRecord {
    id: String,
    serial: String,
    public_text: String,
    encrypted_sym_key: String,
    encrypted_secret: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateSymRecord {
    serial: String,
    public_text: String,
    encrypted_sym_key: String,
    encrypted_secret: String,
}

#[derive(Debug, Deserialize)]
struct UpdateSymRecord {
    encrypted_secret: String,
}

// ─── Database ──────────────────────────────────────────────────────────────

fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS asym_records (
            id          TEXT PRIMARY KEY,
            serial      TEXT NOT NULL,
            public_text TEXT NOT NULL,
            secret_text TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sym_records (
            id                TEXT PRIMARY KEY,
            serial            TEXT NOT NULL,
            public_text       TEXT NOT NULL,
            encrypted_sym_key TEXT NOT NULL,
            encrypted_secret  TEXT NOT NULL,
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        );",
    )
}

// ─── Middleware ─────────────────────────────────────────────────────────────

async fn rate_limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));

    match state.limiter.check_key(&ip) {
        Ok(_) => next.run(req).await,
        Err(_) => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response(),
    }
}

// ─── Key handlers ──────────────────────────────────────────────────────────

async fn serve_key(path: &str) -> Response {
    match fs::read_to_string(path).await {
        Ok(content) => (StatusCode::OK, content).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "Key file not found — run setup_keys.sh first",
        )
            .into_response(),
    }
}

async fn get_asym_public_key() -> Response {
    serve_key("../keys/asym/server_public.pem").await
}
async fn get_asym_private_key() -> Response {
    serve_key("../keys/asym/server_private.pem").await
}
async fn get_sym_party_a_public_key() -> Response {
    serve_key("../keys/sym/partyA_public.pem").await
}
async fn get_sym_party_a_private_key() -> Response {
    serve_key("../keys/sym/partyA_private.pem").await
}
async fn get_sym_party_b_public_key() -> Response {
    serve_key("../keys/sym/partyB_public.pem").await
}
async fn get_sym_party_b_private_key() -> Response {
    serve_key("../keys/sym/partyB_private.pem").await
}
async fn get_sym_key_for_a() -> Response {
    serve_key("../keys/sym/sym_key_encrypted_for_A.b64").await
}

// ─── Asymmetric handlers ───────────────────────────────────────────────────

async fn create_asym_record(
    State(state): State<AppState>,
    Json(body): Json<CreateAsymRecord>,
) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let db = state.db.lock().unwrap();
    match db.execute(
        "INSERT INTO asym_records (id, serial, public_text, secret_text, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, body.serial, body.public_text, body.secret_text, now],
    ) {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_asym_records(State(state): State<AppState>) -> Response {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id, serial, public_text, secret_text, created_at
             FROM asym_records ORDER BY created_at DESC",
        )
        .unwrap();
    let records: Vec<AsymRecord> = stmt
        .query_map([], |row| {
            Ok(AsymRecord {
                id: row.get(0)?,
                serial: row.get(1)?,
                public_text: row.get(2)?,
                secret_text: row.get(3)?,
                created_at: row.get(4)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    Json(records).into_response()
}

async fn get_asym_record(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().unwrap();
    match db.query_row(
        "SELECT id, serial, public_text, secret_text, created_at
         FROM asym_records WHERE id = ?1",
        params![id],
        |row| {
            Ok(AsymRecord {
                id: row.get(0)?,
                serial: row.get(1)?,
                public_text: row.get(2)?,
                secret_text: row.get(3)?,
                created_at: row.get(4)?,
            })
        },
    ) {
        Ok(r) => Json(r).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Record not found").into_response(),
    }
}

// ─── Symmetric handlers ────────────────────────────────────────────────────

async fn create_sym_record(
    State(state): State<AppState>,
    Json(body): Json<CreateSymRecord>,
) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let db = state.db.lock().unwrap();
    match db.execute(
        "INSERT INTO sym_records (id, serial, public_text, encrypted_sym_key, encrypted_secret, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![id, body.serial, body.public_text, body.encrypted_sym_key, body.encrypted_secret, now],
    ) {
        Ok(_) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_sym_records(State(state): State<AppState>) -> Response {
    let db = state.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id, serial, public_text, encrypted_sym_key, encrypted_secret, created_at, updated_at
             FROM sym_records ORDER BY created_at DESC",
        )
        .unwrap();
    let records: Vec<SymRecord> = stmt
        .query_map([], |row| {
            Ok(SymRecord {
                id: row.get(0)?,
                serial: row.get(1)?,
                public_text: row.get(2)?,
                encrypted_sym_key: row.get(3)?,
                encrypted_secret: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    Json(records).into_response()
}

async fn get_sym_record(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().unwrap();
    match db.query_row(
        "SELECT id, serial, public_text, encrypted_sym_key, encrypted_secret, created_at, updated_at
         FROM sym_records WHERE id = ?1",
        params![id],
        |row| {
            Ok(SymRecord {
                id: row.get(0)?,
                serial: row.get(1)?,
                public_text: row.get(2)?,
                encrypted_sym_key: row.get(3)?,
                encrypted_secret: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        },
    ) {
        Ok(r) => Json(r).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Record not found").into_response(),
    }
}

async fn update_sym_record(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateSymRecord>,
) -> Response {
    let now = chrono::Utc::now().to_rfc3339();
    let db = state.db.lock().unwrap();
    match db.execute(
        "UPDATE sym_records SET encrypted_secret = ?1, updated_at = ?2 WHERE id = ?3",
        params![body.encrypted_secret, now, id],
    ) {
        Ok(n) if n > 0 => StatusCode::OK.into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, "Record not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ─── Main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let conn = Connection::open("poc.db").expect("Failed to open SQLite database");
    init_db(&conn).expect("Failed to initialise database schema");
    let db: Db = Arc::new(Mutex::new(conn));

    let quota = Quota::per_minute(NonZeroU32::new(120).unwrap());
    let limiter: Limiter = Arc::new(governor::RateLimiter::keyed(quota));

    let state = AppState { db, limiter };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        // ── Asymmetric key & record routes ──
        .route("/api/asym/public-key", get(get_asym_public_key))
        .route("/api/asym/private-key", get(get_asym_private_key))
        .route(
            "/api/asym/records",
            post(create_asym_record).get(list_asym_records),
        )
        .route("/api/asym/records/:id", get(get_asym_record))
        // ── Symmetric key & record routes ──
        .route("/api/sym/partyA/public-key", get(get_sym_party_a_public_key))
        .route("/api/sym/partyA/private-key", get(get_sym_party_a_private_key))
        .route("/api/sym/partyB/public-key", get(get_sym_party_b_public_key))
        .route("/api/sym/partyB/private-key", get(get_sym_party_b_private_key))
        .route("/api/sym/sym-key-for-A", get(get_sym_key_for_a))
        .route(
            "/api/sym/records",
            post(create_sym_record).get(list_sym_records),
        )
        .route(
            "/api/sym/records/:id",
            get(get_sym_record).put(update_sym_record),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit,
        ))
        .layer(cors)
        .with_state(state)
        .fallback_service(tower_http::services::ServeDir::new("../frontend"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server running → http://{}", addr);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  CryptoJS PoC  →  http://localhost:3000");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
