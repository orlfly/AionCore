//! Black-box integration tests for the Kaneo credential HTTP surface.
//!
//! Tests exercise the HTTP layer (request → handler → response) via
//! `tower::ServiceExt::oneshot`, without authentication middleware.
//! Auth protection is verified at the app-level E2E tests.
//!
//! Contract: metadata-only reads, one-shot plaintext writes (encrypted at
//! rest), rotation in place, deletion, input validation, and the reserved
//! `kaneo-credential:*` preference namespace guard.

use std::sync::Arc;

use aionui_realtime::BroadcastEventBus;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use aionui_auth::CurrentUser;
use aionui_db::{
    SqliteClientPreferenceRepository, SqliteFeedbackDiagnosticsRepository, SqliteProviderRepository,
    SqliteSettingsRepository, UserStatus, UserType, init_database_memory,
};
use aionui_system::{
    ClientPrefService, FeedbackDiagnosticsService, KaneoCredentialService, ModelFetchService,
    ProtocolDetectionService, ProviderService, RuntimePrepareService, SettingsService, SystemRouterState,
    VersionCheckService, system_routes,
};

const TEST_ENCRYPTION_KEY: [u8; 32] = [0x42; 32];
const TEST_USER_ID: &str = "user-1";
const CONTEXT_ID: &str = "kctx-abc";
const PLAINTEXT_KEY: &str = "kaneo-secret-key";

fn build_state(db: &aionui_db::Database) -> SystemRouterState {
    let provider_repo = Arc::new(SqliteProviderRepository::new(db.pool().clone()));
    let http_client = reqwest::Client::new();
    SystemRouterState {
        settings_service: SettingsService::new(Arc::new(SqliteSettingsRepository::new(db.pool().clone()))),
        client_pref_service: ClientPrefService::new(Arc::new(SqliteClientPreferenceRepository::new(
            db.pool().clone(),
        ))),
        provider_service: ProviderService::new(provider_repo.clone(), TEST_ENCRYPTION_KEY),
        model_fetch_service: ModelFetchService::new(provider_repo, TEST_ENCRYPTION_KEY, http_client.clone()),
        protocol_detection_service: ProtocolDetectionService::new(http_client.clone()),
        version_check_service: VersionCheckService::new(http_client, "0.1.0".to_owned()),
        runtime_prepare_service: RuntimePrepareService::new(Arc::new(BroadcastEventBus::new(16))),
        feedback_diagnostics_service: FeedbackDiagnosticsService::new(Arc::new(
            SqliteFeedbackDiagnosticsRepository::new(db.pool().clone()),
        )),
        kaneo_credential_service: KaneoCredentialService::new(
            Arc::new(SqliteClientPreferenceRepository::new(db.pool().clone())),
            TEST_ENCRYPTION_KEY,
        ),
    }
}

async fn setup() -> axum::Router {
    let db = init_database_memory().await.unwrap();
    sqlx::query(
        "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
         VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
    )
    .bind(TEST_USER_ID)
    .bind(TEST_USER_ID)
    .execute(db.pool())
    .await
    .unwrap();
    system_routes(build_state(&db))
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn request_for_user(user_id: &str, method: &str, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let mut req = builder
        .body(Body::from(
            body.map(|v| serde_json::to_vec(&v).unwrap()).unwrap_or_default(),
        ))
        .unwrap();
    req.extensions_mut().insert(CurrentUser {
        id: user_id.to_owned(),
        username: user_id.to_owned(),
        user_type: UserType::Local,
        status: UserStatus::Active,
    });
    req
}

fn upsert_body(api_key: &str) -> serde_json::Value {
    serde_json::json!({
        "base_url": "http://localhost:1337",
        "agent_role": "coding",
        "project_id": "proj-1",
        "key_expires_at": "2026-10-01T00:00:00.000Z",
        "api_key": api_key
    })
}

#[tokio::test]
async fn put_then_get_returns_metadata_without_key() {
    let app = setup().await;
    let response = app
        .clone()
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            Some(upsert_body(PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["success"], true, "raw body: {}", String::from_utf8_lossy(&bytes));
    let meta = &parsed["data"];
    assert_eq!(meta["context_id"], CONTEXT_ID, "raw body: {}", String::from_utf8_lossy(&bytes));
    assert_eq!(meta["base_url"], "http://localhost:1337");
    assert_eq!(meta["agent_role"], "coding");
    assert_eq!(meta["project_id"], "proj-1");
    assert_eq!(meta["key_expires_at"], "2026-10-01T00:00:00.000Z");
    // Neither the metadata nor the body may carry key material.
    assert!(!bytes.windows(PLAINTEXT_KEY.len()).any(|w| w == PLAINTEXT_KEY.as_bytes()));

    let response = app
        .oneshot(request_for_user(
            TEST_USER_ID,
            "GET",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["data"]["context_id"], CONTEXT_ID);
    assert!(
        !bytes.windows(PLAINTEXT_KEY.len()).any(|w| w == PLAINTEXT_KEY.as_bytes()),
        "GET must not echo key material: {}",
        String::from_utf8_lossy(&bytes)
    );
}

#[tokio::test]
async fn get_unknown_context_is_404() {
    let app = setup().await;
    let response = app
        .oneshot(request_for_user(TEST_USER_ID, "GET", "/api/kaneo-credentials/kctx-none", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_only_returns_kaneo_credential_rows() {
    let app = setup().await;
    // Foreign preference row coexisting in the same table.
    let response = app
        .clone()
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            "/api/settings/client",
            Some(serde_json::json!({ "mcp.config": [] })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            Some(upsert_body(PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(request_for_user(TEST_USER_ID, "GET", "/api/kaneo-credentials", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let list = parsed["data"].as_array().unwrap();
    assert_eq!(list.len(), 1, "foreign preference rows must be filtered out");
    assert_eq!(list[0]["context_id"], CONTEXT_ID);
    assert!(!bytes.windows(PLAINTEXT_KEY.len()).any(|w| w == PLAINTEXT_KEY.as_bytes()));
}

#[tokio::test]
async fn rotate_replaces_in_place() {
    let app = setup().await;
    for key in [PLAINTEXT_KEY, "kaneo-rotated-key"] {
        let response = app
            .clone()
            .oneshot(request_for_user(
                TEST_USER_ID,
                "PUT",
                &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
                Some(upsert_body(key)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let parsed = body_json(response).await;
        assert_eq!(parsed["data"]["context_id"], CONTEXT_ID);
    }
    // Exactly one stored row: the second PUT replaced the first.
    let response = app
        .oneshot(request_for_user(TEST_USER_ID, "GET", "/api/kaneo-credentials", None))
        .await
        .unwrap();
    let parsed = body_json(response).await;
    assert_eq!(parsed["data"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn delete_removes_stored_credential() {
    let app = setup().await;
    let response = app
        .clone()
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            Some(upsert_body(PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(request_for_user(
            TEST_USER_ID,
            "DELETE",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let parsed = body_json(response).await;
    assert_eq!(parsed["data"], true);

    let response = app
        .oneshot(request_for_user(
            TEST_USER_ID,
            "GET",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_context_id_rejected() {
    let app = setup().await;
    let response = app
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            "/api/kaneo-credentials/bad%2Fslash",
            Some(upsert_body(PLAINTEXT_KEY)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn blank_api_key_rejected() {
    let app = setup().await;
    let response = app
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            &format!("/api/kaneo-credentials/{CONTEXT_ID}"),
            Some(upsert_body("   ")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reserved_preference_prefix_rejected() {
    let app = setup().await;
    let response = app
        .oneshot(request_for_user(
            TEST_USER_ID,
            "PUT",
            "/api/settings/client",
            Some(serde_json::json!({ "kaneo-credential:evil": "x" })),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}