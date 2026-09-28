//! Kaneo credential storage — AES-256-GCM at rest, addressed by context id.
//!
//! One Kaneo context (= one imported (baseUrl, projectId, role) binding) may
//! store exactly one API key. The ciphertext is encrypted with the same
//! storage-encryption root as provider keys (`aionui_common::encrypt_string`),
//! so a database leak never exposes Kaneo keys. Non-secret metadata (base
//! URL, role, project id, expiry) is stored alongside the ciphertext so
//! clients can bookkeep and render expiry warnings without decryption.
//!
//! Storage rides the generic `client_preferences` table: the key namespace
//! `kaneo-credential:<contextId>` is reserved for this service (clients
//! writing that prefix through the ordinary preferences API are rejected).
//! The stored JSON value carries the ciphertext plus a version tag so the
//! format can evolve without a schema migration.
//!
//! Responses NEVER carry key material. The only plaintext consumer is
//! [`KaneoCredentialService::resolve`], used server-side (session MCP env
//! injection) and never serialized to a client.

use std::sync::Arc;

use aionui_api_types::{KaneoCredentialMetaResponse, UpsertKaneoCredentialRequest};
use aionui_common::{decrypt_string, encrypt_string, now_ms};
use aionui_db::IClientPreferenceRepository;
use serde::{Deserialize, Serialize};

use crate::error::SystemError;

/// Reserved `client_preferences` key prefix. Everything under it belongs to
/// the credential store and must not be written via the generic preferences
/// endpoint.
pub const KANEO_CREDENTIAL_KEY_PREFIX: &str = "kaneo-credential:";

/// Payload schema version (bump when the stored shape changes).
const PAYLOAD_VERSION: i64 = 1;

/// Maximum accepted context id length (keeps the full preference key within
/// the preferences store's 255-character cap).
const MAX_CONTEXT_ID_LENGTH: usize = 200;

/// Serialized credential payload (JSON) inside a `client_preferences` row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredKaneoCredential {
    v: i64,
    /// AES-256-GCM ciphertext (base64), encrypted with the storage root.
    ciphertext: String,
    /// Kaneo instance base URL (plaintext metadata).
    base_url: String,
    /// Agent role bound to the key (plaintext metadata).
    agent_role: String,
    /// Bound project id, or `null` for an unbound (legacy) key.
    #[serde(default)]
    project_id: Option<String>,
    /// Key expiry as reported by Kaneo (ISO string), or `null` when none.
    #[serde(default)]
    key_expires_at: Option<String>,
    /// Epoch-ms write timestamp.
    updated_at: i64,
}

/// Business logic for Kaneo credential storage.
#[derive(Clone)]
pub struct KaneoCredentialService {
    repo: Arc<dyn IClientPreferenceRepository>,
    encryption_key: [u8; 32],
}

impl KaneoCredentialService {
    pub fn new(repo: Arc<dyn IClientPreferenceRepository>, encryption_key: [u8; 32]) -> Self {
        Self { repo, encryption_key }
    }

    /// Store or rotate the key for one context (idempotent upsert; rotation
    /// replaces the ciphertext in place, never adds a second row).
    pub async fn upsert(
        &self,
        user_id: &str,
        context_id: &str,
        req: UpsertKaneoCredentialRequest,
    ) -> Result<KaneoCredentialMetaResponse, SystemError> {
        validate_context_id(context_id)?;
        validate_not_blank(&req.base_url, "base_url")?;
        validate_not_blank(&req.agent_role, "agent_role")?;
        validate_not_blank(&req.api_key, "api_key")?;

        let ciphertext = encrypt_string(&req.api_key, &self.encryption_key)
            .map_err(|e| SystemError::Internal(format!("kaneo credential encryption failed: {e}")))?;
        let payload = StoredKaneoCredential {
            v: PAYLOAD_VERSION,
            ciphertext,
            base_url: req.base_url,
            agent_role: req.agent_role,
            project_id: req.project_id,
            key_expires_at: req.key_expires_at,
            updated_at: now_ms(),
        };
        let value = serde_json::to_string(&payload)
            .map_err(|e| SystemError::Internal(format!("failed to serialize kaneo credential: {e}")))?;
        self.repo
            .upsert_batch(user_id, &[(preference_key(context_id).as_str(), value.as_str())])
            .await
            .map_err(|e| SystemError::Internal(format!("failed to store kaneo credential: {e}")))?;
        Ok(self.meta_response(context_id, payload))
    }

    /// Metadata for one stored credential, or `None` when absent.
    pub async fn get(
        &self,
        user_id: &str,
        context_id: &str,
    ) -> Result<Option<KaneoCredentialMetaResponse>, SystemError> {
        validate_context_id(context_id)?;
        let row = self.load_row(user_id, context_id).await?;
        let Some((_, value)) = row else {
            return Ok(None);
        };
        let payload = parse_payload(&value)?;
        Ok(Some(self.meta_response(context_id, payload)))
    }

    /// Metadata for every stored credential of the caller (no key material).
    /// Foreign preference keys and unreadable rows are skipped, never fatal.
    pub async fn list(&self, user_id: &str) -> Result<Vec<KaneoCredentialMetaResponse>, SystemError> {
        let rows = self
            .repo
            .get_all(user_id)
            .await
            .map_err(|e| SystemError::Internal(format!("failed to list kaneo credentials: {e}")))?;
        let mut metas = Vec::new();
        for row in rows {
            let Some(context_id) = row.key.strip_prefix(KANEO_CREDENTIAL_KEY_PREFIX) else {
                continue;
            };
            let Ok(payload) = parse_payload(&row.value) else {
                tracing::warn!(user_id, key = %row.key, "kaneo credential row unreadable; skipping");
                continue;
            };
            metas.push(self.meta_response(context_id, payload));
        }
        metas.sort_by(|a, b| a.context_id.cmp(&b.context_id));
        Ok(metas)
    }

    /// Delete one stored credential (rotation-away or context removal).
    /// Returns `false` when nothing was stored.
    pub async fn delete(&self, user_id: &str, context_id: &str) -> Result<bool, SystemError> {
        validate_context_id(context_id)?;
        let existed = self.load_row(user_id, context_id).await?.is_some();
        if !existed {
            return Ok(false);
        }
        self.repo
            .delete_keys(user_id, &[preference_key(context_id).as_str()])
            .await
            .map_err(|e| SystemError::Internal(format!("failed to delete kaneo credential: {e}")))?;
        Ok(true)
    }

    /// Resolve a credential by context id for server-side use (session MCP
    /// env injection): the decrypted plaintext key plus the metadata needed
    /// to build `KANEO_API_URL`/`KANEO_API_KEY`. Never exposed via HTTP.
    pub async fn resolve(
        &self,
        user_id: &str,
        context_id: &str,
    ) -> Result<Option<ResolvedKaneoCredential>, SystemError> {
        validate_context_id(context_id)?;
        let row = self.load_row(user_id, context_id).await?;
        let Some((_, value)) = row else {
            return Ok(None);
        };
        let payload = parse_payload(&value)?;
        let api_key = decrypt_string(&payload.ciphertext, &self.encryption_key)
            .map_err(|e| SystemError::Internal(format!("kaneo credential decryption failed: {e}")))?;
        Ok(Some(ResolvedKaneoCredential {
            base_url: payload.base_url,
            agent_role: payload.agent_role,
            project_id: payload.project_id,
            key_expires_at: payload.key_expires_at,
            api_key,
        }))
    }

    async fn load_row(&self, user_id: &str, context_id: &str) -> Result<Option<(String, String)>, SystemError> {
        let rows = self
            .repo
            .get_by_keys(user_id, &[preference_key(context_id).as_str()])
            .await
            .map_err(|e| SystemError::Internal(format!("failed to load kaneo credential: {e}")))?;
        Ok(rows.first().map(|row| (row.key.clone(), row.value.clone())))
    }

    fn meta_response(&self, context_id: &str, payload: StoredKaneoCredential) -> KaneoCredentialMetaResponse {
        KaneoCredentialMetaResponse {
            context_id: context_id.to_owned(),
            base_url: payload.base_url,
            agent_role: payload.agent_role,
            project_id: payload.project_id,
            key_expires_at: payload.key_expires_at,
            updated_at: payload.updated_at,
        }
    }
}

/// Decrypted credential for server-side use (never serialized to the client).
#[derive(Debug, Clone)]
pub struct ResolvedKaneoCredential {
    pub base_url: String,
    pub agent_role: String,
    pub project_id: Option<String>,
    pub key_expires_at: Option<String>,
    pub api_key: String,
}

fn preference_key(context_id: &str) -> String {
    format!("{KANEO_CREDENTIAL_KEY_PREFIX}{context_id}")
}

fn validate_context_id(context_id: &str) -> Result<(), SystemError> {
    if context_id.is_empty() {
        return Err(SystemError::BadRequest("context id must not be empty".into()));
    }
    if context_id.len() > MAX_CONTEXT_ID_LENGTH {
        return Err(SystemError::BadRequest(format!(
            "context id exceeds maximum length of {MAX_CONTEXT_ID_LENGTH}"
        )));
    }
    if !context_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(SystemError::BadRequest(
            "context id may only contain alphanumerics, '-', '_' and '.'".into(),
        ));
    }
    Ok(())
}

fn validate_not_blank(value: &str, field: &'static str) -> Result<(), SystemError> {
    if value.trim().is_empty() {
        return Err(SystemError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(())
}

fn parse_payload(value: &str) -> Result<StoredKaneoCredential, SystemError> {
    let payload: StoredKaneoCredential =
        serde_json::from_str(value).map_err(|e| SystemError::Internal(format!("corrupt kaneo credential: {e}")))?;
    if payload.v != PAYLOAD_VERSION {
        return Err(SystemError::Internal(format!(
            "unsupported kaneo credential payload version {}",
            payload.v
        )));
    }
    Ok(payload)
}

/// Reject client-preference writes that would collide with the reserved
/// credential namespace. Wired into `ClientPrefService::validate_key`.
pub fn is_reserved_credential_key(key: &str) -> bool {
    key.starts_with(KANEO_CREDENTIAL_KEY_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockPrefRepo {
        rows: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl MockPrefRepo {
        fn new() -> Self {
            Self {
                rows: Mutex::new(Vec::new()),
            }
        }
    }

    fn row(key: &str, value: &str) -> aionui_db::models::ClientPreference {
        aionui_db::models::ClientPreference {
            user_id: "user-1".into(),
            key: key.to_owned(),
            value: value.to_owned(),
            updated_at: 0,
        }
    }

    #[async_trait::async_trait]
    impl IClientPreferenceRepository for MockPrefRepo {
        async fn get_all(
            &self,
            _user_id: &str,
        ) -> Result<Vec<aionui_db::models::ClientPreference>, aionui_db::DbError> {
            let rows = self.rows.lock().unwrap();
            Ok(rows.iter().map(|(k, v)| row(k, v)).collect())
        }

        async fn get_by_keys(
            &self,
            _user_id: &str,
            keys: &[&str],
        ) -> Result<Vec<aionui_db::models::ClientPreference>, aionui_db::DbError> {
            let rows = self.rows.lock().unwrap();
            Ok(rows
                .iter()
                .filter(|(k, _)| keys.contains(&k.as_str()))
                .map(|(k, v)| row(k, v))
                .collect())
        }

        async fn upsert_batch(&self, _user_id: &str, entries: &[(&str, &str)]) -> Result<(), aionui_db::DbError> {
            let mut rows = self.rows.lock().unwrap();
            for (key, value) in entries {
                if let Some(existing) = rows.iter_mut().find(|(k, _)| k == key) {
                    existing.1 = value.to_string();
                } else {
                    rows.push((key.to_string(), value.to_string()));
                }
            }
            Ok(())
        }

        async fn delete_keys(&self, _user_id: &str, keys: &[&str]) -> Result<(), aionui_db::DbError> {
            let mut rows = self.rows.lock().unwrap();
            rows.retain(|(k, _)| !keys.contains(&k.as_str()));
            Ok(())
        }
    }

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn sample_request() -> UpsertKaneoCredentialRequest {
        UpsertKaneoCredentialRequest {
            base_url: "http://localhost:1337".into(),
            agent_role: "coding".into(),
            project_id: Some("proj-1".into()),
            key_expires_at: Some("2026-10-01T00:00:00.000Z".into()),
            api_key: "kaneo-test-key".into(),
        }
    }

    #[tokio::test]
    async fn upsert_then_get_returns_metadata_without_key() {
        let repo = Arc::new(MockPrefRepo::new());
        let service = KaneoCredentialService::new(repo.clone(), test_key());
        let meta = service.upsert("user-1", "kctx-abc", sample_request()).await.unwrap();
        assert_eq!(meta.context_id, "kctx-abc");
        assert_eq!(meta.base_url, "http://localhost:1337");
        assert_eq!(meta.agent_role, "coding");
        assert_eq!(meta.project_id.as_deref(), Some("proj-1"));
        assert_eq!(meta.key_expires_at.as_deref(), Some("2026-10-01T00:00:00.000Z"));

        let stored_json = repo.rows.lock().unwrap()[0].1.clone();
        assert!(
            !stored_json.contains("kaneo-test-key"),
            "stored row must not contain plaintext: {stored_json}"
        );
        assert!(stored_json.contains("base_url"), "metadata stored alongside");
    }

    #[tokio::test]
    async fn rotate_replaces_ciphertext_in_place() {
        let repo = Arc::new(MockPrefRepo::new());
        let service = KaneoCredentialService::new(repo.clone(), test_key());
        service.upsert("user-1", "kctx-abc", sample_request()).await.unwrap();
        let rotated = UpsertKaneoCredentialRequest {
            api_key: "kaneo-rotated".into(),
            ..sample_request()
        };
        service.upsert("user-1", "kctx-abc", rotated).await.unwrap();
        assert_eq!(repo.rows.lock().unwrap().len(), 1, "rotation must not add a row");
        let resolved = service.resolve("user-1", "kctx-abc").await.unwrap().unwrap();
        assert_eq!(resolved.api_key, "kaneo-rotated");
    }

    #[tokio::test]
    async fn get_missing_is_none_and_delete_missing_is_false() {
        let service = KaneoCredentialService::new(Arc::new(MockPrefRepo::new()), test_key());
        assert!(service.get("user-1", "kctx-none").await.unwrap().is_none());
        assert!(!service.delete("user-1", "kctx-none").await.unwrap());
    }

    #[tokio::test]
    async fn list_skips_foreign_keys_and_reports_metadata() {
        let repo = Arc::new(MockPrefRepo::new());
        let service = KaneoCredentialService::new(repo.clone(), test_key());
        service.upsert("user-1", "kctx-abc", sample_request()).await.unwrap();
        repo.upsert_batch("user-1", &[("mcp.config", "[]")]).await.unwrap();
        let list = service.list("user-1").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].context_id, "kctx-abc");
    }

    #[tokio::test]
    async fn delete_removes_the_row() {
        let repo = Arc::new(MockPrefRepo::new());
        let service = KaneoCredentialService::new(repo.clone(), test_key());
        service.upsert("user-1", "kctx-abc", sample_request()).await.unwrap();
        assert!(service.delete("user-1", "kctx-abc").await.unwrap());
        assert!(service.get("user-1", "kctx-abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_input_rejected() {
        let service = KaneoCredentialService::new(Arc::new(MockPrefRepo::new()), test_key());
        let req = sample_request();
        assert!(service.upsert("user-1", "", req.clone()).await.is_err());
        assert!(service.upsert("user-1", "bad/slash", req.clone()).await.is_err());
        assert!(service.get("user-1", "../etc").await.is_err());
        let no_key = UpsertKaneoCredentialRequest {
            api_key: "  ".into(),
            ..sample_request()
        };
        assert!(service.upsert("user-1", "kctx-x", no_key).await.is_err());
        let no_base = UpsertKaneoCredentialRequest {
            base_url: "".into(),
            ..sample_request()
        };
        assert!(service.upsert("user-1", "kctx-x", no_base).await.is_err());
    }

    #[tokio::test]
    async fn resolve_roundtrip_decrypts() {
        let service = KaneoCredentialService::new(Arc::new(MockPrefRepo::new()), test_key());
        service.upsert("user-1", "kctx-abc", sample_request()).await.unwrap();
        let resolved = service.resolve("user-1", "kctx-abc").await.unwrap().unwrap();
        assert_eq!(resolved.api_key, "kaneo-test-key");
        assert_eq!(resolved.base_url, "http://localhost:1337");
        assert_eq!(resolved.agent_role, "coding");
        assert_eq!(resolved.project_id.as_deref(), Some("proj-1"));
        assert_eq!(resolved.key_expires_at.as_deref(), Some("2026-10-01T00:00:00.000Z"));
    }

    #[tokio::test]
    async fn resolve_missing_is_none() {
        let service = KaneoCredentialService::new(Arc::new(MockPrefRepo::new()), test_key());
        assert!(service.resolve("user-1", "kctx-none").await.unwrap().is_none());
    }

    #[test]
    fn reserved_prefix_guard() {
        assert!(is_reserved_credential_key("kaneo-credential:kctx-1"));
        assert!(!is_reserved_credential_key("mcp.config"));
    }

    #[test]
    fn metadata_response_shape_has_no_secret_fields() {
        let meta_json = serde_json::to_string(&KaneoCredentialMetaResponse {
            context_id: "kctx-1".into(),
            base_url: "http://x".into(),
            agent_role: "coding".into(),
            project_id: None,
            key_expires_at: None,
            updated_at: 1,
        })
        .unwrap();
        let lowered = meta_json.to_lowercase();
        assert!(!lowered.contains("api_key"));
        assert!(!lowered.contains("ciphertext"));
    }
}
