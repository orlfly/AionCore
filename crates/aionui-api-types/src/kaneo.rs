//! Kaneo credential API types.
//!
//! The backend stores per-context Kaneo API keys AES-256-GCM encrypted at
//! rest (same `encryption_key` root as provider keys). The renderer addresses
//! a stored key only by its Kaneo context id; write requests carry plaintext
//! exactly once (import / rotate), responses never echo key material.

use serde::{Deserialize, Serialize};

/// Request body for `PUT /api/kaneo-credentials/{context_id}`.
///
/// Stores (or rotates) the plaintext API key for one Kaneo context. The
/// backend encrypts `api_key` before persistence; `key_expires_at` is stored
/// as plaintext metadata (it is not secret) so clients can render expiry
/// warnings without a round-trip through decryption.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpsertKaneoCredentialRequest {
    /// Kaneo instance base URL the key belongs to (plaintext metadata).
    pub base_url: String,
    /// Agent role bound to the key (plaintext metadata).
    pub agent_role: String,
    /// Bound Kaneo project id, or `null` for an unbound (legacy) key.
    #[serde(default)]
    pub project_id: Option<String>,
    /// API key `expiresAt` as reported by Kaneo (ISO string), plaintext
    /// metadata. `null` when the key does not expire.
    #[serde(default)]
    pub key_expires_at: Option<String>,
    /// The plaintext API key. Transferred exactly once per store/rotate;
    /// never returned by any endpoint.
    pub api_key: String,
}

/// Metadata response for one stored Kaneo credential.
///
/// Deliberately carries NO key material: callers get the metadata they need
/// for context bookkeeping (base URL, role, project, expiry) and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KaneoCredentialMetaResponse {
    /// Kaneo context id this credential is stored under.
    pub context_id: String,
    /// Kaneo instance base URL the key belongs to.
    pub base_url: String,
    /// Agent role bound to the key.
    pub agent_role: String,
    /// Bound Kaneo project id, or `null` for an unbound (legacy) key.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Key expiry as reported by Kaneo (ISO string), or `null` when none.
    #[serde(default)]
    pub key_expires_at: Option<String>,
    /// When the credential was last written (epoch ms).
    pub updated_at: i64,
}

/// Response for `GET /api/kaneo-credentials` — all metadata for the caller.
pub type KaneoCredentialListResponse = Vec<KaneoCredentialMetaResponse>;
