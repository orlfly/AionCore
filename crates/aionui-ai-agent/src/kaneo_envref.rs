//! Kaneo credential env-ref resolution — turns `kaneo:<contextId>` references
//! in a session MCP server's env/headers into decrypted, host-injected values.
//!
//! The renderer NEVER persists key material: when wiring the Kaneo builtin MCP
//! server it places `kaneo:<contextId>` sentinel values into the stdio env (as
//! `KANEO_API_URL` / `KANEO_API_KEY`). At agent-build time, BEFORE the neutral
//! `SessionMcpServer` is converted to the backend `McpServerSpec`, every env
//! (and HTTP/SSE header) value that carries the `kaneo:` scheme is resolved
//! against [`aionui_system::KaneoCredentialService::resolve`] and replaced with
//! the plaintext. Values that reference an unknown context are DROPPED (the
//! whole server is skipped) — a half-wired Kaneo server would only produce
//! confusing tool failures deeper in the session.
//!
//! Best-effort contract (same as `mcp_resolve`): resolution failure is
//! warn-logged and the affected server is skipped, never fatal.

use std::sync::Arc;

use aionui_api_types::{SessionMcpServer, SessionMcpTransport};
use aionui_system::KaneoCredentialService;
use tracing::warn;

/// Sentinel scheme the renderer embeds in MCP env values. `kaneo:<contextId>`.
pub const KANEO_ENVREF_SCHEME: &str = "kaneo:";

/// Strip the scheme and return the referenced context id, if this value is an
/// env-ref.
pub fn parse_env_ref(value: &str) -> Option<&str> {
    value.strip_prefix(KANEO_ENVREF_SCHEME).filter(|id| !id.is_empty())
}

/// Resolve every `kaneo:<contextId>` value in the server's transport against
/// the credential store. Returns `None` when the server must be dropped (an
/// env-ref failed to resolve; warn-logged inside).
pub async fn resolve_server_env_refs(
    server: &SessionMcpServer,
    user_id: &str,
    service: &Arc<KaneoCredentialService>,
) -> Option<SessionMcpServer> {
    let transport = match &server.transport {
        SessionMcpTransport::Stdio { command, args, env } => {
            let mut env = env.clone();
            let mut resolved_any = false;
            for (key, value) in env.iter_mut() {
                let Some(context_id) = parse_env_ref(value) else {
                    continue;
                };
                match resolve_value(service, user_id, context_id, key).await {
                    Some(replacement) => {
                        *value = replacement;
                        resolved_any = true;
                    }
                    None => return None,
                }
            }
            if resolved_any {
                SessionMcpTransport::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    env,
                }
            } else {
                server.transport.clone()
            }
        }
        SessionMcpTransport::Http { url, headers }
        | SessionMcpTransport::StreamableHttp { url, headers }
        | SessionMcpTransport::Sse { url, headers } => {
            let mut headers = headers.clone();
            let mut resolved_any = false;
            for (key, value) in headers.iter_mut() {
                let Some(context_id) = parse_env_ref(value) else {
                    continue;
                };
                match resolve_value(service, user_id, context_id, key).await {
                    Some(replacement) => {
                        *value = replacement;
                        resolved_any = true;
                    }
                    None => return None,
                }
            }
            if resolved_any {
                match &server.transport {
                    SessionMcpTransport::Sse { .. } => SessionMcpTransport::Sse {
                        url: url.clone(),
                        headers,
                    },
                    SessionMcpTransport::StreamableHttp { .. } => SessionMcpTransport::StreamableHttp {
                        url: url.clone(),
                        headers,
                    },
                    _ => SessionMcpTransport::Http {
                        url: url.clone(),
                        headers,
                    },
                }
            } else {
                server.transport.clone()
            }
        }
    };
    Some(SessionMcpServer {
        id: server.id.clone(),
        name: server.name.clone(),
        transport,
    })
}

/// Resolve ONE env-ref into the replacement value:
/// - `KANEO_API_URL` / `KANEO_BASE_URL` → the stored `base_url`
///   (`KANEO_BASE_URL` is what the upstream `kaneo-mcp` server actually reads)
/// - anything else → the decrypted API key
async fn resolve_value(
    service: &Arc<KaneoCredentialService>,
    user_id: &str,
    context_id: &str,
    env_key: &str,
) -> Option<String> {
    match service.resolve(user_id, context_id).await {
        Ok(Some(credential)) => {
            if env_key == "KANEO_API_URL" || env_key == "KANEO_BASE_URL" {
                Some(credential.base_url)
            } else {
                Some(credential.api_key)
            }
        }
        Ok(None) => {
            warn!(
                context_id,
                env_key, "kaneo_envref: no stored credential for context; dropping MCP server"
            );
            None
        }
        Err(err) => {
            warn!(
                context_id,
                env_key,
                error = %err,
                "kaneo_envref: credential resolve failed; dropping MCP server"
            );
            None
        }
    }
}

/// True when any env/headers value in the server carries the `kaneo:` scheme.
/// Used to fail closed when no credential store is available.
pub fn server_has_env_refs(server: &SessionMcpServer) -> bool {
    let values: Vec<&String> = match &server.transport {
        SessionMcpTransport::Stdio { env, .. } => env.values().collect(),
        SessionMcpTransport::Http { headers, .. }
        | SessionMcpTransport::StreamableHttp { headers, .. }
        | SessionMcpTransport::Sse { headers, .. } => headers.values().collect(),
    };
    values.iter().any(|v| parse_env_ref(v).is_some())
}

/// Convenience: map-resolve a whole snapshot, dropping servers whose env-refs
/// cannot be resolved. Order-preserving.
pub async fn resolve_snapshot_env_refs(
    servers: &[SessionMcpServer],
    user_id: &str,
    service: &Arc<KaneoCredentialService>,
) -> Vec<SessionMcpServer> {
    let mut out = Vec::with_capacity(servers.len());
    for server in servers {
        match resolve_server_env_refs(server, user_id, service).await {
            Some(resolved) => out.push(resolved),
            None => warn!(
                server_name = %server.name,
                "kaneo_envref: dropped MCP server with unresolved kaneo: env-ref"
            ),
        }
    }
    out
}

/// Append the project-scoped Kaneo env (`KANEO_API_URL`/`KANEO_API_KEY`) for the
/// referenced context into the conversation's runtime env, so the AGENT PROCESS
/// itself (its shell, and the ExecCommand tool env) can see them. This is how
/// the `kaneo-*` skills reach the API without MCP: their curl commands read
/// `$KANEO_API_URL` / `$KANEO_API_KEY`.
///
/// Resolution failure is warn-logged and leaves the runtime env untouched
/// (skills then degrade to their documented "ask the host" behavior — they must
/// not invent values). Existing KANEO_* entries are replaced so a resumed
/// conversation picks up rotated credentials.
pub async fn append_runtime_kaneo_env(
    runtime_env: &mut Vec<(String, String)>,
    servers: &[SessionMcpServer],
    user_id: &str,
    service: &Arc<KaneoCredentialService>,
) {
    // Collect the distinct context ids referenced anywhere in the snapshot's
    // stdio env / headers.
    let mut context_ids: Vec<&str> = Vec::new();
    for server in servers {
        let values: Vec<&String> = match &server.transport {
            SessionMcpTransport::Stdio { env, .. } => env.values().collect(),
            SessionMcpTransport::Http { headers, .. }
            | SessionMcpTransport::StreamableHttp { headers, .. }
            | SessionMcpTransport::Sse { headers, .. } => headers.values().collect(),
        };
        for value in values {
            if let Some(context_id) = parse_env_ref(value) {
                if !context_ids.contains(&context_id) {
                    context_ids.push(context_id);
                }
            }
        }
    }
    // Only the first context (the snapshot carries exactly one kaneo context in
    // practice) feeds the process env; a second would be ambiguous for shell
    // consumers anyway.
    let Some(context_id) = context_ids.first().copied() else {
        return;
    };
    match service.resolve(user_id, context_id).await {
        Ok(Some(credential)) => {
            runtime_env.retain(|(key, _)| key != "KANEO_API_URL" && key != "KANEO_API_KEY");
            runtime_env.push(("KANEO_API_URL".to_owned(), credential.base_url));
            runtime_env.push(("KANEO_API_KEY".to_owned(), credential.api_key));
        }
        Ok(None) => warn!(
            context_id,
            "kaneo_envref: no stored credential; skipping agent-process KANEO env injection"
        ),
        Err(err) => warn!(
            context_id,
            error = %err,
            "kaneo_envref: credential resolve failed; skipping agent-process KANEO env injection"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_api_types::UpsertKaneoCredentialRequest;
    use std::collections::HashMap;

    fn stdio_server(env: HashMap<String, String>) -> SessionMcpServer {
        SessionMcpServer {
            id: "srv-1".into(),
            name: "kaneo-test".into(),
            transport: SessionMcpTransport::Stdio {
                command: "kaneo-mcp".into(),
                args: vec!["--stdio".into()],
                env,
            },
        }
    }

    #[test]
    fn parse_env_ref_extracts_context_id() {
        assert_eq!(parse_env_ref("kaneo:kctx-abc"), Some("kctx-abc"));
        assert_eq!(parse_env_ref("kaneo:"), None);
        assert_eq!(parse_env_ref("plain-value"), None);
        assert_eq!(parse_env_ref("https://kaneo.example"), None);
    }

    #[tokio::test]
    async fn passes_through_servers_without_env_refs() {
        let db = aionui_db::init_database_memory().await.unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        let mut env = HashMap::new();
        env.insert("PLAIN".to_string(), "value".to_string());
        let server = stdio_server(env);
        let resolved = resolve_server_env_refs(&server, "user-1", &service).await.unwrap();
        assert_eq!(resolved, server);
    }

    #[tokio::test]
    async fn drops_server_when_context_unknown() {
        let db = aionui_db::init_database_memory().await.unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        let mut env = HashMap::new();
        env.insert("KANEO_API_KEY".to_string(), "kaneo:missing".to_string());
        let server = stdio_server(env);
        assert!(resolve_server_env_refs(&server, "user-1", &service).await.is_none());
    }

    #[tokio::test]
    async fn resolves_url_and_key_from_stored_credential() {
        let db = aionui_db::init_database_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
             VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
        )
        .bind("user-1")
        .bind("user-1")
        .execute(db.pool())
        .await
        .unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        service
            .upsert(
                "user-1",
                "kctx-1",
                UpsertKaneoCredentialRequest {
                    base_url: "https://kaneo.example".into(),
                    agent_role: "developer".into(),
                    project_id: Some("proj-1".into()),
                    key_expires_at: None,
                    api_key: "plaintext-key".into(),
                },
            )
            .await
            .unwrap();

        let mut env = HashMap::new();
        env.insert("KANEO_API_URL".to_string(), "kaneo:kctx-1".to_string());
        env.insert("KANEO_API_KEY".to_string(), "kaneo:kctx-1".to_string());
        let server = stdio_server(env);
        let resolved = resolve_server_env_refs(&server, "user-1", &service).await.unwrap();
        let SessionMcpTransport::Stdio { env, .. } = &resolved.transport else {
            panic!("expected stdio");
        };
        assert_eq!(env.get("KANEO_API_URL").unwrap(), "https://kaneo.example");
        assert_eq!(env.get("KANEO_API_KEY").unwrap(), "plaintext-key");
    }

    #[tokio::test]
    async fn resolves_kaneo_base_url_alias_from_stored_credential() {
        // The upstream `kaneo-mcp` server reads `KANEO_BASE_URL` / `KANEO_TOKEN`,
        // not `KANEO_API_URL` / `KANEO_API_KEY`. Both base-url aliases must map
        // to the stored `base_url` (the renderer emits all four keys).
        let db = aionui_db::init_database_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
             VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
        )
        .bind("user-1")
        .bind("user-1")
        .execute(db.pool())
        .await
        .unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        service
            .upsert(
                "user-1",
                "kctx-1",
                UpsertKaneoCredentialRequest {
                    base_url: "https://kaneo.example".into(),
                    agent_role: "developer".into(),
                    project_id: Some("proj-1".into()),
                    key_expires_at: None,
                    api_key: "plaintext-key".into(),
                },
            )
            .await
            .unwrap();

        let mut env = HashMap::new();
        env.insert("KANEO_BASE_URL".to_string(), "kaneo:kctx-1".to_string());
        env.insert("KANEO_TOKEN".to_string(), "kaneo:kctx-1".to_string());
        let server = stdio_server(env);
        let resolved = resolve_server_env_refs(&server, "user-1", &service).await.unwrap();
        let SessionMcpTransport::Stdio { env, .. } = &resolved.transport else {
            panic!("expected stdio");
        };
        assert_eq!(env.get("KANEO_BASE_URL").unwrap(), "https://kaneo.example");
        assert_eq!(env.get("KANEO_TOKEN").unwrap(), "plaintext-key");
    }

    #[tokio::test]
    async fn append_runtime_kaneo_env_projects_resolved_values() {
        let db = aionui_db::init_database_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
             VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
        )
        .bind("user-1")
        .bind("user-1")
        .execute(db.pool())
        .await
        .unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        service
            .upsert(
                "user-1",
                "kctx-1",
                UpsertKaneoCredentialRequest {
                    base_url: "https://kaneo.example".into(),
                    agent_role: "developer".into(),
                    project_id: Some("proj-1".into()),
                    key_expires_at: None,
                    api_key: "plaintext-key".into(),
                },
            )
            .await
            .unwrap();

        // No kaneo server in the snapshot → runtime env untouched.
        let mut runtime_env = vec![("AIONUI_USER_ID".to_owned(), "user-1".to_owned())];
        append_runtime_kaneo_env(&mut runtime_env, &[], "user-1", &service).await;
        assert_eq!(runtime_env.len(), 1);

        // With a kaneo snapshot server → KANEO_* appended after the AIONUI_* entries.
        let mut env = HashMap::new();
        env.insert("KANEO_API_URL".to_string(), "kaneo:kctx-1".to_string());
        env.insert("KANEO_API_KEY".to_string(), "kaneo:kctx-1".to_string());
        let kaneo = stdio_server(env);
        append_runtime_kaneo_env(&mut runtime_env, &[kaneo], "user-1", &service).await;
        assert!(runtime_env.contains(&("KANEO_API_URL".to_owned(), "https://kaneo.example".to_owned())));
        assert!(runtime_env.contains(&("KANEO_API_KEY".to_owned(), "plaintext-key".to_owned())));

        // Re-running replaces (rotation semantics), never duplicates.
        let mut env2 = HashMap::new();
        env2.insert("KANEO_API_URL".to_string(), "kaneo:kctx-1".to_string());
        let kaneo2 = stdio_server(env2);
        append_runtime_kaneo_env(&mut runtime_env, &[kaneo2], "user-1", &service).await;
        assert_eq!(runtime_env.iter().filter(|(k, _)| k == "KANEO_API_URL").count(), 1);
    }

    #[tokio::test]
    async fn append_runtime_kaneo_env_skips_when_credential_missing() {
        let db = aionui_db::init_database_memory().await.unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        let mut env = HashMap::new();
        env.insert("KANEO_API_URL".to_string(), "kaneo:missing".to_string());
        let kaneo = stdio_server(env);
        let mut runtime_env = Vec::new();
        append_runtime_kaneo_env(&mut runtime_env, &[kaneo], "user-1", &service).await;
        assert!(runtime_env.is_empty());
    }

    #[tokio::test]
    async fn resolve_snapshot_is_order_preserving_and_drops_unresolved() {
        let db = aionui_db::init_database_memory().await.unwrap();
        let service = Arc::new(KaneoCredentialService::new(
            Arc::new(aionui_db::SqliteClientPreferenceRepository::new(db.pool().clone())),
            [0x42; 32],
        ));
        let mut env = HashMap::new();
        env.insert("KANEO_API_KEY".to_string(), "kaneo:nope".to_string());
        let bad = stdio_server(env);
        let mut plain_env = HashMap::new();
        plain_env.insert("X".to_string(), "y".to_string());
        let plain = stdio_server(plain_env);
        let out = resolve_snapshot_env_refs(&[bad, plain], "user-1", &service).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "kaneo-test");
        let SessionMcpTransport::Stdio { env, .. } = &out[0].transport else {
            panic!("expected stdio");
        };
        assert!(env.contains_key("X"));
    }
}
