//! Migration 045 seeds Jcode as a builtin ACP agent.
//!
//! Unlike the Registry npx rows (044), Jcode ships as a standalone native
//! binary, so the row launches `jcode acp` directly and availability probing
//! looks for `jcode` on PATH with no bridge. The assertions pin the launch
//! argv, the probed handshake columns a re-seed must never clobber, and the
//! absence of Registry identity fields.

use aionui_db::{IAgentMetadataRepository, SqliteAgentMetadataRepository, init_database_memory};

const BACKEND: &str = "jcode";

#[tokio::test]
async fn seeds_jcode_as_a_direct_path_builtin() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteAgentMetadataRepository::new(db.pool().clone());

    let row = repo
        .find_builtin_by_backend(BACKEND)
        .await
        .unwrap()
        .expect("jcode is seeded by migration 045");

    assert_eq!(row.id, "a55af7fb");
    assert_eq!(row.user_id, None, "builtin rows are machine-level, user_id stays NULL");
    assert_eq!(row.name, "Jcode");
    assert_eq!(row.agent_type, "acp");
    assert_eq!(row.agent_source, "builtin");
    assert!(row.enabled);
    assert_eq!(row.icon.as_deref(), Some("/api/assets/logos/acp-registry/jcode.svg"));

    // Direct launch: the binary is the ACP server. No npx bridge, no
    // release-lock pin — Jcode versions through its own `jcode update`.
    assert_eq!(row.command.as_deref(), Some("jcode"));
    assert_eq!(row.args.as_deref(), Some(r#"["acp"]"#));
    assert_eq!(row.env.as_deref(), Some("[]"));

    let source: serde_json::Value =
        serde_json::from_str(row.agent_source_info.as_deref().expect("agent_source_info")).unwrap();
    assert_eq!(source["binary_name"], "jcode");
    assert!(
        source.get("bridge_binary").is_none(),
        "jcode launches directly; no bridge binary applies"
    );
    assert!(
        source.get("registry_json_id").is_none() && source.get("package_name").is_none(),
        "agent_source_info must not carry Registry identity fields: {source}"
    );
}

/// `initialize` was probed live (jcode 0.90.0), so `agent_capabilities` is
/// seeded snake_case; `initialize` advertised no auth methods, so
/// `auth_methods` stays NULL rather than a synthesized blob. Neither column
/// may appear in the migration's `ON CONFLICT DO UPDATE` set — a re-seed must
/// not reset what a live handshake later taught this install.
#[tokio::test]
async fn seeds_probed_capabilities_and_leaves_unprobed_fields_null() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteAgentMetadataRepository::new(db.pool().clone());

    let row = repo
        .find_builtin_by_backend(BACKEND)
        .await
        .unwrap()
        .expect("jcode is seeded");

    let caps: serde_json::Value =
        serde_json::from_str(row.agent_capabilities.as_deref().expect("agent_capabilities seeded")).unwrap();
    assert_eq!(caps["load_session"], true);
    assert_eq!(
        caps["mcp_capabilities"]["http"], false,
        "the probed handshake advertised no MCP transports"
    );
    assert_eq!(caps["mcp_capabilities"]["sse"], false);
    assert_eq!(caps["prompt_capabilities"]["image"], true);
    assert_eq!(caps["prompt_capabilities"]["embedded_context"], true);
    assert!(caps["session_capabilities"].get("resume").is_some());
    assert!(
        row.agent_capabilities.as_deref().unwrap().contains("load_session")
            && !row.agent_capabilities.as_deref().unwrap().contains("loadSession"),
        "handshake columns are stored snake_case (migration 003 contract)"
    );

    assert_eq!(
        row.auth_methods, None,
        "initialize advertised no auth methods; nothing is synthesized"
    );
    assert_eq!(row.yolo_id, None, "no dedicated permission session mode id");
    assert_eq!(row.native_skills_dirs, None, "no project-relative skills directory");
}

/// Bad path: aliases must not resolve to builtin rows, so nothing can
/// accidentally seed a second row under a different identity and split the
/// agent's metadata.
#[tokio::test]
async fn aliases_are_not_registered_as_backends() {
    let db = init_database_memory().await.unwrap();
    let repo = SqliteAgentMetadataRepository::new(db.pool().clone());

    for alias in ["Jcode", "jcode-acp", "j-code"] {
        assert!(
            repo.find_builtin_by_backend(alias).await.unwrap().is_none(),
            "{alias} must not resolve to a builtin row"
        );
    }
}
