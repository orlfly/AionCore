-- Add Jcode as a builtin ACP agent (PATH-distributed, direct launch).
--
-- Identity: the ACP `initialize` handshake reports agentInfo
-- {name:"jcode", title:"Jcode"} (probed 2026-10-03, jcode 0.90.0), matching
-- the `backend` column. `agent_source` stays `builtin` rather than
-- `extension`: Jcode ships as a standalone native binary (GitHub releases,
-- `jcode update`), NOT an npm package. The `jcode` name on npm is an
-- unrelated MVC framework, so the Registry npx bridge pattern used by
-- minimax-code (044) does not apply — the row launches `jcode acp` directly
-- and availability probing looks for `jcode` on PATH.
--
-- Probe evidence (2026-10-03, jcode 0.90.0, clean handshake):
--   initialize ok, protocolVersion 1, agentCapabilities:
--     load_session=true, mcp http/sse=false,
--     prompt image=true embedded_context=true audio=false,
--     session close={} resume={}
--   session/new ok (no auth gate in a logged-in environment);
--   authMethods advertised: none, so auth_methods stays NULL.
--
-- yolo_id stays NULL: Jcode manages permission levels through its own
-- permission prompt flow, not through a dedicated session mode id.
--
-- native_skills_dirs stays NULL: skills are resolved by the Jcode daemon
-- itself, no project-relative directory contract is documented.
--
-- behavior_policy omits `supports_team`: migration 033 retired the negative
-- form, and team capability is derived from backend + probed capabilities.
-- Post-030 seed shape: builtin rows use agent_id = id and user_id NULL.
INSERT INTO agent_metadata
    (id, agent_id, icon, name, backend, agent_type, agent_source, agent_source_info,
     enabled, command, args, env, native_skills_dirs, behavior_policy, yolo_id,
     agent_capabilities, sort_order, created_at, updated_at)
VALUES
    ('a55af7fb', 'a55af7fb', '/api/assets/logos/acp-registry/jcode.svg', 'Jcode',
     'jcode', 'acp', 'builtin', '{"binary_name":"jcode"}',
     1, 'jcode', '["acp"]', '[]',
     NULL,
     '{}',
     NULL,
     '{"load_session":true,"mcp_capabilities":{"http":false,"sse":false},"prompt_capabilities":{"image":true,"audio":false,"embedded_context":true},"session_capabilities":{"close":{},"resume":{}}}',
     3995,
     unixepoch('now','subsec')*1000, unixepoch('now','subsec')*1000)
ON CONFLICT(id) DO UPDATE SET
    agent_id = excluded.agent_id,
    icon = excluded.icon,
    name = excluded.name,
    description = NULL,
    backend = excluded.backend,
    agent_type = excluded.agent_type,
    agent_source = excluded.agent_source,
    agent_source_info = excluded.agent_source_info,
    enabled = excluded.enabled,
    command = excluded.command,
    args = excluded.args,
    env = excluded.env,
    native_skills_dirs = excluded.native_skills_dirs,
    behavior_policy = excluded.behavior_policy,
    yolo_id = excluded.yolo_id,
    sort_order = excluded.sort_order,
    updated_at = unixepoch('now','subsec')*1000;
