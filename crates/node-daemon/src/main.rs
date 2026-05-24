use agent_capability_policy::{
    NodeCapabilityPolicy, effective_tool_catalog, load_policy, tool_allowed, write_policy,
};
use agent_identity_core::{
    CapabilityGrantClaims, LoadOptions, NodeIdentity, SignedCapabilityGrant,
    load_or_create_identity,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_PROFILE_DIR: &str = ".agent-node";
const DEFAULT_BIND_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8787;
const TOKEN_BYTES: usize = 32;
const REQUEST_CODE_BYTES: usize = 32;
const DEFAULT_GRANT_TTL_SECONDS: i64 = 900;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => init_profile(&args[2..])?,
        Some("run") => run_daemon(&args[2..]).await?,
        Some("issue-token") => issue_token(&args[2..])?,
        Some("help") | Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(2);
        }
    }
    Ok(())
}

fn init_profile(args: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = path_arg(args, "--profile").unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR));
    let role = value_arg(args, "--role").unwrap_or("researcher-agent");
    let identity_path =
        path_arg(args, "--identity").unwrap_or_else(|| profile.join("identity.key"));
    let token_path = path_arg(args, "--token").unwrap_or_else(|| profile.join("agent.token"));
    let policy_path = path_arg(args, "--policy").unwrap_or_else(|| profile.join("policy.json"));
    let password = identity_password("Create a password for the new node identity:")?;

    fs::create_dir_all(&profile)?;
    let (identity, status) =
        load_or_create_identity(&identity_path, &password, LoadOptions::default())?;
    let token = load_or_create_token(&token_path)?;

    if !policy_path.exists() {
        let policy = NodeCapabilityPolicy::permissive_for_role(role);
        write_policy(&policy_path, &policy)?;
    }

    let manifest = identity.manifest()?;
    println!("initialized profile: {}", profile.display());
    println!("identity status: {:?}", status);
    println!("peer id: {}", manifest.peer_id);
    println!("identity path: {}", identity_path.display());
    println!("token path: {}", token_path.display());
    println!("policy path: {}", policy_path.display());
    println!("agent token: {token}");
    Ok(())
}

async fn run_daemon(args: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = path_arg(args, "--profile").unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR));
    let role = value_arg(args, "--role")
        .unwrap_or("researcher-agent")
        .to_string();
    let identity_path =
        path_arg(args, "--identity").unwrap_or_else(|| profile.join("identity.key"));
    let token_path = path_arg(args, "--token").unwrap_or_else(|| profile.join("agent.token"));
    let policy_path = path_arg(args, "--policy").unwrap_or_else(|| profile.join("policy.json"));
    let bind_host = value_arg(args, "--bind")
        .unwrap_or(DEFAULT_BIND_HOST)
        .to_string();
    let port = value_arg(args, "--port")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    let password = identity_password("Unlock node identity:")?;

    let (identity, status) =
        load_or_create_identity(&identity_path, &password, LoadOptions::default())?;
    let token = load_or_create_token(&token_path)?;
    let policy = load_policy(Some(&policy_path), &role)?;

    let manifest = identity.manifest()?;
    println!("identity status: {:?}", status);
    println!("peer id: {}", manifest.peer_id);
    println!("policy: {}", policy_path.display());
    println!("listening: http://{bind_host}:{port}");

    let state = ApiState {
        identity: Arc::new(identity),
        token,
        policy: Arc::new(policy),
        role,
        bind_host: bind_host.clone(),
        port,
        pending_requests: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/healthz", get(health_handler))
        .route("/auth/request-code", post(request_code_handler))
        .route("/auth/grants", post(grant_issue_handler))
        .route("/auth/verify", post(grant_verify_handler))
        .route("/.well-known/agent-card.json", get(agent_card_handler))
        .route("/status", get(status_handler))
        .route("/manifest", get(manifest_handler))
        .route("/capabilities", get(capabilities_handler))
        .route("/mcp", post(mcp_handler))
        .route("/execute", post(execute_handler))
        .route("/broadcast", post(broadcast_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("{bind_host}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn issue_token(args: &[String]) -> Result<(), Box<dyn Error>> {
    let profile = path_arg(args, "--profile").unwrap_or_else(|| PathBuf::from(DEFAULT_PROFILE_DIR));
    let token_path = path_arg(args, "--token").unwrap_or_else(|| profile.join("agent.token"));
    let token = write_new_token(&token_path)?;
    println!("{token}");
    Ok(())
}

#[derive(Clone)]
struct ApiState {
    identity: Arc<NodeIdentity>,
    token: String,
    policy: Arc<NodeCapabilityPolicy>,
    role: String,
    bind_host: String,
    port: u16,
    pending_requests: Arc<RwLock<HashMap<String, AuthRequestCode>>>,
}

#[derive(Debug, Serialize)]
struct NodeManifest {
    schema_version: &'static str,
    peer_id: String,
    role: String,
    api: ApiManifest,
    identity: agent_identity_core::IdentityManifest,
    capabilities: Vec<agent_capability_policy::ToolContract>,
    policy: NodeCapabilityPolicy,
}

#[derive(Debug, Serialize)]
struct ApiManifest {
    bind_host: String,
    port: u16,
    auth: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct AuthRequestCode {
    request_id: String,
    request_code: String,
    subject: String,
    requested_scopes: Vec<String>,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct RequestCodeRequest {
    subject: Option<String>,
    requested_scopes: Option<Vec<String>>,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GrantIssueRequest {
    request_id: String,
    subject: Option<String>,
    scopes: Vec<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct GrantVerifyRequest {
    grant: Option<SignedCapabilityGrant>,
    grant_base64: Option<String>,
    required_scope: Option<String>,
}

type ApiResult<T> = Result<T, Box<Response>>;

fn manifest_from_state(state: &ApiState) -> ApiResult<NodeManifest> {
    let identity = state
        .identity
        .manifest()
        .map_err(|err| Box::new(internal_error(err)))?;
    Ok(NodeManifest {
        schema_version: "agent-node/v0alpha1",
        peer_id: identity.peer_id.clone(),
        role: state.role.clone(),
        api: ApiManifest {
            bind_host: state.bind_host.clone(),
            port: state.port,
            auth: "bearer-token bootstrap; signed scoped grants for agent requests",
        },
        identity,
        capabilities: effective_tool_catalog(&state.policy),
        policy: (*state.policy).clone(),
    })
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn agent_card_handler(State(state): State<ApiState>) -> Response {
    let base_url = format!("http://{}:{}", state.bind_host, state.port);
    let tools: Vec<Value> = effective_tool_catalog(&state.policy)
        .into_iter()
        .map(|tool| {
            json!({
                "id": canonical_scope_segment(tool.name),
                "name": tool.name,
                "description": tool.description,
                "tags": ["capability", tool.permission_scope],
                "examples": [tool.schema_payload],
                "inputModes": ["application/json", "text/plain"],
                "outputModes": ["application/json", "text/plain"]
            })
        })
        .collect();

    Json(json!({
        "protocolVersion": "1.0",
        "name": "Agent Identity Node",
        "description": "Local authorization and verifiable capability authority for agent runtimes.",
        "url": base_url,
        "preferredTransport": "JSONRPC",
        "version": env!("CARGO_PKG_VERSION"),
        "provider": {
            "organization": "HIVE research project"
        },
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "stateTransitionHistory": false,
            "extensions": [
                {
                    "uri": "https://github.com/luka-waronig/agent-identity-node/blob/main/docs/integrations.md",
                    "description": "Signed scoped grants for local tool authorization.",
                    "required": false
                }
            ]
        },
        "securitySchemes": {
            "bootstrapBearer": {
                "type": "http",
                "scheme": "bearer",
                "description": "local bootstrap token for administrative grant issuance"
            },
            "ainGrant": {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
                "description": "AIN-Grant <base64-json-grant>"
            }
        },
        "security": [
            { "ainGrant": [] },
            { "bootstrapBearer": [] }
        ],
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "supportedInterfaces": [
            {
                "url": format!("{base_url}/mcp"),
                "protocolBinding": "https://modelcontextprotocol.io/specification/2025-06-18",
                "protocolVersion": "2025-06-18"
            },
            {
                "url": base_url,
                "protocolBinding": "https://github.com/luka-waronig/agent-identity-node/blob/main/docs/protocol.md",
                "protocolVersion": "0alpha1"
            }
        ],
        "skills": tools
    }))
    .into_response()
}

async fn request_code_handler(
    State(state): State<ApiState>,
    Json(req): Json<RequestCodeRequest>,
) -> Response {
    let now = unix_timestamp();
    let ttl = req.ttl_seconds.unwrap_or(300).clamp(30, 900);
    let request = AuthRequestCode {
        request_id: random_hex(REQUEST_CODE_BYTES),
        request_code: random_hex(REQUEST_CODE_BYTES),
        subject: req.subject.unwrap_or_else(|| "agent-runtime".to_string()),
        requested_scopes: normalize_scopes(req.requested_scopes.unwrap_or_default()),
        issued_at: now,
        expires_at: now + ttl,
    };

    state
        .pending_requests
        .write()
        .await
        .insert(request.request_id.clone(), request.clone());

    Json(json!({
        "schema_version": "agent-node/request-code/v0alpha1",
        "request": request,
        "next": "POST /auth/grants with the bearer bootstrap token, request_id, subject, scopes, and optional ttl_seconds."
    }))
    .into_response()
}

async fn grant_issue_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<GrantIssueRequest>,
) -> Response {
    if !has_bootstrap_token(&headers, &state.token) {
        return unauthorized("grant issuance requires the bootstrap bearer token");
    }

    let now = unix_timestamp();
    reap_expired_requests(&state, now).await;
    let request = match state.pending_requests.write().await.remove(&req.request_id) {
        Some(request) if request.expires_at >= now => request,
        _ => return bad_request("request_id is unknown or expired"),
    };

    let subject = req.subject.unwrap_or_else(|| request.subject.clone());
    if subject.trim().is_empty() {
        return bad_request("grant subject must not be empty");
    }

    let requested_scopes = normalize_scopes(req.scopes);
    if requested_scopes.is_empty() {
        return bad_request("grant scopes must not be empty");
    }
    if !request.requested_scopes.is_empty()
        && !requested_scopes
            .iter()
            .all(|scope| request.requested_scopes.contains(scope))
    {
        return forbidden("requested grant scopes exceed the authorization request scopes");
    }
    if let Some(disallowed) = requested_scopes
        .iter()
        .find(|scope| !scope_allowed_by_policy(&state.policy, scope))
    {
        return forbidden(&format!(
            "scope {disallowed} is not permitted by the current node policy"
        ));
    }

    let ttl = req
        .ttl_seconds
        .unwrap_or(DEFAULT_GRANT_TTL_SECONDS)
        .clamp(30, DEFAULT_GRANT_TTL_SECONDS);
    let expires_at = now + ttl;
    let grant = match state.identity.issue_grant(
        subject,
        requested_scopes,
        expires_at,
        request.request_code,
    ) {
        Ok(grant) => grant,
        Err(err) => return internal_error(err),
    };
    let encoded = match grant.encode_base64_json() {
        Ok(encoded) => encoded,
        Err(err) => return internal_error(err),
    };

    Json(json!({
        "schema_version": "agent-node/grant-response/v0alpha1",
        "grant": grant,
        "grant_base64": encoded,
        "authorization_header": format!("AIN-Grant {encoded}"),
    }))
    .into_response()
}

async fn grant_verify_handler(
    State(state): State<ApiState>,
    Json(req): Json<GrantVerifyRequest>,
) -> Response {
    let grant = match req.grant {
        Some(grant) => grant,
        None => match req.grant_base64 {
            Some(encoded) => match SignedCapabilityGrant::decode_base64_json(&encoded) {
                Ok(grant) => grant,
                Err(err) => return forbidden(&err.to_string()),
            },
            None => return bad_request("grant or grant_base64 is required"),
        },
    };

    let now = unix_timestamp();
    let verification = match req.required_scope.as_deref() {
        Some(scope) => state.identity.verify_grant(&grant, scope, now),
        None => grant
            .verify_with_public_key(
                &state.identity.keypair().public(),
                Some(&state.identity.peer_id().to_string()),
                now,
            )
            .map(|_| grant.claims.clone()),
    };

    match verification {
        Ok(claims) => Json(json!({ "valid": true, "claims": claims })).into_response(),
        Err(err) => forbidden(&err.to_string()),
    }
}

async fn status_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Err(resp) = authorize(&headers, &state, "status:read").await {
        return *resp;
    }

    match manifest_from_state(&state) {
        Ok(manifest) => Json(json!({
            "status": "healthy",
            "peer_id": manifest.peer_id,
            "role": manifest.role,
            "capabilities": manifest.capabilities,
            "auth_mode": manifest.api.auth,
        }))
        .into_response(),
        Err(resp) => *resp,
    }
}

async fn manifest_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Err(resp) = authorize(&headers, &state, "manifest:read").await {
        return *resp;
    }

    match manifest_from_state(&state) {
        Ok(manifest) => Json(manifest).into_response(),
        Err(resp) => *resp,
    }
}

async fn capabilities_handler(headers: HeaderMap, State(state): State<ApiState>) -> Response {
    if let Err(resp) = authorize(&headers, &state, "capabilities:read").await {
        return *resp;
    }

    Json(json!({
        "schema_version": "agent-node/v0alpha1",
        "role": state.role,
        "tools": effective_tool_catalog(&state.policy),
        "auth_scopes": allowed_scopes_for_policy(&state.policy),
        "policy": (*state.policy).clone(),
    }))
    .into_response()
}

async fn mcp_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<Value>,
) -> Response {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return json_rpc_error(id, -32600, "invalid JSON-RPC request");
    };

    match method {
        "initialize" => json_rpc_result(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {
                        "listChanged": false
                    }
                },
                "serverInfo": {
                    "name": "agent-identity-node",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),
        "tools/list" => {
            if let Err(resp) = authorize(&headers, &state, "capabilities:read").await {
                return *resp;
            }
            json_rpc_result(
                id,
                json!({
                    "tools": mcp_tools_for_policy(&state.policy)
                }),
            )
        }
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return json_rpc_error(id, -32602, "tools/call requires params.name");
            };
            let payload = params
                .get("arguments")
                .and_then(|args| args.get("payload"))
                .and_then(Value::as_str)
                .unwrap_or("");

            let required_scope = format!("tool:{}", canonical_scope_segment(name));
            if let Err(resp) = authorize(&headers, &state, &required_scope).await {
                return *resp;
            }
            if !tool_allowed(&state.policy, name) {
                return json_rpc_error(id, -32001, "tool is not permitted by this node policy");
            }

            match execute_tool(name, payload, &state.policy) {
                Ok(result) => json_rpc_result(
                    id,
                    json!({
                        "content": [
                            {
                                "type": "text",
                                "text": result
                            }
                        ],
                        "isError": false
                    }),
                ),
                Err(err) => json_rpc_error(id, -32000, &err.to_string()),
            }
        }
        _ => json_rpc_error(id, -32601, "method not found"),
    }
}

fn mcp_tools_for_policy(policy: &NodeCapabilityPolicy) -> Vec<Value> {
    effective_tool_catalog(policy)
        .into_iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "payload": {
                            "type": "string",
                            "description": tool.schema_payload
                        }
                    },
                    "required": ["payload"]
                }
            })
        })
        .collect()
}

fn json_rpc_result(id: Value, result: Value) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
    .into_response()
}

fn json_rpc_error(id: Value, code: i64, message: &str) -> Response {
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct ExecuteRequest {
    tool_name: String,
    payload: String,
}

async fn execute_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<ExecuteRequest>,
) -> Response {
    let required_scope = format!("tool:{}", canonical_scope_segment(&req.tool_name));
    if let Err(resp) = authorize(&headers, &state, &required_scope).await {
        return *resp;
    }

    if !tool_allowed(&state.policy, &req.tool_name) {
        return forbidden(&format!(
            "tool {} is not permitted by this node policy",
            req.tool_name.trim()
        ));
    }

    match execute_tool(&req.tool_name, &req.payload, &state.policy) {
        Ok(result) => Json(json!({ "result": result })).into_response(),
        Err(err) => internal_error(err),
    }
}

#[derive(Debug, Deserialize)]
struct BroadcastRequest {
    content: String,
}

#[derive(Debug, Serialize)]
struct SignedBroadcast {
    schema_version: &'static str,
    sender_peer_id: String,
    timestamp: i64,
    content: String,
    signature_base64: String,
}

async fn broadcast_handler(
    headers: HeaderMap,
    State(state): State<ApiState>,
    Json(req): Json<BroadcastRequest>,
) -> Response {
    if let Err(resp) = authorize(&headers, &state, "broadcast:write").await {
        return *resp;
    }

    if !state.policy.broadcast_policy.allow_agent_broadcasts {
        return forbidden("agent-initiated broadcasts are disabled by node policy");
    }

    let content = req.content.trim();
    if content.is_empty() {
        return bad_request("broadcast content must not be empty");
    }
    if content.len() > state.policy.broadcast_policy.max_payload_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": "broadcast content exceeds policy limit" })),
        )
            .into_response();
    }

    let timestamp = unix_timestamp();
    let sender_peer_id = state.identity.peer_id().to_string();
    let signing_payload = json!({
        "sender_peer_id": sender_peer_id,
        "timestamp": timestamp,
        "content": content,
    })
    .to_string();
    let signature = match state.identity.sign(signing_payload.as_bytes()) {
        Ok(signature) => BASE64.encode(signature),
        Err(err) => return internal_error(err),
    };

    Json(SignedBroadcast {
        schema_version: "agent-node/signed-broadcast/v0alpha1",
        sender_peer_id,
        timestamp,
        content: content.to_string(),
        signature_base64: signature,
    })
    .into_response()
}

async fn authorize(
    headers: &HeaderMap,
    state: &ApiState,
    required_scope: &str,
) -> ApiResult<Option<CapabilityGrantClaims>> {
    if has_bootstrap_token(headers, &state.token) {
        return Ok(None);
    }

    let Some(grant) = grant_from_headers(headers) else {
        return Err(Box::new(unauthorized(
            "missing bearer token or signed capability grant",
        )));
    };

    match state
        .identity
        .verify_grant(&grant, required_scope, unix_timestamp())
    {
        Ok(claims) => {
            if !scope_allowed_by_policy(&state.policy, required_scope) {
                return Err(Box::new(forbidden(
                    "grant scope is no longer allowed by node policy",
                )));
            }
            Ok(Some(claims))
        }
        Err(err) => Err(Box::new(forbidden(&err.to_string()))),
    }
}

fn has_bootstrap_token(headers: &HeaderMap, expected_token: &str) -> bool {
    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    provided == Some(expected_token)
}

fn grant_from_headers(headers: &HeaderMap) -> Option<SignedCapabilityGrant> {
    if let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("AIN-Grant "))
    {
        return SignedCapabilityGrant::decode_base64_json(value).ok();
    }

    headers
        .get("x-agent-grant")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| SignedCapabilityGrant::decode_base64_json(value).ok())
}

fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
}

fn execute_tool(
    tool_name: &str,
    payload: &str,
    policy: &NodeCapabilityPolicy,
) -> Result<String, Box<dyn Error>> {
    let vault_path = PathBuf::from(policy.vault_policy.vault_dir.trim());
    fs::create_dir_all(&vault_path)?;

    match tool_name.trim().to_ascii_uppercase().as_str() {
        "READ_FILE" => {
            let clean_name = sanitize_filename(payload)?;
            let target = vault_path.join(clean_name);
            if target.exists() {
                Ok(fs::read_to_string(target)?)
            } else {
                Ok(format!("file not found in vault: {}", payload.trim()))
            }
        }
        "ARCHIVE_DATA" => {
            let normalized = payload.trim();
            if normalized.is_empty() {
                return Ok("cannot archive empty payload".to_string());
            }
            let target = vault_path.join(format!("artifact_{}.txt", unix_timestamp()));
            fs::write(&target, normalized)?;
            Ok(format!(
                "archived payload as {}",
                target
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("artifact.txt")
            ))
        }
        "SCAN_VAULT" => {
            let mut files = Vec::new();
            for entry in fs::read_dir(vault_path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        files.push(name.to_string());
                    }
                }
            }
            files.sort();
            Ok(serde_json::to_string(&files)?)
        }
        other => Ok(format!("tool {other} is not implemented")),
    }
}

fn sanitize_filename(payload: &str) -> Result<String, Box<dyn Error>> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Err("filename cannot be empty".into());
    }
    let path = Path::new(trimmed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid file name")?;
    if file_name != trimmed || file_name.contains("..") {
        return Err("path traversal is not allowed".into());
    }
    Ok(file_name.to_string())
}

fn load_or_create_token(path: impl AsRef<Path>) -> Result<String, Box<dyn Error>> {
    let path = path.as_ref();
    if path.exists() {
        Ok(fs::read_to_string(path)?.trim().to_string())
    } else {
        write_new_token(path)
    }
}

fn write_new_token(path: impl AsRef<Path>) -> Result<String, Box<dyn Error>> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut file = fs::File::create(path)?;
    file.write_all(token.as_bytes())?;
    Ok(token)
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn normalize_scopes(scopes: Vec<String>) -> Vec<String> {
    let mut scopes: Vec<String> = scopes
        .into_iter()
        .map(|scope| scope.trim().to_ascii_lowercase())
        .filter(|scope| !scope.is_empty())
        .collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

fn canonical_scope_segment(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

fn allowed_scopes_for_policy(policy: &NodeCapabilityPolicy) -> Vec<String> {
    let mut scopes = vec![
        "status:read".to_string(),
        "manifest:read".to_string(),
        "capabilities:read".to_string(),
    ];

    if policy.broadcast_policy.allow_agent_broadcasts {
        scopes.push("broadcast:write".to_string());
    }

    for tool in effective_tool_catalog(policy) {
        scopes.push(format!("tool:{}", canonical_scope_segment(tool.name)));
    }

    scopes.sort();
    scopes.dedup();
    scopes
}

fn scope_allowed_by_policy(policy: &NodeCapabilityPolicy, scope: &str) -> bool {
    match scope.trim().to_ascii_lowercase().as_str() {
        "status:read" | "manifest:read" | "capabilities:read" => true,
        "broadcast:write" => policy.broadcast_policy.allow_agent_broadcasts,
        tool_scope if tool_scope.starts_with("tool:") => {
            let tool = tool_scope.trim_start_matches("tool:");
            tool_allowed(policy, tool)
        }
        _ => false,
    }
}

async fn reap_expired_requests(state: &ApiState, now: i64) {
    state
        .pending_requests
        .write()
        .await
        .retain(|_, request| request.expires_at >= now);
}

fn identity_password(prompt: &str) -> Result<String, Box<dyn Error>> {
    for key in ["AIN_IDENTITY_PASSWORD", "AGENT_NODE_IDENTITY_PASSWORD"] {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    println!("{prompt}");
    Ok(rpassword::read_password()?)
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn value_arg<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == key)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

fn path_arg(args: &[String], key: &str) -> Option<PathBuf> {
    value_arg(args, key).map(PathBuf::from)
}

fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response()
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

fn internal_error(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

fn print_help() {
    println!(
        r#"agent-node

USAGE:
  agent-node init [--profile DIR] [--role ROLE]
  agent-node run [--profile DIR] [--bind HOST] [--port PORT]
  agent-node issue-token [--profile DIR]

ENV:
  AIN_IDENTITY_PASSWORD          identity unlock password for non-interactive use
  AGENT_NODE_IDENTITY_PASSWORD   fallback identity unlock password

DEFAULTS:
  profile: .agent-node
  bind:    127.0.0.1
  port:    8787
"#
    );
}
