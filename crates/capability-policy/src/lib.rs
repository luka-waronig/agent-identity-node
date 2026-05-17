use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::Path;

pub const POLICY_SCHEMA_VERSION: &str = "agent-node/v0alpha1";

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ToolContract {
    pub name: &'static str,
    pub description: &'static str,
    pub schema_payload: &'static str,
    pub permission_scope: &'static str,
}

pub const TOOL_CATALOG: [ToolContract; 3] = [
    ToolContract {
        name: "READ_FILE",
        description: "Read a UTF-8 text file from the node vault.",
        schema_payload: "A file name within the vault, such as notes.txt.",
        permission_scope: "vault:read",
    },
    ToolContract {
        name: "ARCHIVE_DATA",
        description: "Append a text artifact into the node vault.",
        schema_payload: "The text payload to archive.",
        permission_scope: "vault:write",
    },
    ToolContract {
        name: "SCAN_VAULT",
        description: "List visible files in the node vault.",
        schema_payload: "No payload required.",
        permission_scope: "vault:list",
    },
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPolicy {
    pub allowed_tools: Vec<String>,
    pub denied_tools: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastPolicy {
    pub allow_agent_broadcasts: bool,
    pub max_payload_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskPolicy {
    pub allow_announce: bool,
    pub allow_claim: bool,
    pub allow_complete: bool,
    pub allow_verify: bool,
    pub allowed_requested_roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultPolicy {
    pub vault_dir: String,
    pub allow_read: bool,
    pub allow_list: bool,
    pub allow_write: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderPolicy {
    pub allowed_providers: Vec<String>,
    pub allowed_models: Vec<String>,
    pub allow_local: bool,
    pub allow_cloud: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCapabilityPolicy {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub role: String,
    pub tool_policy: ToolPolicy,
    pub broadcast_policy: BroadcastPolicy,
    pub task_policy: TaskPolicy,
    pub vault_policy: VaultPolicy,
    pub provider_policy: ProviderPolicy,
}

impl NodeCapabilityPolicy {
    pub fn permissive_for_role(role: &str) -> Self {
        let normalized = normalize_role(role);
        Self {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            role: normalized.clone(),
            tool_policy: ToolPolicy {
                allowed_tools: TOOL_CATALOG
                    .iter()
                    .map(|tool| tool.name.to_string())
                    .collect(),
                denied_tools: Vec::new(),
            },
            broadcast_policy: BroadcastPolicy {
                allow_agent_broadcasts: true,
                max_payload_bytes: 32_768,
            },
            task_policy: TaskPolicy {
                allow_announce: true,
                allow_claim: true,
                allow_complete: true,
                allow_verify: false,
                allowed_requested_roles: vec![normalized.clone()],
            },
            vault_policy: VaultPolicy {
                vault_dir: format!("vault_{normalized}"),
                allow_read: true,
                allow_list: true,
                allow_write: true,
            },
            provider_policy: ProviderPolicy {
                allowed_providers: Vec::new(),
                allowed_models: Vec::new(),
                allow_local: true,
                allow_cloud: false,
            },
        }
    }

    pub fn locked_down(role: &str) -> Self {
        let normalized = normalize_role(role);
        Self {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            role: normalized.clone(),
            tool_policy: ToolPolicy {
                allowed_tools: Vec::new(),
                denied_tools: TOOL_CATALOG
                    .iter()
                    .map(|tool| tool.name.to_string())
                    .collect(),
            },
            broadcast_policy: BroadcastPolicy {
                allow_agent_broadcasts: false,
                max_payload_bytes: 0,
            },
            task_policy: TaskPolicy {
                allow_announce: false,
                allow_claim: false,
                allow_complete: false,
                allow_verify: false,
                allowed_requested_roles: vec![normalized.clone()],
            },
            vault_policy: VaultPolicy {
                vault_dir: format!("vault_{normalized}"),
                allow_read: false,
                allow_list: false,
                allow_write: false,
            },
            provider_policy: ProviderPolicy {
                allowed_providers: Vec::new(),
                allowed_models: Vec::new(),
                allow_local: false,
                allow_cloud: false,
            },
        }
    }
}

pub fn load_policy(
    path: Option<impl AsRef<Path>>,
    role: &str,
) -> Result<NodeCapabilityPolicy, Box<dyn Error>> {
    match path {
        Some(path) => {
            let raw = fs::read_to_string(path)?;
            let policy: NodeCapabilityPolicy = serde_json::from_str(&raw)?;
            Ok(policy)
        }
        None => Ok(NodeCapabilityPolicy::locked_down(role)),
    }
}

pub fn write_policy(
    path: impl AsRef<Path>,
    policy: &NodeCapabilityPolicy,
) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, serde_json::to_string_pretty(policy)?)?;
    Ok(())
}

pub fn requested_role_allowed(policy: &NodeCapabilityPolicy, requested_role: &str) -> bool {
    let requested = normalize_role(requested_role);
    if requested.is_empty() || policy.task_policy.allowed_requested_roles.is_empty() {
        return true;
    }

    policy
        .task_policy
        .allowed_requested_roles
        .iter()
        .any(|allowed| {
            let allowed = normalize_role(allowed);
            allowed == "any" || allowed == "all" || allowed == requested
        })
}

pub fn tool_allowed(policy: &NodeCapabilityPolicy, tool_name: &str) -> bool {
    let normalized = canonical_tool_name(tool_name);
    if policy
        .tool_policy
        .denied_tools
        .iter()
        .any(|entry| canonical_tool_name(entry) == normalized)
    {
        return false;
    }

    if !policy.tool_policy.allowed_tools.is_empty()
        && !policy
            .tool_policy
            .allowed_tools
            .iter()
            .any(|entry| canonical_tool_name(entry) == normalized)
    {
        return false;
    }

    match normalized.as_str() {
        "READ_FILE" => policy.vault_policy.allow_read,
        "SCAN_VAULT" => policy.vault_policy.allow_list,
        "ARCHIVE_DATA" => policy.vault_policy.allow_write,
        _ => false,
    }
}

pub fn effective_tool_catalog(policy: &NodeCapabilityPolicy) -> Vec<ToolContract> {
    TOOL_CATALOG
        .iter()
        .copied()
        .filter(|tool| tool_allowed(policy, tool.name))
        .collect()
}

fn default_schema_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

fn normalize_role(role: &str) -> String {
    role.trim().to_ascii_lowercase()
}

fn canonical_tool_name(name: &str) -> String {
    name.trim().to_ascii_uppercase().replace(['-', ' '], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_tools_override_allowed_tools() {
        let mut policy = NodeCapabilityPolicy::permissive_for_role("researcher");
        policy
            .tool_policy
            .denied_tools
            .push("read-file".to_string());
        assert!(!tool_allowed(&policy, "READ_FILE"));
    }

    #[test]
    fn vault_permissions_gate_tool_catalog() {
        let mut policy = NodeCapabilityPolicy::permissive_for_role("researcher");
        policy.vault_policy.allow_write = false;
        assert!(!tool_allowed(&policy, "ARCHIVE_DATA"));
        assert!(tool_allowed(&policy, "SCAN_VAULT"));
    }

    #[test]
    fn policy_round_trips_as_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        let policy = NodeCapabilityPolicy::permissive_for_role("researcher");
        write_policy(&path, &policy).unwrap();
        let loaded = load_policy(Some(&path), "ignored").unwrap();
        assert_eq!(loaded, policy);
    }
}
