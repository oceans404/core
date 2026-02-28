use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backups: Option<u32>,
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub vault_path: PathBuf,
    #[serde(default)]
    pub rpc: HashMap<String, String>,
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Config {
            vault_path: PathBuf::from(home).join(".lws"),
            rpc: HashMap::new(),
            plugins: HashMap::new(),
            backup: None,
        }
    }
}

impl Config {
    /// Look up an RPC URL by chain identifier.
    pub fn rpc_url(&self, chain: &str) -> Option<&str> {
        self.rpc.get(chain).map(|s| s.as_str())
    }

    /// Load config from a file path, or return defaults if file doesn't exist.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::LwsError> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let contents = std::fs::read_to_string(path).map_err(|e| crate::error::LwsError::InvalidInput {
            message: format!("failed to read config: {}", e),
        })?;
        serde_json::from_str(&contents).map_err(|e| crate::error::LwsError::InvalidInput {
            message: format!("failed to parse config: {}", e),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_vault_path() {
        let config = Config::default();
        let path_str = config.vault_path.to_string_lossy();
        assert!(path_str.ends_with(".lws"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let mut rpc = HashMap::new();
        rpc.insert("eip155:1".to_string(), "https://eth.rpc.example".to_string());

        let config = Config {
            vault_path: PathBuf::from("/home/test/.lws"),
            rpc,
            plugins: HashMap::new(),
            backup: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.vault_path, config2.vault_path);
        assert_eq!(config.rpc, config2.rpc);
    }

    #[test]
    fn test_rpc_lookup_hit() {
        let mut config = Config::default();
        config.rpc.insert(
            "eip155:1".to_string(),
            "https://eth.rpc.example".to_string(),
        );
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://eth.rpc.example")
        );
    }

    #[test]
    fn test_rpc_lookup_miss() {
        let config = Config::default();
        assert_eq!(config.rpc_url("eip155:999"), None);
    }

    #[test]
    fn test_optional_backup() {
        let config = Config::default();
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_none());
    }

    #[test]
    fn test_backup_config_serde() {
        let config = Config {
            vault_path: PathBuf::from("/tmp/.lws"),
            rpc: HashMap::new(),
            plugins: HashMap::new(),
            backup: Some(BackupConfig {
                path: PathBuf::from("/tmp/backup"),
                auto_backup: Some(true),
                max_backups: Some(5),
            }),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_some());
        assert_eq!(json["backup"]["auto_backup"], true);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(std::path::Path::new("/nonexistent/path/config.json")).unwrap();
        assert!(config.vault_path.to_string_lossy().ends_with(".lws"));
    }
}
