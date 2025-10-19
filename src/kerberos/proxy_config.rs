use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub socks_host: String,
    pub socks_port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socks_host: "127.0.0.1".to_string(),
            socks_port: 1080,
        }
    }
}

impl ProxyConfig {
    pub fn config_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".ironeye").join("proxy.conf")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if !path.exists() {
            return Self::default();
        }

        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => config,
                Err(_) => Self::default(),
            },
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::config_path();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;

        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get_host(&self) -> &str {
        &self.socks_host
    }

    pub fn get_port(&self) -> u16 {
        self.socks_port
    }
}
