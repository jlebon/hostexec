// File-based command allowlist loaded at daemon startup.

use std::path::PathBuf;

use serde::Deserialize;
use tracing::{info, warn};

/// Persistent command allowlist loaded from
/// `$XDG_CONFIG_HOME/hostexec/allowlist.toml`.
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

impl Allowlist {
    /// Load the allowlist from the config file. Returns an empty allowlist if
    /// the file does not exist or cannot be parsed.
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self {
                entries: Vec::new(),
            };
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    entries: Vec::new(),
                };
            }
            Err(e) => {
                warn!(path = %path.display(), "cannot read allowlist: {e}");
                return Self {
                    entries: Vec::new(),
                };
            }
        };

        match toml::from_str::<AllowlistConfig>(&content) {
            Ok(config) => {
                info!(
                    path = %path.display(),
                    count = config.allow.len(),
                    "loaded allowlist"
                );
                Self {
                    entries: config.allow,
                }
            }
            Err(e) => {
                warn!(path = %path.display(), "cannot parse allowlist: {e}");
                Self {
                    entries: Vec::new(),
                }
            }
        }
    }

    /// Check whether the given command matches any allowlist entry.
    pub fn matches(&self, cmd: &[String]) -> bool {
        self.entries.iter().any(|entry| entry.matches(cmd))
    }
}

#[derive(Deserialize)]
struct AllowlistConfig {
    #[serde(default)]
    allow: Vec<AllowEntry>,
}

#[derive(Deserialize)]
struct AllowEntry {
    cmd: Vec<String>,
    #[serde(rename = "type")]
    match_type: MatchType,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum MatchType {
    Exact,
    Prefix,
}

impl AllowEntry {
    fn matches(&self, cmd: &[String]) -> bool {
        match self.match_type {
            MatchType::Exact => cmd == self.cmd.as_slice(),
            MatchType::Prefix => {
                cmd.len() >= self.cmd.len() && cmd[..self.cmd.len()] == self.cmd[..]
            }
        }
    }
}

fn config_path() -> Option<PathBuf> {
    let config_dir = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME")?;
            PathBuf::from(home).join(".config")
        }
    };
    Some(config_dir.join("hostexec").join("allowlist.toml"))
}
