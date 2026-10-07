//! `devices.json` parsing and validation.
//!
//! Drop-in compatible with Juniper/junos-mcp-server.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Shared input-validation helpers used by both `Inventory::validate`
/// (load-time) and `add_device::validate` (runtime). Keeping these in one
/// module guarantees the on-disk parser and the live-add API enforce the
/// same character classes (RJMCP-SEC-003).
pub(crate) mod validation {
    use std::path::Path;

    /// Device name: 1..=64 ASCII alnum + `_ . -`, never starting with `-`.
    pub fn is_valid_device_name(s: &str) -> bool {
        if s.is_empty() || s.len() > 64 || s.starts_with('-') {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// IPv4/IPv6 literal or RFC 1123 hostname (1..=253 chars; labels 1..=63
    /// of `[A-Za-z0-9-]`, no leading/trailing hyphen).
    pub fn is_valid_ip_or_hostname(s: &str) -> bool {
        if s.parse::<std::net::IpAddr>().is_ok() {
            return true;
        }
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    }

    /// SSH username: 1..=64 ASCII alnum + `_ . -`, must not start with `-`.
    /// The leading-dash rejection prevents the value from being interpreted
    /// as an SSH option flag (e.g. `-oProxyCommand=...`).
    pub fn is_valid_ssh_username(s: &str) -> bool {
        if s.is_empty() || s.len() > 64 || s.starts_with('-') {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    }

    /// SSH private-key path: non-empty, contains no NUL byte, and the
    /// rendered string form must not begin with `-` (same SSH-flag concern
    /// as usernames). Existence is checked separately by `Inventory::validate`.
    pub fn is_valid_auth_path(p: &Path) -> bool {
        let os = p.as_os_str();
        if os.is_empty() {
            return false;
        }
        // Reject embedded NUL — defends against unusual byte sequences in
        // path-like inputs.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            if os.as_bytes().contains(&0) {
                return false;
            }
        }
        if let Some(s) = p.to_str()
            && s.starts_with('-')
        {
            return false;
        }
        true
    }

    /// Environment variable name: 1..=128 ASCII uppercase alnum + `_`, not
    /// starting with a digit. Restrictive on purpose -- this name is never a
    /// secret, so there is no reason to accept the exotic byte sequences the
    /// path/username checks above must tolerate from real-world data.
    pub fn is_valid_env_var_name(s: &str) -> bool {
        if s.is_empty() || s.len() > 128 || s.starts_with(|c: char| c.is_ascii_digit()) {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;

        #[test]
        fn device_name_accepts_canonical_forms() {
            for ok in ["r1", "core-3", "user.name", "user_name", "vsrx-test10"] {
                assert!(is_valid_device_name(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn device_name_rejects_bad_forms() {
            for bad in [
                "",
                " ",
                "bad name",
                "evil; rm -rf /",
                "-leading-dash",
                "a/b",
                &"x".repeat(65),
            ] {
                assert!(!is_valid_device_name(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn ip_or_hostname_accepts_addr_and_hostname() {
            for ok in [
                "10.0.0.1",
                "127.0.0.1",
                "::1",
                "fe80::1",
                "router-3.example.net",
                "h",
            ] {
                assert!(is_valid_ip_or_hostname(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn ip_or_hostname_rejects_junk() {
            for bad in [
                "",
                "not an ip or host",
                "10.0.0.1; rm -rf /",
                "-bad.example",
                "bad-.example",
                ".",
                "a..b",
            ] {
                assert!(!is_valid_ip_or_hostname(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn ssh_username_accepts_typical_names() {
            for ok in ["admin", "netconf", "user.name", "user-name", "user_name"] {
                assert!(is_valid_ssh_username(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn ssh_username_rejects_leading_dash_and_spaces() {
            for bad in [
                "",
                " ",
                "-oProxyCommand=foo",
                "user with space",
                "user/name",
                &"x".repeat(65),
            ] {
                assert!(!is_valid_ssh_username(bad), "should reject: {bad:?}");
            }
        }

        #[test]
        fn auth_path_accepts_typical_paths() {
            assert!(is_valid_auth_path(&PathBuf::from("/etc/jmcp/keys/id")));
            assert!(is_valid_auth_path(&PathBuf::from("./key.pem")));
            assert!(is_valid_auth_path(&PathBuf::from("relative/path")));
        }

        #[test]
        fn auth_path_rejects_empty_or_leading_dash() {
            assert!(!is_valid_auth_path(&PathBuf::from("")));
            assert!(!is_valid_auth_path(&PathBuf::from("-evil")));
            assert!(!is_valid_auth_path(&PathBuf::from("-oProxyCommand=foo")));
        }

        #[test]
        fn env_var_name_accepts_canonical_forms() {
            for ok in ["R1_PASSWORD", "DEVICE_PW", "A", "A1_B2"] {
                assert!(is_valid_env_var_name(ok), "should accept: {ok}");
            }
        }

        #[test]
        fn env_var_name_rejects_bad_forms() {
            for bad in [
                "",
                "1LEADING_DIGIT",
                "lower_case",
                "has space",
                "has-dash",
                "has.dot",
                &"X".repeat(129),
            ] {
                assert!(!is_valid_env_var_name(bad), "should reject: {bad:?}");
            }
        }
    }
}

/// Device authentication method for NETCONF.
// Tagged enum mirroring the Python repo's `auth.type` discriminator for
// drop-in compatibility with Juniper/junos-mcp-server inventories.
// The `Debug` impl is hand-written to redact passwords.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Authenticate with a plaintext password. Supported for NETCONF; not
    /// supported for SCP-based file transfers.
    Password {
        /// Plaintext password for SSH authentication.
        password: String,
    },
    /// Authenticate with an SSH private key. Path is validated at inventory
    /// load time; the file must exist.
    SshKey {
        /// Path to the SSH private key file.
        private_key_path: PathBuf,
    },
    /// Authenticate with a plaintext password read from an environment
    /// variable at connect time, named by `password_env`. The variable name
    /// is validated at inventory load time; the variable itself is read
    /// fresh on every connection (not cached), so rotating it takes effect
    /// without a restart. Keeps the password out of `devices.json`, so an
    /// inventory file that leaks (backup, bug report, `git add .`) carries no
    /// credential, and out of argv entirely.
    PasswordEnv {
        /// Name of the environment variable holding the plaintext password.
        password_env: String,
    },
}

// Hand-written Debug to redact passwords. Never derive Debug on this enum.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"<redacted>")
                .finish(),
            Self::SshKey { private_key_path } => f
                .debug_struct("SshKey")
                .field("private_key_path", private_key_path)
                .finish(),
            Self::PasswordEnv { password_env } => f
                .debug_struct("PasswordEnv")
                .field("password_env", password_env)
                .finish(),
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn password_debug_does_not_leak_secret() {
        let auth = AuthConfig::Password {
            password: "hunter2".into(),
        };
        let s = format!("{auth:?}");
        assert!(
            !s.contains("hunter2"),
            "debug output leaked the password: {s}"
        );
        assert!(s.contains("redacted"));
    }

    #[test]
    fn ssh_key_debug_shows_path() {
        let auth = AuthConfig::SshKey {
            private_key_path: "/tmp/k.pem".into(),
        };
        let s = format!("{auth:?}");
        assert!(s.contains("/tmp/k.pem"));
    }

    #[test]
    fn deserialize_password() {
        let json = r#"{"type":"password","password":"x"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::Password { password } => assert_eq!(password, "x"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn deserialize_ssh_key() {
        let json = r#"{"type":"ssh_key","private_key_path":"/k.pem"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::SshKey { private_key_path } => {
                assert_eq!(private_key_path, std::path::PathBuf::from("/k.pem"))
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn password_env_debug_shows_var_name_not_value() {
        let auth = AuthConfig::PasswordEnv {
            password_env: "R1_PASSWORD".into(),
        };
        let s = format!("{auth:?}");
        assert!(s.contains("R1_PASSWORD"));
    }

    #[test]
    fn deserialize_password_env() {
        let json = r#"{"type":"password_env","password_env":"R1_PASSWORD"}"#;
        let parsed: AuthConfig = serde_json::from_str(json).unwrap();
        match parsed {
            AuthConfig::PasswordEnv { password_env } => {
                assert_eq!(password_env, "R1_PASSWORD")
            }
            _ => panic!("wrong variant"),
        }
    }
}

/// Blocklist rule action.
// Rules are evaluated most-specific-first (literal count tiebreak), then
// device rules win over defaults.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Block the input. Logged as a denied operation.
    Deny,
    /// Permit the input. Overrides a broader `Deny` rule.
    Allow,
}

/// Single blocklist rule as authored in `devices.json`.
// Compiled into a `CompiledRule<Action>` by `policy::build()`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuleSpec {
    /// `deny` or `allow`.
    pub action: Action,
    /// Glob pattern (e.g., `request system *`, `delete interfaces *`).
    pub pattern: String,
}

/// Which authorization model governs the `commands`/`pfe_commands` policy
/// domains: fail-closed allowlist (default) or fail-open blocklist (legacy).
/// Mirrors `mecmcp_policy::CommandMode`, which is chosen once per compiled
/// `Policy` — this key is therefore only meaningful on `_blocklist_defaults`;
/// setting it on a per-device `blocklist` is rejected at load time
/// (`policy::Policy::build` / `Inventory::validate`) rather than silently
/// ignored, so an operator can't believe they set a per-device mode that the
/// underlying engine has no way to honour.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommandModeConfig {
    /// Fail-closed: a command is denied unless it matches a literal
    /// token-prefix entry in `allow` (or `allowed_pipes` for stages after a
    /// `|`). This is the default when `mode` is absent and there are no
    /// legacy deny rules.
    Allowlist,
    /// Fail-open: the pre-MEC-92/93 behaviour. A command is denied only if it
    /// matches a `deny` glob rule; everything else is allowed. Kept for
    /// backward compatibility; see README.md for the migration path to
    /// `allowlist`.
    Blocklist,
}

/// Per-domain blocklist rules for a device or the global defaults.
// `commands` gates `execute_junos_command`, `config` gates
// `load_and_commit_config` (set-format only), and `pfe_commands` gates
// `execute_junos_pfe_command`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BlocklistRules {
    /// Rules for operational CLI commands. Defaults to empty. Only consulted
    /// under `mode: blocklist`.
    #[serde(default)]
    pub commands: Vec<RuleSpec>,
    /// Rules for configuration loads (set-format only). Defaults to empty.
    /// Always a fail-open blocklist; unaffected by `mode`.
    #[serde(default)]
    pub config: Vec<RuleSpec>,
    /// Rules for PFE commands. Defaults to empty. Only consulted under
    /// `mode: blocklist`.
    #[serde(default)]
    pub pfe_commands: Vec<RuleSpec>,
    /// Policy-wide command mode. Only valid on `_blocklist_defaults`; a
    /// per-device value is a load-time validation error (see
    /// `CommandModeConfig`). Defaults to `None`, meaning "infer at build
    /// time" (see `policy::Policy::build`'s migration logic).
    #[serde(default)]
    pub mode: Option<CommandModeConfig>,
    /// Token-prefix allowlist entries for the `commands` domain, consulted
    /// under `mode: allowlist`. Each entry is whitespace-tokenized and must
    /// match literal tokens — no globs (`*`, `?`, `[` are rejected at policy
    /// build time). Merged with `_blocklist_defaults.allow` the same way
    /// `commands` deny rules are merged: defaults ∪ this device's own list.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Token-prefix entries each `|`-separated pipe stage after the first
    /// must match, under `mode: allowlist`. Defaults to empty, so a config
    /// that doesn't set this refuses every piped command even if the first
    /// stage is allowlisted. Merged the same way as `allow`.
    #[serde(default)]
    pub allowed_pipes: Vec<String>,
    /// Token-prefix allowlist entries for the `pfe_commands` domain,
    /// consulted under `mode: allowlist`. Same matching/merge rules as
    /// `allow`, but independent of it — `execute_junos_pfe_command` is
    /// gated by this list, not `allow`. Defaults to empty, so a config that
    /// doesn't set this refuses every PFE command under allowlist mode
    /// (fail-closed).
    #[serde(default)]
    pub pfe_allow: Vec<String>,
    /// Token-prefix entries each `|`-separated pipe stage of a PFE command
    /// after the first must match, under `mode: allowlist`. Defaults to
    /// empty. Merged the same way as `allow`/`pfe_allow`.
    #[serde(default)]
    pub pfe_allowed_pipes: Vec<String>,
}

fn default_port() -> u16 {
    22
}

/// Single device entry from `devices.json`.
///
/// Validated at load time: `ip` must be an IPv4/IPv6 address or RFC 1123
/// hostname; `port` in 1..=65535; `username` is 1-64 ASCII alphanumeric +
/// `_.-`, no leading hyphen; `private_key_path` (if SSH key auth) must exist
/// on disk. Optional `ssh_config` is loaded for ProxyJump/ProxyCommand; all
/// other connection parameters come from this entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceEntry {
    /// IPv4/IPv6 address or RFC 1123 hostname.
    pub ip: String,
    /// SSH port. Defaults to 22.
    #[serde(default = "default_port")]
    pub port: u16,
    /// SSH username. 1-64 ASCII alphanumeric + `_.-`, no leading hyphen.
    pub username: String,
    /// Authentication method (password or SSH key).
    pub auth: AuthConfig,
    /// Optional SSH config file for ProxyJump/ProxyCommand. When set, `ip` is
    /// used as the alias to look up proxy settings. Connection parameters
    /// (`ip`, `port`, `username`, `auth`) from this entry override the file.
    #[serde(default)]
    pub ssh_config: Option<PathBuf>,
    /// Per-device blocklist rules. Merged with `_blocklist_defaults` at
    /// policy build time.
    #[serde(default)]
    pub blocklist: Option<BlocklistRules>,
    /// Configuration authority: which management plane owns this device's config.
    ///
    /// Defaults to `Unknown` when unset so the audit trail can distinguish
    /// "unset" from "explicitly declared local". Operations treat `Unknown` as
    /// local for behaviour (writes are not refused), but the audit event
    /// records the distinction.
    ///
    /// See RustJunosMCP#292 and mecmcp#256.
    #[serde(default)]
    pub config_authority: crate::config_authority::JunosAuthority,
    /// Declared logins the owning plane's own commit sessions use on this
    /// device (MEC-1880, P5b). Used only by the commit-0 attribution
    /// classifier that gates a guarded `rollback_source: 1` on a plane-owned
    /// device.
    ///
    /// Absent or empty always classifies commit 0 as `ambiguous` — this field
    /// is never inferred from device behaviour, only declared by the operator.
    #[serde(default)]
    pub plane_commit_logins: Vec<String>,
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn parses_password_entry_with_default_port() {
        let json = r#"{
            "ip":"10.0.0.1",
            "username":"admin",
            "auth":{"type":"password","password":"x"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.ip, "10.0.0.1");
        assert_eq!(e.port, 22);
        assert_eq!(e.username, "admin");
        assert!(e.ssh_config.is_none());
    }

    #[test]
    fn parses_ssh_key_entry_with_explicit_port_and_ssh_config() {
        let json = r#"{
            "ip":"10.0.0.2",
            "port":830,
            "username":"netconf",
            "ssh_config":"/home/u/.ssh/config_jh",
            "auth":{"type":"ssh_key","private_key_path":"/k.pem"}
        }"#;
        let e: DeviceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.port, 830);
        assert_eq!(e.ssh_config, Some(PathBuf::from("/home/u/.ssh/config_jh")));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{"username":"admin","auth":{"type":"password","password":"x"}}"#;
        let r: Result<DeviceEntry, _> = serde_json::from_str(json);
        assert!(r.is_err(), "expected error for missing 'ip'");
    }
}

use crate::error::JmcpError;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Parsed and validated Junos device inventory.
///
/// Wraps `mecmcp-inventory::FileInventory<DeviceEntry, BlocklistRules>` and
/// adds Junos-specific validation (SSH username/key-path character classes,
/// port range, key-file existence). The flat-map schema with
/// `_blocklist_defaults` is parsed by the shared crate; the validators here
/// encode SSH and Junos rules the shared crate does not know.
#[derive(Debug, Clone)]
pub struct Inventory {
    devices: HashMap<String, DeviceEntry>,
    blocklist_defaults: Option<BlocklistRules>,
    source_path: PathBuf,
}

impl Inventory {
    /// Empty inventory with no devices. For tests that do not need real devices.
    pub fn empty() -> Self {
        Self {
            devices: Default::default(),
            blocklist_defaults: None,
            source_path: PathBuf::new(),
        }
    }

    /// Load and validate `devices.json` from disk.
    ///
    /// Parsing is delegated to `mecmcp-inventory::FileInventory`, which handles
    /// the flat-map schema (top-level keys are device names, plus the special
    /// `_blocklist_defaults` policy key). Junos-specific validators then check
    /// SSH username/key-path character classes, port ranges, and key-file
    /// existence. Returns `InventoryInvalid` if parsing fails or any device
    /// entry is malformed.
    pub fn load(path: &Path) -> Result<Self, JmcpError> {
        use mecmcp_inventory::Inventory as _;

        let shared = mecmcp_inventory::FileInventory::<DeviceEntry, BlocklistRules>::load(path)
            .map_err(|error| JmcpError::InventoryInvalid(error.to_string()))?;

        let devices: HashMap<String, DeviceEntry> = shared
            .names()
            .into_iter()
            .map(|name| {
                let entry = shared
                    .get(&name)
                    .map_err(|error| JmcpError::InventoryInvalid(error.to_string()))?;
                Ok((name, entry))
            })
            .collect::<Result<_, JmcpError>>()?;

        Self::validate(&devices)?;

        Ok(Self {
            devices,
            blocklist_defaults: shared.policy(),
            source_path: path.to_path_buf(),
        })
    }

    fn validate(devices: &HashMap<String, DeviceEntry>) -> Result<(), JmcpError> {
        use validation::*;
        for (name, entry) in devices {
            if !is_valid_device_name(name) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': name is invalid (must match ^[A-Za-z0-9_.-]{{1,64}}$, no leading '-')"
                )));
            }
            if !is_valid_ip_or_hostname(&entry.ip) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': ip/hostname is invalid"
                )));
            }
            if entry.port == 0 {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': port must be non-zero"
                )));
            }
            if !is_valid_ssh_username(&entry.username) {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': username is invalid (must match ^[A-Za-z0-9_.-]{{1,64}}$, no leading '-')"
                )));
            }
            if let AuthConfig::SshKey { private_key_path } = &entry.auth {
                if !is_valid_auth_path(private_key_path) {
                    return Err(JmcpError::InventoryInvalid(format!(
                        "router '{name}': private_key_path is invalid (empty, contains NUL, or starts with '-')"
                    )));
                }
                if !private_key_path.exists() {
                    return Err(JmcpError::KeyFileMissing(private_key_path.clone()));
                }
            }
            if let AuthConfig::PasswordEnv { password_env } = &entry.auth
                && !is_valid_env_var_name(password_env)
            {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': password_env is invalid (1-128 ASCII uppercase \
                     alnum/underscore, must not start with a digit)"
                )));
            }
            // `mode` selects the fail-open/fail-closed command engine for the
            // whole policy (mecmcp_policy::CommandMode is chosen once per
            // compiled Policy, not per device); a per-device value has no way
            // to be honoured, so reject it here rather than silently
            // discarding it and letting an operator believe they set
            // something that took effect.
            if let Some(bl) = &entry.blocklist
                && bl.mode.is_some()
            {
                return Err(JmcpError::InventoryInvalid(format!(
                    "router '{name}': blocklist.mode is not allowed on a per-device blocklist; \
                     'mode' is policy-wide and must be set only in _blocklist_defaults"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::io::Write;

    fn write(name: &str, json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .prefix(name)
            .suffix(".json")
            .tempfile()
            .unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    #[test]
    fn loads_valid_password_only_inventory() {
        let f = write(
            "ok",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_zero_port() {
        let f = write(
            "p0",
            r#"{
            "r1":{"ip":"1.2.3.4","port":0,"username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_empty_ip() {
        let f = write(
            "ip",
            r#"{
            "r1":{"ip":"","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_device_name_with_space() {
        let f = write(
            "badname",
            r#"{
            "bad name":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_ip_with_shell_metacharacters() {
        let f = write(
            "shellip",
            r#"{
            "r1":{"ip":"10.0.0.1; rm -rf /","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_username_starting_with_dash() {
        let f = write(
            "badusr",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"-oProxyCommand=foo","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_username_with_space() {
        let f = write(
            "spcusr",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"user with space","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn rejects_private_key_path_starting_with_dash() {
        // A `private_key_path` whose rendered string starts with `-` could be
        // mis-parsed by ssh/scp as a CLI flag (e.g. `-oProxyCommand=...`).
        // Validation must reject before any existence check.
        let json = r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                   "auth":{"type":"ssh_key","private_key_path":"-oProxyCommand=foo"}}
        }"#;
        let f = write("dashkey", json);
        let r = Inventory::load(f.path());
        assert!(
            matches!(r, Err(JmcpError::InventoryInvalid(ref s)) if s.contains("private_key_path")),
            "expected InventoryInvalid for leading-dash path, got {r:?}"
        );
    }

    #[test]
    fn accepts_typical_usernames() {
        for name in ["admin", "netconf", "user.name", "user-name", "user_name"] {
            let json = format!(
                r#"{{"r1":{{"ip":"1.2.3.4","username":"{name}","auth":{{"type":"password","password":"x"}}}}}}"#,
            );
            let f = write("u", &json);
            let inv = Inventory::load(f.path());
            assert!(inv.is_ok(), "expected '{name}' accepted, got {inv:?}");
        }
    }

    #[test]
    fn rejects_missing_key_file() {
        let f = write(
            "missing",
            r#"{
            "r1":{"ip":"1.2.3.4","username":"u",
                  "auth":{"type":"ssh_key","private_key_path":"/nope/missing.pem"}}
        }"#,
        );
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::KeyFileMissing(_))));
    }

    #[test]
    fn accepts_existing_key_file() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(
            r#"{{
            "r1":{{"ip":"1.2.3.4","username":"u",
                   "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}
        }}"#,
            key.path().display()
        );
        let f = write("withkey", &json);
        let inv = Inventory::load(f.path()).unwrap();
        assert_eq!(inv.devices.len(), 1);
    }

    #[test]
    fn rejects_invalid_json() {
        let f = write("bad", "{not json");
        let r = Inventory::load(f.path());
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(_))));
    }

    #[test]
    fn loads_inventory_with_blocklist_defaults_and_per_device_blocklist() {
        let f = write(
            "bl",
            r#"{
                "_blocklist_defaults": {
                    "commands": [
                        {"action":"deny","pattern":"request system *"}
                    ],
                    "config": [
                        {"action":"deny","pattern":"delete *"}
                    ]
                },
                "r1": {
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "commands": [
                            {"action":"allow","pattern":"request system reboot"}
                        ]
                    }
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let defaults = inv.blocklist_defaults().expect("defaults present");
        assert_eq!(defaults.commands.len(), 1);
        assert_eq!(defaults.config.len(), 1);
        let r1 = inv.get("r1").unwrap();
        let r1_bl = r1.blocklist.as_ref().expect("r1 has blocklist");
        assert_eq!(r1_bl.commands.len(), 1);
        assert!(r1_bl.config.is_empty());
    }

    #[test]
    fn v0_1_inventory_without_blocklist_loads_unchanged() {
        let f = write(
            "v01",
            r#"{
                "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert!(inv.blocklist_defaults().is_none());
        assert!(inv.get("r1").unwrap().blocklist.is_none());
    }

    #[test]
    fn missing_blocklist_subkeys_default_to_empty() {
        let f = write(
            "empty",
            r#"{
                "_blocklist_defaults": {},
                "r1":{
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {}
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let d = inv.blocklist_defaults().unwrap();
        assert!(d.commands.is_empty() && d.config.is_empty());
        let r1bl = inv.get("r1").unwrap().blocklist.as_ref().unwrap();
        assert!(r1bl.commands.is_empty() && r1bl.config.is_empty());
    }

    #[test]
    fn loads_inventory_with_pfe_commands() {
        let f = write(
            "pfe",
            r#"{
                "_blocklist_defaults": {
                    "pfe_commands": [{"action":"deny","pattern":"set *"}]
                },
                "r1": {
                    "ip":"1.2.3.4","username":"u",
                    "auth":{"type":"password","password":"x"},
                    "blocklist": {
                        "pfe_commands": [{"action":"allow","pattern":"set debug *"}]
                    }
                }
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        let d = inv.blocklist_defaults().expect("defaults present");
        assert_eq!(d.pfe_commands.len(), 1);
        assert_eq!(d.pfe_commands[0].pattern, "set *");
        let r1bl = inv.get("r1").unwrap().blocklist.as_ref().unwrap();
        assert_eq!(r1bl.pfe_commands.len(), 1);
        assert_eq!(r1bl.pfe_commands[0].pattern, "set debug *");
    }

    #[test]
    fn missing_pfe_commands_defaults_to_empty() {
        let f = write(
            "no_pfe",
            r#"{
                "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"x"}]},
                "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let inv = Inventory::load(f.path()).unwrap();
        assert!(inv.blocklist_defaults().unwrap().pfe_commands.is_empty());
    }

    /// Backward compatibility: devices.json without config_authority must load
    /// unchanged. This is a hard constraint because LXC 600 and 609 (609 is tagged
    /// `protected` with 34 devices) have deployed inventory files without this field.
    ///
    /// This test must fail before the serde default is added, then pass after.
    #[test]
    fn v0_17_inventory_without_config_authority_loads_unchanged() {
        // Representative v0.17 inventory: no config_authority field.
        let f = write(
            "v017",
            r#"{
                "r1":{"ip":"1.2.3.4","username":"u","auth":{"type":"password","password":"x"}},
                "r2":{"ip":"1.2.3.5","port":830,"username":"admin","auth":{"type":"ssh_key","private_key_path":"/tmp/k.pem"}}
            }"#,
        );
        // Create a temporary key file so the ssh_key auth validates.
        std::fs::write("/tmp/k.pem", "dummy").expect("failed to write temp key");

        let inv = Inventory::load(f.path()).expect("v0.17 inventory must load");

        // Both devices loaded.
        assert_eq!(inv.len(), 2);
        assert!(inv.get("r1").is_ok());
        assert!(inv.get("r2").is_ok());

        // The field must have a serde default so the absence is not a parse error.
        // The default must be Unknown (not Local) to distinguish "unset" from "local" in audit.
        let r1 = inv.get("r1").unwrap();
        assert_eq!(
            r1.config_authority,
            crate::config_authority::JunosAuthority::Unknown
        );

        // Clean up temp key.
        let _ = std::fs::remove_file("/tmp/k.pem");
    }
}

impl Inventory {
    /// Look up a device by name. Returns `UnknownRouter` if not found.
    pub fn get(&self, name: &str) -> Result<&DeviceEntry, JmcpError> {
        self.devices
            .get(name)
            .ok_or_else(|| JmcpError::UnknownRouter(name.to_string()))
    }

    /// Alphabetically sorted list of device names. Used by `get_router_list`.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.devices.keys().cloned().collect();
        names.sort();
        names
    }

    /// Path from which this inventory was loaded. Used by `reload_devices` and
    /// `add_device` for CAS checks.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Global blocklist rules from `_blocklist_defaults`, if present. Merged
    /// with each device's per-device rules at policy build time.
    pub fn blocklist_defaults(&self) -> Option<&BlocklistRules> {
        self.blocklist_defaults.as_ref()
    }

    /// Number of devices in this inventory.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True if this inventory contains no devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// True if the named device exists in this inventory. Used server-side to
    /// classify tool errors (unknown device vs. out-of-scope) for observability
    /// logging without leaking inventory to the caller.
    pub fn contains_router(&self, name: &str) -> bool {
        self.devices.contains_key(name)
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;
    use std::io::Write;

    fn build(json: &str) -> Inventory {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Inventory::load(f.path()).unwrap()
    }

    #[test]
    fn get_returns_known_router() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert_eq!(inv.get("r1").unwrap().ip, "1.1.1.1");
    }

    #[test]
    fn get_returns_unknown_router_error() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        let r = inv.get("nope");
        assert!(matches!(r, Err(JmcpError::UnknownRouter(ref s)) if s == "nope"));
    }

    #[test]
    fn names_returns_sorted() {
        let inv = build(
            r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert_eq!(inv.names(), vec!["a".to_string(), "z".to_string()]);
    }

    #[test]
    fn contains_router_returns_true_for_present() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert!(inv.contains_router("r1"));
    }

    #[test]
    fn contains_router_returns_false_for_absent() {
        let inv = build(
            r#"{
            "r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}
        }"#,
        );
        assert!(!inv.contains_router("nope"));
    }
}

#[cfg(test)]
mod rule_type_tests {
    use super::*;

    #[test]
    fn rule_spec_parses_deny() {
        let json = r#"{"action":"deny","pattern":"request system *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert_eq!(r.pattern, "request system *");
        assert!(matches!(r.action, Action::Deny));
    }

    #[test]
    fn rule_spec_parses_allow() {
        let json = r#"{"action":"allow","pattern":"show *"}"#;
        let r: RuleSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(r.action, Action::Allow));
    }

    #[test]
    fn rule_spec_rejects_unknown_action() {
        let json = r#"{"action":"audit","pattern":"x"}"#;
        let r: Result<RuleSpec, _> = serde_json::from_str(json);
        assert!(r.is_err());
    }

    #[test]
    fn blocklist_rules_default_to_empty_lists() {
        let json = r#"{}"#;
        let b: BlocklistRules = serde_json::from_str(json).unwrap();
        assert!(b.commands.is_empty());
        assert!(b.config.is_empty());
        assert!(b.pfe_commands.is_empty());
    }
}

/// Insert a device into a JSON-shaped inventory, preserving key order.
///
/// Used by `add_device` to build the updated inventory before writing it back
/// to disk. Returns the modified `Value`. Fails with `DeviceExists` if `name`
/// is already present.
///
/// Handles both accepted inventory shapes. A bare map takes the device as a
/// top-level key; the canonical envelope -- `{"version": 1, "devices": {...}}`
/// -- takes it inside `devices`. Writing a top-level key into an envelope would
/// put it beside `version` and `devices`, and `mecmcp-inventory` refuses
/// unknown top-level keys once it has identified the shape, so the file would
/// be written and then be unreadable at the next start. The add would report a
/// failure having already corrupted the inventory on disk.
pub fn insert_device(
    inv: &serde_json::Value,
    name: &str,
    ip: &str,
    port: u32,
    username: &str,
    auth: &AuthConfig,
) -> Result<serde_json::Value, JmcpError> {
    let mut out = inv.clone();
    let entry = serde_json::json!({
        "ip": ip,
        "port": port,
        "username": username,
        "auth": auth,
    });

    // An envelope is identified by a `devices` key. When it holds an object the
    // devices live inside it. When it holds anything else -- notably the legacy
    // array envelope `{"version": 1, "devices": [...]}`, which the loader also
    // accepts -- there is no key-shaped slot to add to, and writing a top-level
    // key would put it beside `version` and `devices` and make the file
    // unreadable. Refuse instead of corrupting it: an inventory this tool
    // cannot extend safely is one a human should edit.
    let target = match out.as_object_mut() {
        Some(obj) => match obj.get("devices") {
            Some(serde_json::Value::Object(_)) => obj
                .get_mut("devices")
                .and_then(serde_json::Value::as_object_mut),
            Some(_) => {
                return Err(JmcpError::InventoryParse(
                    "this inventory keeps its devices in a form add_device cannot extend \
                     (`devices` is present but is not an object); add the device by editing \
                     the file directly"
                        .into(),
                ));
            }
            None => Some(obj),
        },
        None => None,
    };

    let inserted = if let Some(obj) = target {
        if obj.contains_key(name) {
            return Err(JmcpError::DeviceExists(name.to_string()));
        }
        obj.insert(name.to_string(), entry);
        true
    } else {
        false
    };

    if !inserted {
        return Err(JmcpError::InventoryParse(
            "top-level inventory is not a JSON object".into(),
        ));
    }
    Ok(out)
}

/// SHA-256 digest of the file at `path`, or all-zeros if it does not exist.
///
/// Used by `add_device` and `reload_devices` for CAS checks. The all-zero
/// sentinel cannot collide with a real SHA-256 digest (statistically
/// infeasible), so callers can treat it as "no last-known content" and detect
/// TOCTOU races.
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest);
            Ok(out)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok([0u8; 32]),
        Err(e) => Err(e),
    }
}

/// Write `value` (pretty-printed + trailing newline) to a temp file in the
/// same directory as `path`, sync it, and return it without renaming it into
/// place. Preserves `path`'s existing file mode bits on Unix. Accepts an
/// arbitrary `serde_json::Value` rather than a typed struct so callers can
/// preserve unknown top-level keys (`_blocklist_defaults`, future extensions).
///
/// Lets a caller validate the staged content (e.g. re-parse it and rebuild
/// the policy from it) before committing with [`NamedTempFile::persist`], so
/// a validation failure never touches the file at `path`.
pub fn stage_atomic(
    path: &Path,
    value: &serde_json::Value,
) -> std::io::Result<tempfile::NamedTempFile> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inventory path has no parent directory",
        )
    })?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("parent directory does not exist: {}", parent.display()),
        ));
    }
    let resolved_parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };

    let mut tmp = tempfile::NamedTempFile::new_in(resolved_parent)?;
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tmp.write_all(pretty.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;

    // Preserve mode bits if the target already exists.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }

    Ok(tmp)
}

/// Atomically write JSON to disk via same-filesystem rename.
///
/// Stages `value` via [`stage_atomic`] and immediately persists it over
/// `path` with no validation step. Used by callers that have already
/// validated `value` is well-formed, or do not need to.
pub fn write_atomic(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let tmp = stage_atomic(path, value)?;
    // Surface the underlying io::Error from rename(2) (EXDEV, EACCES, ENOSPC,
    // …) untouched rather than stringifying through PersistError.
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod write_tests {
    use super::*;

    fn fixture(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn atomic_write_replaces_file_in_place() {
        let f = fixture(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let new_content = serde_json::json!({
            "r2": {"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}}
        });
        write_atomic(f.path(), &new_content).unwrap();
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("r2").is_some());
        assert!(on_disk.get("r1").is_none());
    }

    #[test]
    fn atomic_write_preserves_blocklist_defaults() {
        let original = serde_json::json!({
            "_blocklist_defaults": {"commands":[{"action":"deny","pattern":"request system reboot"}]},
            "r1": {"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}
        });
        let f = fixture(&serde_json::to_string(&original).unwrap());

        let mut updated = original.clone();
        updated["r2"] = serde_json::json!({
            "ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}
        });

        write_atomic(f.path(), &updated).unwrap();

        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(f.path()).unwrap()).unwrap();
        assert!(on_disk.get("_blocklist_defaults").is_some());
        assert!(on_disk.get("r1").is_some());
        assert!(on_disk.get("r2").is_some());
    }

    #[test]
    fn atomic_write_preserves_key_order() {
        // Requires serde_json's `preserve_order` feature; verify by building
        // the input map in insertion order and checking on-disk byte order.
        let mut map = serde_json::Map::new();
        map.insert("first".into(), serde_json::json!({"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}));
        map.insert("second".into(), serde_json::json!({"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}));
        let val = serde_json::Value::Object(map);
        let f = tempfile::NamedTempFile::new().unwrap();
        write_atomic(f.path(), &val).unwrap();
        let bytes = std::fs::read(f.path()).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.find("\"first\"").unwrap() < s.find("\"second\"").unwrap());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod envelope_insert_tests {
    use super::*;

    fn auth() -> AuthConfig {
        AuthConfig::Password {
            password: "x".to_owned(),
        }
    }

    /// The canonical envelope must take the device inside `devices`.
    ///
    /// Written as a top-level key it lands beside `version` and `devices`, and
    /// `mecmcp-inventory` refuses unknown top-level keys once it has identified
    /// the shape -- so `add_device` would write the file and then find it
    /// unreadable, reporting a failure having already corrupted the inventory.
    #[test]
    fn an_envelope_inventory_takes_the_device_under_devices() {
        let inv: serde_json::Value = serde_json::from_str(
            r#"{"version":1,"devices":{"core-1":{"ip":"10.0.0.1","port":22,"username":"u","auth":{"type":"password","password":"x"}}}}"#,
        )
        .unwrap();

        let out = insert_device(&inv, "core-2", "10.0.0.2", 22, "u", &auth()).unwrap();

        let top = out.as_object().unwrap();
        assert_eq!(
            top.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["version", "devices"],
            "the envelope must gain no new top-level key: {out}"
        );
        assert!(
            out["devices"].get("core-2").is_some(),
            "the device belongs under `devices`: {out}"
        );
        assert!(
            out["devices"].get("core-1").is_some(),
            "the existing device must survive: {out}"
        );

        // The written file has to still load. This is the assertion the bug
        // would have failed, and it is why the shape check exists at all:
        // `add_device` writes, then reloads, so a file it corrupts is a file it
        // has already put on disk.
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_string(&out).unwrap()).unwrap();
        Inventory::load(file.path()).expect("an inventory this tool wrote must still be readable");
    }

    /// A bare map keeps taking the device as a top-level key.
    #[test]
    fn a_bare_map_inventory_still_takes_a_top_level_key() {
        let inv: serde_json::Value = serde_json::from_str(
            r#"{"core-1":{"ip":"10.0.0.1","port":22,"username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();

        let out = insert_device(&inv, "core-2", "10.0.0.2", 22, "u", &auth()).unwrap();
        assert!(out.get("core-2").is_some(), "bare map insert: {out}");
        assert!(out.get("core-1").is_some(), "existing device kept: {out}");
    }

    /// The legacy array envelope is refused rather than corrupted.
    ///
    /// `{"version": 1, "devices": [...]}` is a shape the loader accepts, and it
    /// has no key-shaped slot to add to. Writing a top-level key would put the
    /// device beside `version` and `devices`, and the file would not load
    /// again -- so this refuses before writing anything.
    #[test]
    fn a_legacy_array_envelope_is_refused_not_corrupted() {
        let inv: serde_json::Value =
            serde_json::from_str(r#"{"version":1,"devices":[{"name":"core-1"}]}"#).unwrap();

        let error = insert_device(&inv, "core-2", "10.0.0.2", 22, "u", &auth())
            .expect_err("an array envelope cannot be extended by key");
        assert!(
            matches!(&error, JmcpError::InventoryParse(message) if message.contains("devices")),
            "the refusal must explain the shape: {error}"
        );
    }

    /// A duplicate inside the envelope is still a duplicate.
    #[test]
    fn an_envelope_duplicate_is_refused() {
        let inv: serde_json::Value = serde_json::from_str(
            r#"{"version":1,"devices":{"core-1":{"ip":"10.0.0.1","port":22,"username":"u","auth":{"type":"password","password":"x"}}}}"#,
        )
        .unwrap();

        let error = insert_device(&inv, "core-1", "10.0.0.9", 22, "u", &auth())
            .expect_err("a device already in the envelope must not be added twice");
        assert!(
            matches!(error, JmcpError::DeviceExists(name) if name == "core-1"),
            "the refusal must name the device"
        );
    }
}
