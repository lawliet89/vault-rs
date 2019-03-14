//! Implements the [`/sys/mounts`](https://www.vaultproject.io/api/system/mounts.html) endpoint
use std::collections::{HashMap, HashSet};

use crate::Error;

use serde::{Deserialize, Serialize};
use serde_json::map::Map;
use serde_json::Value;

/// Secrets Engine Mount
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct SecretEngine {
    /// Path to the secrets engine
    pub path: String,
    /// Type of secrets engine
    pub r#type: String,
    /// Specifies the human-friendly description of the mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Configuration options for the mounts
    pub config: Option<SecretsEngineConfig>,
}

/// Configuration options for secrets engines
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct SecretsEngineConfig {
    /// The default lease duration, specified as a string duration like "5s" or "30m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lease_ttl: Option<u64>,
    /// The maximum lease duration, specified as a string duration like "5s" or "30m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<u64>,
    /// Disable caching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_no_cache: Option<bool>,
    /// List of keys that will not be HMAC'd by audit devices in the request data object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_request_keys: Option<HashSet<String>>,
    /// List of keys that will not be HMAC'd by audit devices in the response data object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_response_keys: Option<HashSet<String>>,
    /// Specifies whether to show this mount in the UI-specific listing endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_visibility: Option<ListingVisibility>,
    /// List of headers to whitelist and pass from the request to the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_request_headers: Option<HashSet<String>>,
    /// List of headers to whitelist, allowing a plugin to include them in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_response_headers: Option<HashSet<String>>,
    /// Specifies mount type specific options that are passed to the backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,
    /// (Vault Enterprise) Specifies if the secrets engine is a local mount only.
    /// Local mounts are not replicated nor (if a secondary) removed by replication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    /// (Vault Enterprise) Enable seal wrapping for the mount,
    /// causing values stored by the mount to be wrapped by the seal's encryption capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_wrap: Option<bool>,
}

/// Tuning options for secrets engines
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct SecretsEngineTune {
    /// Specifies the human-friendly description of the mount.
    pub description: Option<String>,
    /// The default lease duration, specified as a string duration like "5s" or "30m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lease_ttl: Option<u64>,
    /// The maximum lease duration, specified as a string duration like "5s" or "30m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<u64>,
    /// List of keys that will not be HMAC'd by audit devices in the request data object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_request_keys: Option<HashSet<String>>,
    /// List of keys that will not be HMAC'd by audit devices in the response data object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_response_keys: Option<HashSet<String>>,
    /// Specifies whether to show this mount in the UI-specific listing endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_visibility: Option<ListingVisibility>,
    /// List of headers to whitelist and pass from the request to the plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_request_headers: Option<HashSet<String>>,
    /// List of headers to whitelist, allowing a plugin to include them in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_response_headers: Option<HashSet<String>>,
}

/// Specifies whether to show this mount in the UI-specific listing endpoint.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ListingVisibility {
    /// Always visible
    Unauth,
    /// Hidden
    Hidden,
}

/// Implements the [`/sys/mounts`](https://www.vaultproject.io/api/system/mounts.html) endpoint
pub trait Mounts {
    /// List all the mounted secrets engine
    fn list(&self) -> Result<HashMap<String, SecretEngine>, Error>;

    /// Enable a secrets Engine
    fn enable(&self, engine: &SecretEngine) -> Result<crate::Response, Error>;

    /// Disable a secrets engine
    fn disable(&self, path: &str) -> Result<crate::Response, Error>;

    /// Get the configuration for a mount
    fn get(&self, path: &str) -> Result<SecretsEngineConfig, Error>;

    /// Tune the configuration for a mount
    fn tune(&self, path: &str, config: &SecretsEngineTune) -> Result<crate::Response, Error>;
}

impl<T> Mounts for T
where
    T: crate::Vault,
{
    fn list(&self) -> Result<HashMap<String, SecretEngine>, Error> {
        let values: HashMap<String, Map<String, Value>> = self.get("sys/mounts")?.data()?;

        let values: Result<HashMap<String, SecretEngine>, Error> = values
            .into_iter()
            .map(|(path, mut map)| {
                // Let's trim the trailing slash
                let path = path.trim_end_matches('/').to_string();

                let _ = map.insert("path".to_string(), serde_json::Value::String(path.clone()));

                let value = Value::Object(map);
                let engine = serde_json::from_value(value)?;

                Ok((path, engine))
            })
            .collect();

        Ok(values?)
    }

    fn enable(&self, engine: &SecretEngine) -> Result<crate::Response, Error> {
        let mut value = serde_json::to_value(engine)?;
        let path = value["path"].take();
        let path = format!("sys/mounts/{}", path.as_str().expect("To be a string"));
        self.post(&path, &value, false)
    }

    fn disable(&self, path: &str) -> Result<crate::Response, Error> {
        let path = format!("sys/mounts/{}", path);
        self.delete(&path, false)
    }

    fn get(&self, path: &str) -> Result<SecretsEngineConfig, Error> {
        let path = format!("sys/mounts/{}/tune", path);
        self.get(&path)?.data()
    }

    fn tune(&self, path: &str, config: &SecretsEngineTune) -> Result<crate::Response, Error> {
        let path = format!("sys/mounts/{}/tune", path);
        self.post(&path, config, false)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::Vault;

    pub(crate) struct Mount<'a, T>
    where
        T: Vault,
    {
        pub(crate) path: String,
        pub(crate) client: &'a T,
    }

    impl<'a, T> Mount<'a, T>
    where
        T: Vault,
    {
        pub(crate) fn new(client: &'a T, config: &SecretEngine) -> Self {
            let response = Mounts::enable(&client, &config).unwrap();
            assert!(response.ok().unwrap().is_none());
            Mount {
                path: config.path.clone(),
                client,
            }
        }
    }

    impl<'a, T> Drop for Mount<'a, T>
    where
        T: Vault,
    {
        fn drop(&mut self) {
            let response = Mounts::disable(self.client, &self.path).unwrap();
            assert!(response.ok().unwrap().is_none());
        }
    }

    #[test]
    fn can_list_mounts() {
        let client = crate::tests::vault_client();
        let _ = Mounts::list(&client).unwrap();
    }

    #[test]
    fn can_mount_and_unmount_kv() {
        let client = crate::tests::vault_client();

        let path = crate::tests::uuid();
        let engine = SecretEngine {
            path: path.clone(),
            r#type: "kv".to_string(),
            ..Default::default()
        };
        let response = Mounts::enable(&client, &engine).unwrap();
        assert!(response.ok().unwrap().is_none());

        let mounts = Mounts::list(&client).unwrap();
        assert!(mounts.get(&path).is_some());

        // Config can be read back
        let _ = Mounts::get(&client, &path).unwrap();

        // Tune description
        let _ = Mounts::tune(
            &client,
            &path,
            &SecretsEngineTune {
                description: Some("hello world".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        let response = Mounts::disable(&client, &path).unwrap();
        assert!(response.ok().unwrap().is_none());

        let mounts = Mounts::list(&client).unwrap();
        assert!(mounts.get(&path).is_none());
    }
}
