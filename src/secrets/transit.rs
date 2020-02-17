//! Transit Secrets Engine
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/transit/index.html).
use crate::{Error, Response};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::map::Map;
use serde_json::Value;

#[derive(Serialize, Debug, Eq, PartialEq, Default)]
/// Parameters for creating a new Key
pub struct CreateKey {
    /// Specifies the name of the encryption key to create.
    pub name: String,
    /// If enabled, the key will support convergent encryption,
    /// where the same plaintext creates the same ciphertext.
    /// This requires derived to be set to true.
    /// When enabled, each encryption(/decryption/rewrap/datakey) operation
    /// will derive a nonce value rather than randomly generate it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergent_encryption: Option<bool>,
    /// Specifies if key derivation is to be used. If enabled,
    /// all encrypt/decrypt requests to this named key must provide a context
    /// which is used for key derivation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<bool>,
    /// Enables keys to be exportable. This allows for all the valid keys in the key ring
    /// to be exported. Once set, this cannot be disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    /// If set, enables taking backup of named key in the plaintext format.
    /// Once set, this cannot be disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    /// Specifies the type of key to create.
    pub r#type: KeyType,
}

/// Type of Key in the Transit Secrets Engine
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum KeyType {
    /// AES-256 wrapped with GCM using a 96-bit nonce size
    /// AEAD (symmetric, supports derivation and convergent encryption)
    #[serde(rename = "aes256-gcm96")]
    AES256GCM96,
    /// ChaCha20-Poly1305 AEAD (symmetric, supports derivation and convergent encryption)
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305AEAD,
    /// ED25519 (asymmetric, supports derivation). When using derivation, a sign operation with the
    /// same context will derive the same key and signature; this is a signing analogue to
    /// convergent_encryption.
    #[serde(rename = "ed25519")]
    ED25519,
    /// ECDSA using the P-256 elliptic curve (asymmetric)
    #[serde(rename = "ecdsa-p256")]
    EC256,
    /// RSA with bit size of 2048 (asymmetric)
    #[serde(rename = "rsa-2048")]
    RSA2048,
    /// RSA with bit size of 4096 (asymmetric)
    #[serde(rename = "rsa-4096")]
    RSA4096,
}

/// Transit Engine Key
#[derive(Deserialize, Debug, PartialEq, Default)]
pub struct Key {
    /// Specifies the name of the encryption key to create.
    pub name: String,
    /// Specifies if key derivation is to be used. If enabled,
    /// all encrypt/decrypt requests to this named key must provide a context
    /// which is used for key derivation.
    pub derived: bool,
    /// Enables keys to be exportable. This allows for all the valid keys in the key ring
    /// to be exported. Once set, this cannot be disabled.
    pub exportable: bool,
    /// If set, enables taking backup of named key in the plaintext format.
    /// Once set, this cannot be disabled.
    pub allow_plaintext_backup: bool,
    /// Specifies the type of key to create.
    pub r#type: KeyType,
    /// Whether they key can be deleted
    pub deletion_allowed: bool,
    /// List of key versions
    pub keys: HashMap<String, Value>,
    /// Minimum decryption version
    pub min_decryption_version: u64,
    /// Minimum encryption version
    pub min_encryption_version: u64,
    /// Key supports encryption
    pub supports_encryption: bool,
    /// Key supports decryption
    pub supports_decryption: bool,
    /// Key supports derivation
    pub supports_derivation: bool,
    /// Key supports signing
    pub supports_signing: bool,
}

#[derive(Serialize, Debug, Eq, PartialEq, Default)]
/// Parameters for Key Configuration
pub struct ConfigureKey {
    /// Specifies the minimum version of ciphertext allowed to be decrypted.
    /// Adjusting this as part of a key rotation policy can prevent old copies of
    /// ciphertext from being decrypted, should they fall into the wrong hands.
    /// For signatures, this value controls the minimum version of signature that can be
    /// verified against. For HMACs, this controls the minimum version of a key allowed to
    /// be used as the key for verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_decryption_version: Option<u64>,
    /// Specifies the minimum version of the key that can be used to encrypt plaintext,
    /// sign payloads, or generate HMACs. Must be 0 (which will use the latest version) or
    /// a value greater or equal to min_decryption_version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_encryption_version: Option<u64>,
    /// Specifies if the key is allowed to be deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_allowed: Option<bool>,
    /// Enables keys to be exportable. This allows for all the valid keys in the key ring to be
    /// exported. Once set, this cannot be disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    /// If set, enables taking backup of named key in the plaintext format.
    /// Once set, this cannot be disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
}

#[derive(Serialize, Debug, Eq, PartialEq, Default)]
/// A single item to be encrypted
pub struct EncryptPayload<'a, 'b, 'c> {
    /// Plaintext to be encrypted
    #[serde(serialize_with = "crate::utils::serialize_bytes")]
    pub plaintext: &'a [u8],
    /// Nonce, if any.
    /// This must be provided if convergent encryption is enabled for this key and the
    /// key was generated with Vault 0.6.1. Not required for keys created in 0.6.2+.
    /// The value must be exactly 96 bits (12 bytes) long and the user must ensure that for
    /// any given context (and thus, any given encryption key) this nonce value is never reused.
    #[serde(serialize_with = "crate::utils::serialize_option_bytes")]
    pub nonce: Option<&'b [u8]>,
    /// Context, if any. This is required if key derivation is enabled for this key.
    #[serde(serialize_with = "crate::utils::serialize_option_bytes")]
    pub context: Option<&'c [u8]>,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::AES256GCM96
    }
}

/// Transit Secrets Engine
///
/// See the [documentation](https://www.vaultproject.io/api/secret/transit/index.html).
pub trait Transit {
    /// Create a new named encryption key
    fn create_key(&self, path: &str, key: &CreateKey) -> Result<Response, Error>;
    /// Read a named key
    fn read_key(&self, path: &str, key: &str) -> Result<Key, Error>;
    /// List keys
    fn list_keys(&self, path: &str) -> Result<Vec<String>, Error>;
    /// Delete Key
    fn delete_key(&self, path: &str, key: &str) -> Result<Response, Error>;
    /// Update Key Configuration
    fn configure_key(
        &self,
        path: &str,
        key: &str,
        configuration: &ConfigureKey,
    ) -> Result<Response, Error>;
}

impl<T> Transit for T
where
    T: crate::Vault,
{
    fn create_key(&self, path: &str, key: &CreateKey) -> Result<Response, Error> {
        let mut values = serde_json::to_value(key)?;
        let name = values["name"].take();
        let path = format!("{}/keys/{}", path, name.as_str().expect("To be a string"));
        self.post(&path, &values, false)
    }

    fn read_key(&self, path: &str, key: &str) -> Result<Key, Error> {
        let path = format!("{}/keys/{}", path, key);
        self.get(&path)?.data()
    }

    fn list_keys(&self, path: &str) -> Result<Vec<String>, Error> {
        let path = format!("{}/keys", path);
        let data: Map<String, Value> = self.list(&path)?.data()?;
        let keys = data.get("keys").ok_or_else(|| Error::MalformedResponse)?;
        let keys = keys.as_array().ok_or_else(|| Error::MalformedResponse)?;
        let keys: Result<Vec<&str>, Error> = keys
            .iter()
            .map(|s| s.as_str().ok_or_else(|| Error::MalformedResponse))
            .collect();

        Ok(keys?.iter().map(|s| (*s).to_string()).collect())
    }

    fn delete_key(&self, path: &str, key: &str) -> Result<Response, Error> {
        let path = format!("{}/keys/{}", path, key);
        self.delete(&path, false)
    }

    fn configure_key(
        &self,
        path: &str,
        key: &str,
        configuration: &ConfigureKey,
    ) -> Result<Response, Error> {
        let path = format!("{}/keys/{}/config", path, key);
        self.post(&path, configuration, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mounts::tests::Mount;

    #[test]
    fn can_create_key() {
        let client = crate::tests::vault_client();

        let path = crate::tests::uuid_prefix("transit");
        let engine = crate::sys::mounts::SecretEngine {
            path: path.clone(),
            r#type: "transit".to_string(),
            ..Default::default()
        };

        let mount = Mount::new(&client, &engine);
        let create_key = CreateKey {
            name: "test".to_string(),
            r#type: KeyType::RSA4096,
            ..Default::default()
        };
        let response = Transit::create_key(&client, &mount.path, &create_key).unwrap();
        assert!(response.ok().unwrap().is_none());

        // Read key
        let _key = Transit::read_key(&client, &path, "test").unwrap();

        // List keys
        let keys = Transit::list_keys(&client, &path).unwrap();
        assert_eq!(vec!["test"], keys);
    }
}
