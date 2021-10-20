//! AWS Secrets Engine
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).
use crate::{Error, LeasedData, Response};

use async_trait::async_trait;
use reqwest::Method;
use serde::{Deserialize, Serialize};

/// Parameters for configuring the Root credentials for the AWS Secrets Engine
#[derive(Serialize, Debug, Eq, PartialEq)]
pub struct RootCredentials {
    /// Number of max retries the client should use for recoverable errors.
    /// The default (-1) falls back to the AWS SDK's default behavior.
    #[serde(default = "default_max_retries")]
    pub max_retries: i64,
    /// Specifies the AWS access key ID.
    pub access_key: String,
    /// Specifies the AWS secret access key.
    pub secret_key: String,
    /// Specifies the AWS region. If not set it will use the AWS_REGION env var, AWS_DEFAULT_REGION
    /// env var, or us-east-1 in that order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Specifies a custom HTTP IAM endpoint to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_endpoint: Option<String>,
    /// Specifies a custom HTTP STS endpoint to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_endpoint: Option<String>,
}

/// Parameters for configuring the lease for the AWS Secrets Engine
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Lease {
    /// Specifies the lease value provided as a string duration with time suffix. "h" (hour) is
    /// the largest suffix.
    pub lease: String,
    /// Specifies the maximum lease value provided as a string duration with time suffix. "h"
    /// (hour) is the largest suffix.
    pub lease_max: String,
}

/// AWS Secrets Engine Role
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct Role {}

/// Request to Generate Credentials
#[derive(Serialize, Debug, Eq, PartialEq, Default)]
pub struct CredentialsRequest {
    /// The ARN of the role to assume if credential_type on the Vault role is assumed_role.
    /// Must match one of the allowed role ARNs in the Vault role. Optional if the Vault role
    /// only allows a single AWS role ARN; required otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    /// Specifies the TTL for the use of the STS token. This is specified as a string with a
    /// duration suffix. Valid only when credential_type is assumed_role or federation_token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

/// Credentials Returned from Vault
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct Credentials {
    /// AWS Access Key
    pub access_key: String,
    /// AWS Secret Key
    pub secret_key: String,
    /// AWS Security Token, if any
    #[serde(default)]
    pub security_token: Option<String>,
}

/// AWS Secrets Engine
///
/// See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).
#[async_trait]
pub trait Aws {
    /// Configure the Root IAM Credentials that Vault uses to communicate with AWS
    async fn configure_root(&self, path: &str, config: &RootCredentials)
        -> Result<Response, Error>;
    /// Rotate Root IAM Credentials
    ///
    /// See [warnings](https://www.vaultproject.io/api/secret/aws/index.html#rotate-root-iam-credentials)
    /// on Vault's documentation
    async fn rotate_root(&self, path: &str) -> Result<Response, Error>;
    /// Configures the lease for the AWS Secrets Engine
    async fn configure_lease(&self, path: &str, lease: &Lease) -> Result<Response, Error>;
    /// Reads the Lease for the AWS Secrets Engine
    async fn read_lease(&self, path: &str) -> Result<Lease, Error>;
    /// Create role
    async fn create_role(&self, path: &str, role: &Role) -> Result<Response, Error>;
    /// Update Role
    async fn update_role(&self, path: &str, role: &Role) -> Result<Response, Error> {
        self.create_role(path, role).await
    }
    /// Read Role
    async fn read_role(&self, path: &str, role: &str) -> Result<Role, Error>;
    /// List Roles
    async fn list_roles(&self, path: &str) -> Result<Vec<String>, Error>;
    /// Delete Role
    async fn delete_role(&self, path: &str, role: &str) -> Result<Response, Error>;
    /// Generate Credentials
    async fn generate_credentials(
        &self,
        path: &str,
        role: &str,
        request: &CredentialsRequest,
    ) -> Result<LeasedData<Credentials>, Error>;
}

#[async_trait]
impl<T> Aws for T
where
    T: crate::Vault + Send + Sync,
{
    async fn configure_root(
        &self,
        path: &str,
        config: &RootCredentials,
    ) -> Result<Response, Error> {
        let values = serde_json::to_value(config)?;
        let path = format!("{}/config/root", path);
        self.post(&path, &values, false).await
    }

    async fn rotate_root(&self, path: &str) -> Result<Response, Error> {
        let path = format!("{}/config/rotate-root", path);
        self.read(&path, Method::POST).await
    }

    async fn configure_lease(&self, path: &str, lease: &Lease) -> Result<Response, Error> {
        let values = serde_json::to_value(lease)?;
        let path = format!("{}/config/lease", path);
        self.post(&path, &values, false).await
    }

    async fn read_lease(&self, path: &str) -> Result<Lease, Error> {
        let path = format!("{}/config/lease", path);
        let data: Lease = self.get(&path).await?.data()?;
        Ok(data)
    }

    async fn create_role(&self, _path: &str, _role: &Role) -> Result<Response, Error> {
        unimplemented!()
    }

    async fn read_role(&self, _path: &str, _role: &str) -> Result<Role, Error> {
        unimplemented!()
    }

    async fn list_roles(&self, _path: &str) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    async fn delete_role(&self, _path: &str, _role: &str) -> Result<Response, Error> {
        unimplemented!()
    }

    async fn generate_credentials(
        &self,
        path: &str,
        role: &str,
        request: &CredentialsRequest,
    ) -> Result<LeasedData<Credentials>, Error> {
        let path = format!("{}/creds/{}", path, role);
        self.get_with_query(&path, request).await?.leased_data()
    }
}

#[allow(dead_code)]
const fn default_max_retries() -> i64 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::mounts::tests::Mount;

    #[tokio::test(flavor = "multi_thread")]
    async fn can_configure() {
        let client = crate::tests::vault_client();

        let path = crate::tests::uuid_prefix("aws");
        let engine = crate::sys::mounts::SecretEngine {
            path,
            r#type: "aws".to_string(),
            ..Default::default()
        };

        let mount = Mount::new(&client, &engine).await;
        let config = RootCredentials {
            max_retries: -1,
            access_key: "aaa".to_string(),
            secret_key: "aaa".to_string(),
            region: None,
            iam_endpoint: Some("http://aws_iam:5000".to_string()),
            sts_endpoint: Some("http://aws_sts:8000".to_string()),
        };

        let response = Aws::configure_root(&client, &mount.path, &config)
            .await
            .unwrap();
        assert!(response.ok().unwrap().is_none());

        let lease = Lease {
            lease: "1h".to_string(),
            lease_max: "24h".to_string(),
        };
        let response = Aws::configure_lease(&client, &mount.path, &lease)
            .await
            .unwrap();
        assert!(response.ok().unwrap().is_none());

        let actual_lease = Aws::read_lease(&client, &mount.path).await.unwrap();
        assert_eq!(actual_lease.lease, "1h0m0s");
        assert_eq!(actual_lease.lease_max, "24h0m0s");
    }
}
