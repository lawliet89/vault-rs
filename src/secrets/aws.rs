//! AWS Secrets Engine
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).
use crate::{Error, Response};

use serde::Serialize;

/// Parameters for configuring the Root credentials for the AWS Secrets Engine
#[derive(Serialize, Debug, Eq, PartialEq, Default)]
pub struct RootCredentials {
    /// Number of max retries the client should use for recoverable errors.
    /// The default (-1) falls back to the AWS SDK's default behavior.
    #[serde(default = "default_max_retries")]
    max_retries: i64,
    /// Specifies the AWS access key ID.
    access_key: String,
    /// Specifies the AWS secret access key.
    secret_key: String,
    /// Specifies the AWS region. If not set it will use the AWS_REGION env var, AWS_DEFAULT_REGION
    /// env var, or us-east-1 in that order.
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    /// Specifies a custom HTTP IAM endpoint to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    iam_endpoint: Option<String>,
    /// Specifies a custom HTTP STS endpoint to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    sts_endpoint: Option<String>,
}

/// AWS Secrets Engine
///
/// See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).
pub trait Aws {
    /// Configure the Root IAM Credentials that Vault uses to communicate with AWS
    fn configure_root(&self, path: &str, config: &RootCredentials) -> Result<Response, Error>;
}

impl<T> Aws for T
where
    T: crate::Vault,
{
    fn configure_root(&self, path: &str, config: &RootCredentials) -> Result<Response, Error> {
        let values = serde_json::to_value(config)?;
        let path = format!("{}/config/root", path);
        self.post(&path, &values, false)
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

    #[test]
    fn can_configure_root_credentials() {
        let client = crate::tests::vault_client();

        let path = crate::tests::uuid_prefix("aws");
        let engine = crate::sys::mounts::SecretEngine {
            path: path.clone(),
            r#type: "aws".to_string(),
            ..Default::default()
        };

        let mount = Mount::new(&client, &engine);
        let config = RootCredentials {
            max_retries: -1,
            access_key: "aaa".to_string(),
            secret_key: "aaa".to_string(),
            region: None,
            iam_endpoint: Some("http://aws_iam:5000".to_string()),
            sts_endpoint: Some("http://aws_sts:8000".to_string()),
        };

        let response = Aws::configure_root(&client, &mount.path, &config).unwrap();
        assert!(response.ok().unwrap().is_none());
    }
}
