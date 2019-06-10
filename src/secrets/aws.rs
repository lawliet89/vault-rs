//! AWS Secrets Engine
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).

/// AWS Secrets Engine
///
/// See the [documentation](https://www.vaultproject.io/api/secret/aws/index.html).
pub trait Aws {}

impl<T> Aws for T where T: crate::Vault {}
