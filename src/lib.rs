//! Vault Client
//!
//! This is a thin wrapper around the HTTP API for [Vault](https://www.vaultproject.io/).
#![allow(
    missing_copy_implementations,
    missing_debug_implementations,
    unknown_lints
)]
#![deny(
    const_err,
    dead_code,
    deprecated,
    arithmetic_overflow,
    improper_ctypes,
    missing_docs,
    mutable_transmutes,
    no_mangle_const_items,
    non_camel_case_types,
    non_shorthand_field_patterns,
    non_upper_case_globals,
    overflowing_literals,
    path_statements,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unconditional_recursion,
    unknown_crate_types,
    unreachable_code,
    unused_allocation,
    unused_assignments,
    unused_attributes,
    unused_comparisons,
    unused_extern_crates,
    unused_features,
    unused_imports,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    unused_mut,
    unused_parens,
    unused_results,
    unused_unsafe,
    unused_variables,
    variant_size_differences,
    warnings,
    while_true
)]
#![doc(test(attr(allow(unused_variables), deny(warnings))))]

mod error;
mod utils;

pub mod secrets;
pub mod sys;

pub use error::Error;
pub use reqwest::Method;

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::Read;
use std::ops::Deref;

use async_trait::async_trait;
use log::{debug, info, warn};
use reqwest::{Certificate, Client as HttpClient, ClientBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// A wrapper around a String with custom implementation of Display and Debug to not leak
/// secrets during logging.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Secret(pub String);

impl Deref for Secret {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***")
    }
}

impl AsRef<str> for Secret {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret(s)
    }
}

/// Vault API Client
#[derive(Clone, Debug)]
pub struct Client {
    token: Secret,
    address: String,
    client: HttpClient,
    revoke_self_on_drop: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct Empty;

/// Generic Vault Response
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant, variant_size_differences)]
pub enum Response {
    /// An error response
    Error {
        /// List of errors returned from Vault
        errors: Vec<String>,
    },
    /// A successful response
    Response(ResponseData),
    /// An Empty (succesful) Response. Usually returned from `DELETE` operations
    Empty,
}

/// Vault Generic Response Data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ResponseData {
    /// Request UUID
    pub request_id: String,
    /// Lease ID for secrets
    pub lease_id: String,
    /// Renewable for secrets
    pub renewable: bool,
    /// Lease duration for secrets
    pub lease_duration: u64,
    /// Warnings, if any
    #[serde(default)]
    pub warnings: Option<Vec<String>>,

    /// Auth data for authentication requests
    #[serde(default)]
    pub auth: Option<Authentication>,

    /// Data for secrets requests
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    // Missing and ignored fields:
    // - wrap_info
}

/// Wrapped Vault Secret with Lease Data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct LeasedData<T> {
    /// Lease ID for secrets
    pub lease_id: String,
    /// Renewable for secrets
    pub renewable: bool,
    /// Lease duration for secrets
    pub lease_duration: u64,
    /// Wrapped Data
    pub data: T,
}

impl<T> LeasedData<T> {
    /// Unwrap and discard the lease data, returning the wrapped data
    pub fn unwrap(self) -> T {
        self.data
    }
}

/// Authentication data from Vault
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Authentication {
    /// The actual token
    pub client_token: Secret,
    /// The accessor for the Token
    pub accessor: String,
    /// List of policies for token, including from Identity
    pub policies: Vec<String>,
    /// List of tokens directly assigned to token
    pub token_policies: Vec<String>,
    /// Arbitrary metadata
    pub metadata: HashMap<String, String>,
    /// Lease Duration for the token
    pub lease_duration: u64,
    /// Whether the token is renewable
    pub renewable: bool,
    /// UUID for the entity
    pub entity_id: String,
    /// Type of token
    pub token_type: TokenType,
}

/// Type of token from Vault
/// See [Vault Documentation](https://www.vaultproject.io/docs/concepts/tokens.html#token-types-in-detail)
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Long lived service tokens
    Service,
    /// Short lived batch tokens
    Batch,
}

/// Trait implementing the basic API operations for Vault
#[async_trait]
pub trait Vault {
    /// Read a generic Path from Vault
    async fn read(&self, path: &str, method: Method) -> Result<Response, Error>;

    /// Read a generic Path from Vault with Query
    async fn read_with_query<T: Serialize + Send + Sync + ?Sized>(
        &self,
        path: &str,
        method: Method,
        query: &T,
    ) -> Result<Response, Error>;

    /// Write to a generic Path in Vault.
    async fn write<T: Serialize + Send + Sync>(
        &self,
        path: &str,
        payload: &T,
        method: Method,
        response_expected: bool,
    ) -> Result<Response, Error>;

    /// Convenience method to Get a generic path from Vault
    async fn get(&self, path: &str) -> Result<Response, Error> {
        self.read(path, Method::GET).await
    }

    /// Convenience method to Get a generic path from VaultResult
    async fn get_with_query<T: Serialize + Send + Sync + ?Sized>(
        &self,
        path: &str,
        query: &T,
    ) -> Result<Response, Error> {
        self.read_with_query(path, Method::GET, query).await
    }

    /// Convenience method to List a generic path from Vault
    async fn list(&self, path: &str) -> Result<Response, Error> {
        self.read(path, Method::from_bytes(b"LIST").expect("Not to fail"))
            .await
    }

    /// Convenience method to Post to a generic path to Vault
    async fn post<T: Serialize + Send + Sync>(
        &self,
        path: &str,
        payload: &T,
        response_expected: bool,
    ) -> Result<Response, Error> {
        self.write(path, payload, Method::POST, response_expected)
            .await
    }

    /// Convenience method to Put to a generic path to Vault
    async fn put<T: Serialize + Send + Sync>(
        &self,
        path: &str,
        payload: &T,
        response_expected: bool,
    ) -> Result<Response, Error> {
        self.write(path, payload, Method::PUT, response_expected)
            .await
    }

    /// Convenience method to Delete a Path from Vault
    async fn delete(&self, path: &str, response_expected: bool) -> Result<Response, Error> {
        self.write(path, &Empty, Method::DELETE, response_expected)
            .await
    }
}

impl Client {
    fn internal_new<S1, S2>(
        vault_address: S1,
        vault_token: S2,
        revoke_self_on_drop: bool,
        client: Option<HttpClient>,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let client = match client {
            Some(client) => client,
            None => ClientBuilder::new().build()?,
        };

        Ok(Self {
            address: vault_address.as_ref().to_string(),
            token: Secret(vault_token.as_ref().to_string()),
            revoke_self_on_drop,
            client,
        })
    }

    /// Create a new Vault Client.
    ///
    /// You can optionally provide a `reqwest::Client` if you have specific needs like custom root
    /// CA certificate or require client authentication
    #[allow(clippy::new_ret_no_self)]
    pub fn new<S1, S2, S3>(
        vault_address: Option<S1>,
        vault_token: Option<S2>,
        root_ca: Option<S3>,
        revoke_self_on_drop: bool,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
        S3: AsRef<str>,
    {
        let mut client = Self::from_environment(vault_address, vault_token, root_ca)?;
        client.revoke_self_on_drop = revoke_self_on_drop;
        Ok(client)
    }

    /// Create a client from environment variables. You can provide alternative sources of
    /// the parameters with the optional arguments
    ///
    /// The vnrionment variables are:
    ///
    /// - `VAULT_ADDR`: Vault Address
    /// - `VAULT_TOKEN`: Vault Token
    /// - `VAULT_CACERT`: Path to the CA Certificate for Vault
    pub fn from_environment<S1, S2, S3>(
        address: Option<S1>,
        token: Option<S2>,
        ca_cert: Option<S3>,
    ) -> Result<Self, Error>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
        S3: AsRef<str>,
    {
        let address = Self::environment_variable_or_provided("VAULT_ADDR", address)
            .ok_or(Error::MissingAddress)?;
        let token = Self::environment_variable_or_provided("VAULT_TOKEN", token)
            .ok_or(Error::MissingToken)?;
        let root_ca = Self::environment_variable_or_provided("VAULT_CACERT", ca_cert);

        let client = if let Some(cert) = root_ca {
            let cert = Certificate::from_pem(&read_file(cert)?)?;

            Some(ClientBuilder::new().add_root_certificate(cert).build()?)
        } else {
            None
        };

        // TODOs
        // VAULT_CLIENT_CERT
        // VAULT_CLIENT_KEY
        // VAULT_TLS_SERVER_NAME
        Self::internal_new(&address, &token, false, client)
    }

    fn environment_variable_or_provided<S>(
        env: &'static str,
        alternative: Option<S>,
    ) -> Option<String>
    where
        S: AsRef<str>,
    {
        alternative
            .map(|s| s.as_ref().to_string())
            .or_else(|| std::env::var(env).ok())
    }

    /// Returns the Vault address
    pub fn address(&self) -> &str {
        &self.address
    }

    async fn execute_request<T>(client: &HttpClient, request: reqwest::Request) -> Result<T, Error>
    where
        T: DeserializeOwned + Debug,
    {
        debug!("Executing request: {:#?}", request);
        let response = client.execute(request).await?;
        debug!("Response received: {:#?}", response);
        let body = response.text().await?;
        debug!("Response body: {}", body);
        let result = serde_json::from_str(&body)?;
        debug!("Deserialized body: {:#?}", result);
        Ok(result)
    }

    async fn execute_request_no_body(
        client: &HttpClient,
        request: reqwest::Request,
    ) -> Result<(), Error> {
        debug!("Executing request: {:#?}", request);
        let response = client.execute(request).await?;
        debug!("Response received: {:#?}", response);
        let body = response.text().await?;
        if !body.is_empty() {
            return Err(Error::UnexpectedResponse(body));
        }
        Ok(())
    }

    fn build_request<S: AsRef<str>>(
        &self,
        path: S,
        method: Method,
    ) -> Result<reqwest::RequestBuilder, Error> {
        let vault_address = url::Url::parse(self.address())?;
        let vault_address = vault_address.join(&format!("/v1/{}", path.as_ref()))?;

        Ok(self
            .client
            .request(method, vault_address)
            .header("X-Vault-Token", self.token.as_str()))
    }

    /// Revoke the Vault token itself
    ///
    /// If successful, the Vault Token can no longer be used
    pub async fn revoke_self(&self) -> Result<(), Error> {
        info!("Revoking self Vault Token");

        let request = self.build_revoke_self_request()?;
        // HTTP 204 is returned
        Self::execute_request_no_body(&self.client, request).await?;
        Ok(())
    }

    fn build_revoke_self_request(&self) -> Result<reqwest::Request, Error> {
        let vault_address = url::Url::parse(self.address())?;
        let vault_address = vault_address.join("/v1/auth/token/revoke-self")?;

        Ok(self
            .client
            .post(vault_address)
            .header("X-Vault-Token", self.token.as_str())
            .build()?)
    }
}

#[async_trait]
#[allow(clippy::trivially_copy_pass_by_ref)]
impl<T> Vault for &T
where
    T: Vault + Send + Sync,
{
    async fn read(&self, path: &str, method: Method) -> Result<Response, Error> {
        T::read(self, path, method).await
    }

    async fn read_with_query<Q: Serialize + Send + Sync + ?Sized>(
        &self,
        path: &str,
        method: Method,
        query: &Q,
    ) -> Result<Response, Error> {
        T::read_with_query(self, path, method, query).await
    }

    async fn write<P: Serialize + Send + Sync>(
        &self,
        path: &str,
        payload: &P,
        method: Method,
        response_expected: bool,
    ) -> Result<Response, Error> {
        T::write(self, path, payload, method, response_expected).await
    }
}

#[async_trait]
impl Vault for Client {
    async fn read(&self, path: &str, method: Method) -> Result<Response, Error> {
        let request = self.build_request(path, method)?.build()?;

        Self::execute_request(&self.client, request).await
    }

    async fn read_with_query<T: Serialize + Send + Sync + ?Sized>(
        &self,
        path: &str,
        method: Method,
        query: &T,
    ) -> Result<Response, Error> {
        let request = self.build_request(path, method)?.query(&query).build()?;
        Self::execute_request(&self.client, request).await
    }

    async fn write<T: Serialize + Send + Sync>(
        &self,
        path: &str,
        payload: &T,
        method: Method,
        response_expected: bool,
    ) -> Result<Response, Error> {
        let request = self.build_request(path, method)?.json(payload).build()?;
        if response_expected {
            Self::execute_request(&self.client, request).await
        } else {
            Self::execute_request_no_body(&self.client, request)
                .await
                .map(|_| Response::Empty)
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.revoke_self_on_drop {
            info!("Vault Client is being dropped. Revoking its own Token");
            match futures::executor::block_on(self.revoke_self()) {
                Ok(()) => {}
                Err(e) => warn!("Error revoking self: {}", e),
            }
        }
    }
}

impl Response {
    /// Transform the Response into `Result`, where any successful response is `Ok`,
    /// and an error from Vault is an `Err`.
    pub fn ok(self) -> Result<Option<ResponseData>, Error> {
        match self {
            Response::Error { errors } => Err(Error::VaultError(errors.join("; "))),
            Response::Response(data) => Ok(Some(data)),
            Response::Empty => Ok(None),
        }
    }
    /// Turns a Response into `Result`, where a response with data is `Ok`, and anything else
    /// is an `Err`
    pub fn data_value(&self) -> Result<&serde_json::Value, Error> {
        match self {
            Response::Error { errors } => Err(Error::VaultError(errors.join("; "))),
            Response::Empty => Err(Error::MissingData(Box::new(self.clone()))),
            Response::Response(data) => match &data.data {
                None => Err(Error::MissingData(Box::new(self.clone()))),
                Some(data) => Ok(data),
            },
        }
    }

    /// Decode the response into the appropriate data type
    pub fn data<T: DeserializeOwned>(&self) -> Result<T, Error> {
        match self {
            Response::Error { errors } => Err(Error::VaultError(errors.join("; "))),
            Response::Empty => Err(Error::MissingData(Box::new(self.clone()))),
            Response::Response(response_data) => match &response_data.data {
                None => Err(Error::MissingData(Box::new(self.clone()))),
                Some(data) => Ok(serde_json::from_value(data.clone())?),
            },
        }
    }

    /// Decode the response into the appropriate data type along with lease data
    pub fn leased_data<T: DeserializeOwned>(&self) -> Result<LeasedData<T>, Error> {
        match self {
            Response::Error { errors } => Err(Error::VaultError(errors.join("; "))),
            Response::Empty => Err(Error::MissingData(Box::new(self.clone()))),
            Response::Response(response_data) => match &response_data.data {
                None => Err(Error::MissingData(Box::new(self.clone()))),
                Some(data) => {
                    let deserialized = serde_json::from_value(data.clone())?;
                    Ok(LeasedData {
                        lease_id: response_data.lease_id.clone(),
                        renewable: response_data.renewable,
                        lease_duration: response_data.lease_duration,
                        data: deserialized,
                    })
                }
            },
        }
    }
}

fn read_file<P: AsRef<std::path::Path>>(path: P) -> Result<Vec<u8>, Error> {
    let metadata = std::fs::metadata(&path)?;
    let size = metadata.len();
    let mut file = File::open(&path)?;
    let mut buffer = Vec::with_capacity(size as usize);
    let _ = file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn vault_client() -> Client {
        Client::from_environment::<_, &str, &str>(
            Some("http://127.0.0.1:8200"),
            Some("12345"),
            None,
        )
        .unwrap()
    }

    pub(crate) fn uuid() -> String {
        uuid::Uuid::new_v4().to_simple().to_string()
    }

    pub(crate) fn uuid_prefix(prefix: &str) -> String {
        format!("{}-{}", prefix, uuid::Uuid::new_v4().to_simple())
    }

    #[tokio::test]
    async fn can_read_self_capabilities() {
        let client = vault_client();
        let _ = client.get("/auth/token/lookup-self").await.unwrap();
    }

    #[tokio::test]
    async fn can_list_kv() {
        let client = vault_client();
        let _ = client.list("secrets").await.unwrap();
    }
}
