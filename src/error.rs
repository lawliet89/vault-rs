use failure::Fail;

/// Error type for this library
#[derive(Debug, Fail)]
pub enum Error {
    /// Errors related to API HTTP calls
    #[fail(display = "Error making HTTP Request: {}", _0)]
    ReqwestError(#[cause] reqwest::Error),
    /// Errors parsing headers
    #[fail(display = "Error parsing HTTP header: {}", _0)]
    HeadersErrors(#[cause] reqwest::header::ToStrError),
    /// Errors related to URL parsing
    #[fail(display = "Error Parsing URL: {}", _0)]
    UrlParseError(#[cause] url::ParseError),
    /// Response from Vault was unexpected
    #[fail(display = "Unexpected response from Vault: {}", _0)]
    InvalidVaultResponse(String),
    /// Errors parsing Numbers
    #[fail(display = "Error parsing integer: {}", _0)]
    ParseIntError(#[cause] std::num::ParseIntError),
    /// Errors deserializing JSON
    #[fail(display = "Error deserializing JSON: {}", _0)]
    JsonError(#[cause] serde_json::Error),
    /// Vault address is missing
    #[fail(display = "Vault Address is missing")]
    MissingAddress,
    /// Vault token is missing
    #[fail(display = "Vault Token is missing")]
    MissingToken,
    /// IO Error
    #[fail(display = "{}", _0)]
    IoError(#[cause] std::io::Error),
    /// Error decoding bytes to UTF-8
    #[fail(display = "Error converting bytes to UTF-8: {}", _0)]
    Utf8Error(#[cause] std::string::FromUtf8Error),
    /// Vault Error
    #[fail(display = "Vault Error: {}", _0)]
    VaultError(String),
    /// Missing data from Vault
    #[fail(display = "Expected data from Vault, but was missing: {:#?}", _0)]
    MissingData(Box<crate::Response>),
    /// Expected an empty response, but got something
    #[fail(display = "Expected an empty response from Vault but got {}", _0)]
    UnexpectedResponse(String)
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::ReqwestError(error)
    }
}

impl From<reqwest::header::ToStrError> for Error {
    fn from(error: reqwest::header::ToStrError) -> Self {
        Error::HeadersErrors(error)
    }
}

impl From<url::ParseError> for Error {
    fn from(error: url::ParseError) -> Self {
        Error::UrlParseError(error)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(error: std::num::ParseIntError) -> Self {
        Error::ParseIntError(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::JsonError(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Error::Utf8Error(error)
    }
}
