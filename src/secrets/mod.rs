//! Implementation of the Various Vault Secret Engines
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/).

pub mod transit;

pub use transit::Transit;
