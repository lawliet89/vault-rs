//! Implementation of the Various Vault Secret Engines
//!
//! See the [documentation](https://www.vaultproject.io/api/secret/).

pub mod aws;
pub mod transit;

#[doc(inline)]
pub use aws::Aws;
#[doc(inline)]
pub use transit::Transit;
