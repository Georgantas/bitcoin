#![warn(missing_docs)]

//! Generates bitcoin paper wallets

pub mod address;
pub mod private_key;

pub use address::Address;
pub use private_key::PrivateKey;
