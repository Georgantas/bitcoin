use crate::private_key::PrivateKey;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Error, Secp256k1, SecretKey};
use bitcoin::Address as Addr;
use bitcoin::PublicKey;
use std::convert::TryFrom;

/// Wrapper to Addr to implement TryFrom
pub struct Address(pub Addr);

impl TryFrom<PrivateKey> for Address {
    type Error = Error;

    fn try_from(private_key: PrivateKey) -> Result<Address, Error> {
        let secp = Secp256k1::new();
        let public_key = PublicKey {
            compressed: false,
            key: secp256k1::PublicKey::from_secret_key(
                &secp,
                &SecretKey::from_slice(&private_key.0[..])?,
            ),
        };

        Ok(Address(Addr::p2pkh(&public_key, Network::Bitcoin)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generates_a_public_key() {
        let private_key = PrivateKey([
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ]);

        let address = Address::try_from(private_key).unwrap();

        assert_eq!(
            "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S",
            format!("{}", address.0)
        );
    }
}
