use bitcoin_wallet::{Address, PrivateKey};

use std::convert::TryFrom;

fn main() {
    let private_key = PrivateKey::new();

    println!(
        "Private Key (WIF): {}\nPublic Address: {}",
        &private_key,
        Address::try_from(private_key.clone()).unwrap().0
    );
}
