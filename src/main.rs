pub mod address;
pub mod private_key;

use std::convert::TryFrom;

fn main() {
    let private_key = private_key::PrivateKey::generate_new();

    println!(
        "Private Key (WIF): {}\nPublic Address: {}",
        &private_key,
        address::Address::try_from(private_key.clone()).unwrap().0
    );
}
