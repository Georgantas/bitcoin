pub mod private_key;

fn main() {
    println!(
        "Private Key (WIF): {}\nPublic Address: {}",
        private_key::PrivateKey::generate_new(),
        "TODO"
    );
}
