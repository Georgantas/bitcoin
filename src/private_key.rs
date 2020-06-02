//! Bitcoin Private Keys

const PRIVATE_KEY_LOWER_BOUND: [u8; 32] = {
    let mut ret: [u8; 32] = [0x00; 32];
    ret[31] = 0x01;
    ret
};

const PRIVATE_KEY_UPPER_BOUND: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
];

/// A bitcoin private key
#[derive(Debug, Clone)]
pub struct PrivateKey(pub [u8; 32]);

impl std::fmt::Display for PrivateKey {
    /// The private key is displayed in WIF format
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_wif())
    }
}

impl PrivateKey {
    /// Converts the private to to Wallet Import Format
    pub fn to_wif(&self) -> std::string::String {
        let mut ret: [u8; 33] = [0; 33];
        ret[0] = 0x80;
        ret[1..33].copy_from_slice(&self.0[..]);

        bitcoin::util::base58::check_encode_slice(&ret[..])
    }

    /// Generates a new random PrivateKey
    ///
    /// # Examples
    ///
    /// ```
    /// use generate_bitcoin_paper_wallet::private_key::PrivateKey;
    /// let private_key = PrivateKey::new();
    /// ```
    pub fn new() -> PrivateKey {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut has_generated_key_within_bounds = false;
        let mut key: [u8; 32] = [0; 32];
        while !has_generated_key_within_bounds {
            for i in 0..32 {
                let index = 31 - i;
                let candidate_value: u8 = rng.gen();
                if !has_generated_key_within_bounds {
                    if candidate_value > PRIVATE_KEY_UPPER_BOUND[index]
                        && candidate_value < PRIVATE_KEY_LOWER_BOUND[index]
                    {
                        break;
                    }
                    key[index] = candidate_value;
                    has_generated_key_within_bounds = true;
                } else {
                    key[index] = candidate_value;
                }
            }
        }
        PrivateKey(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_in_wif_format() {
        let key = PrivateKey([
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ]);

        assert_eq!(
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            format!("{}", key)
        )
    }
}
