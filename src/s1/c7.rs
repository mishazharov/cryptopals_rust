extern crate openssl;

use openssl::symm::{decrypt, Cipher};
use openssl::sha;

use super::c6::base64_from_file;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ecb () {
        let key = b"YELLOW SUBMARINE";

        let file_contents: &'static str = include_str!("7.txt");
        let raw_bytes: Vec<u8> = base64_from_file(file_contents);

        let cipher = Cipher::aes_128_ecb();
        let res = decrypt(
            cipher,
            key,
            None,
            &raw_bytes
        ).unwrap();

        assert_eq!(
            hex::decode(
                "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6"
            ).unwrap(),
            sha::sha256(&res)
        );
    }
}
