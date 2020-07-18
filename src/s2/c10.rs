extern crate openssl;

use crate::symmetric::aes::*;
use crate::s1::c5::xor_encrypt;

// Decrypts AES CBC data assuming that it is using PKCS #7 padding
fn aes_cbc_decrypt(key: &[u8], data: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext = aes_ecb_decrypt_nopad(key, data, iv);

    let slice_end = data.len() - 16;
    xor_encrypt(&data[..slice_end], &mut plaintext[16..]);

    // Remove PKCS #7 padding
    strip_pkcs7(&mut plaintext);

    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::base64_from_str;
    use openssl::sha;

    #[test]
    fn test_aes_cbc() {
        let file_contents: &'static str = include_str!("10.txt");
        let raw_bytes: Vec<u8> = base64_from_str(file_contents);

        let key = b"YELLOW SUBMARINE";
        let iv = [0u8; AES_BLOCK_SIZE];
        
        let plaintext = aes_cbc_decrypt(key, &raw_bytes, &iv);

        assert_eq!(
            hex::decode(
                "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6"
            ).unwrap(),
            sha::sha256(&plaintext)
        );
    }
}
