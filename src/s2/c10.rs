extern crate openssl;

use openssl::symm::{Cipher, Mode, Crypter};
use openssl::sha;
use crate::decode_utils::base64_from_str;

use crate::s1::c5::xor_encrypt;

const AES_BLOCK_SIZE: usize = 16;

fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(
        Cipher::aes_128_ecb(),
        Mode::Decrypt,
        key,
        Some(&iv)).unwrap();

    // Padding will cause OpenSSL to throw a bad decrypt error
    // https://github.com/wahern/luaossl/issues/30
    // Similar to https://crypto.stackexchange.com/a/12623/29392
    // Because when using ECB, the padding in the plaintext
    // will be invalid (until we XOR it with the ciphertext)
    decrypter.pad(false);
    let mut plaintext = vec![0; data.len() + 16];

    let mut count = decrypter.update(&data, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    let slice_end = data.len() - 16;
    xor_encrypt(&data[..slice_end], &mut plaintext[16..]);
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_cbc() {
        let file_contents: &'static str = include_str!("10.txt");
        let raw_bytes: Vec<u8> = base64_from_str(file_contents);

        let key = b"YELLOW SUBMARINE";
        let iv = [0u8; AES_BLOCK_SIZE];
        
        // xor_encrypt(&raw_bytes, &mut res);
        let plaintext = aes_cbc_decrypt(&raw_bytes, key, &iv);

        assert_eq!(
            hex::decode(
                "368f2b80b437209451355b750181b378f425cc00af3922bcecc8d4a7d84a5198"
            ).unwrap(),
            sha::sha256(&plaintext)
        );
    }
}
