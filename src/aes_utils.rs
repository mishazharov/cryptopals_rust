use openssl::symm::{Cipher, encrypt, decrypt};

pub const AES_BLOCK_SIZE: usize = 16;

pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let ciphertext = encrypt(
        cipher,
        key,
        None,
        plaintext
    ).unwrap();
    ciphertext
}

pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(
        cipher,
        key,
        None,
        ciphertext
    ).unwrap();
    plaintext
}
