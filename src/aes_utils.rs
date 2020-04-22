use openssl::symm::{Cipher, encrypt, decrypt};
use rand::Rng;

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

pub fn aes_cbc_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    let iv = [0u8; 16];
    let ciphertext = encrypt(
        cipher,
        key,
        Some(&iv),
        plaintext
    ).unwrap();
    ciphertext
}

pub fn aes_cbc_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    let iv = [0u8; 16];
    let plaintext = decrypt(
        cipher,
        key,
        Some(&iv),
        ciphertext
    ).unwrap();
    plaintext
}

pub fn gen_random_aes_key() -> [u8; AES_BLOCK_SIZE] {
    let mut rng = rand::thread_rng();

    let key: [u8; AES_BLOCK_SIZE] = rng.gen();
    key
}
