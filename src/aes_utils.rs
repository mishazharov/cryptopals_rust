use openssl::symm::{Cipher, encrypt, decrypt, Mode, Crypter};
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

pub fn aes_decrypt_nopad(key: &[u8], ciphertext: &[u8], iv: &[u8], cipher: Cipher) -> Vec<u8> {
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        key,
        Some(&iv)
    ).unwrap();

    // Padding will cause OpenSSL to throw a bad decrypt error
    // https://github.com/wahern/luaossl/issues/30
    // Similar to https://crypto.stackexchange.com/a/12623/29392
    // Because when using ECB, the padding in the plaintext
    // will be invalid (until we XOR it with the ciphertext)
    decrypter.pad(false);
    let mut plaintext = vec![0; ciphertext.len() + 16];

    let mut count = decrypter.update(&ciphertext, &mut plaintext).unwrap();
    count += decrypter.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count);
    plaintext
}

pub fn aes_ecb_decrypt_nopad(key: &[u8], ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    aes_decrypt_nopad(key, ciphertext, iv, Cipher::aes_128_ecb())
}

pub fn aes_cbc_decrypt_nopad(key: &[u8], ciphertext: &[u8], iv: &[u8]) -> Vec<u8> {
    aes_decrypt_nopad(key, ciphertext, iv, Cipher::aes_128_cbc())
}

pub fn gen_random_16_bytes() -> [u8; AES_BLOCK_SIZE] {
    let mut rng = rand::thread_rng();

    let key: [u8; AES_BLOCK_SIZE] = rng.gen();
    key
}

pub fn strip_pkcs7(inp: &mut Vec<u8>) {
    let padding_length = inp.last().unwrap();
    let final_length = inp.len().saturating_sub(*padding_length as usize);
    inp.truncate(final_length);
}
