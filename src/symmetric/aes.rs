use openssl::symm::{Cipher, encrypt, decrypt, Mode, Crypter};
use rand::Rng;

use crate::s1::c6::xor_vecs;

pub const AES_BLOCK_SIZE: usize = 16;
pub trait CryptoWrapper {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, ()>;
}

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

pub fn aes_cbc_encrypt(key: &[u8], plaintext: &[u8], iv: Option<[u8; AES_BLOCK_SIZE]>) -> Vec<u8> {
    let cipher = Cipher::aes_128_cbc();
    let real_iv = iv.unwrap_or_default();
    let ciphertext = encrypt(
        cipher,
        key,
        Some(&real_iv),
        plaintext
    ).unwrap();
    ciphertext
}

pub fn aes_cbc_decrypt(key: &[u8], ciphertext: &[u8], iv: Option<[u8; AES_BLOCK_SIZE]>) -> Result<Vec<u8>, ()> {
    let cipher = Cipher::aes_128_cbc();
    let real_iv = iv.unwrap_or_default();
    let plaintext_res = decrypt(
        cipher,
        key,
        Some(&real_iv),
        ciphertext
    );
    match plaintext_res {
        Ok(res) => return Ok(res),
        Err(_) => return Err(())
    };
}

pub struct AesCbcWrapper<'a> {
    key: &'a[u8],
    iv: Option<[u8; AES_BLOCK_SIZE]>,
    padding: bool
}

impl<'a> AesCbcWrapper<'a> {
    pub fn new(key: &'a[u8], iv: Option<[u8; AES_BLOCK_SIZE]>, padding: bool) -> AesCbcWrapper<'a> {
        return AesCbcWrapper {
            key: key,
            iv: iv,
            padding: padding
        }
    }
}

impl<'a> CryptoWrapper for AesCbcWrapper<'a> {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_cbc_encrypt(self.key, plaintext, self.iv)
    }

    fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, ()> {
        if self.padding {
            aes_cbc_decrypt(self.key, ct, self.iv)
        } else {
            Ok(aes_cbc_decrypt_nopad(self.key, ct, &self.iv.unwrap_or_default()))
        }
    }
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
    let mut plaintext = vec![0; ciphertext.len() + AES_BLOCK_SIZE];

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

pub fn aes_ctr_crypt(key: &[u8], text: &[u8], nonce: u64) -> Vec<u8> {
    assert_eq!(key.len(), AES_BLOCK_SIZE);

    let mut blocks_needed = text.len() / 16;

    if text.len() % 16 != 0 {
        blocks_needed += 1;
    }

    let mut keystream_pt: Vec<u8> = vec![0u8; blocks_needed * AES_BLOCK_SIZE];

    for i in 0..blocks_needed {
        let bytes_nonce = nonce.to_le_bytes();
        let bytes_ctr = (i as i64).to_le_bytes();

        for j in 0..8 {
            keystream_pt[i * AES_BLOCK_SIZE + j] = bytes_nonce[j];
            keystream_pt[i * AES_BLOCK_SIZE + j + 8] = bytes_ctr[j];
        }
    }

    let mut keystream_ct = aes_ecb_encrypt(key, &keystream_pt);
    keystream_ct.truncate(text.len());
    xor_vecs(text, &keystream_ct).unwrap()
}

pub struct AesCtrWrapper<'a> {
    key: &'a[u8],
    nonce: u64
}

impl<'a> AesCtrWrapper<'a> {
    pub fn new(key: &'a[u8], nonce: u64) -> AesCtrWrapper<'a> {
        AesCtrWrapper {
            key: key,
            nonce: nonce
        }
    }
}

impl<'a> CryptoWrapper for AesCtrWrapper<'a> {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        aes_ctr_crypt(self.key, plaintext, self.nonce)
    }

    fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(aes_ctr_crypt(self.key, ct, self.nonce))
    }
}
