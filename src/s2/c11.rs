extern crate rand;
use rand::Rng;

use openssl::symm::{Cipher, encrypt};
use crate::s1::c8::is_aes_ecb;

use crate::symmetric::aes::*;

// Returns an array of a random size in the given range, filled with random data
fn rand_bytes(size_min: usize, size_max: usize) -> Vec<u8> {
    let num_rand_at_start = rand::thread_rng().gen_range(size_min, size_max);
    let res: Vec<u8> = (0..num_rand_at_start).map(|_| rand::random::<u8>()).collect();
    res
}

// Returns true if ECB was used
fn oracle_aes_ecb_cbc(plaintext: &[u8]) -> (bool, Vec<u8>) {
    let use_ecb: bool = rand::random();
    let mut res: Vec<u8> = rand_bytes(5, 11);
    let key: [u8; AES_BLOCK_SIZE] = rand::thread_rng().gen();

    if use_ecb {
        let mut encrypted = aes_ecb_encrypt(&key,&plaintext);
        res.append(&mut encrypted);
    } else {
        let cipher = Cipher::aes_128_cbc();
        let iv: [u8; AES_BLOCK_SIZE] = rand::thread_rng().gen();
        let mut encrypted = encrypt(
            cipher,
            &key,
            Some(&iv),
            &plaintext
        ).unwrap();
        res.append(&mut encrypted);
    }

    let mut end_bytes: Vec<u8> = rand_bytes(5, 11);
    res.append(&mut end_bytes);
    (use_ecb, res)
}

pub fn detect_ecb_from_stream(ciphertext: &[u8]) -> bool {
    for i in 0..AES_BLOCK_SIZE {
        let num_blocks = (ciphertext.len() - i) / AES_BLOCK_SIZE;
        if is_aes_ecb(&ciphertext[i..num_blocks * AES_BLOCK_SIZE + i]).unwrap() {
            return true;
        }
    }
    return false;
}

mod tests {
    use super::*;

    #[test]
    fn test_detect_ecb_from_stream() {
        let plaintext = ['A' as u8; 64];
        for _ in 0..200 {
            let (is_ecb, encrypted) = oracle_aes_ecb_cbc(
                &plaintext
            );

            assert_eq!(
                is_ecb,
                detect_ecb_from_stream(&encrypted)
            );
        }
    }
}
