use crate::aes_utils::*;

use crate::s2::c15::padding_validation;
use crate::decode_utils::base64_from_str;

pub trait IsServerOracle {
    fn get_ciphertext(&self) -> &[u8];
    fn check_padding(&self, ciphertext: &[u8]) -> bool;
}

pub struct ServerOracle<'a> {
    key: &'a [u8],
    ciphertext: Vec<u8>,
    plaintext: Vec<u8>
}

impl<'a> ServerOracle<'a> {
    fn new(key: &'a [u8], ind: usize) -> ServerOracle<'a> {

        let plaintexts = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ];

        let ind_bounded = usize::min(ind, plaintexts.len() - 1);
        ServerOracle {
            key: key,
            plaintext: base64_from_str(plaintexts[ind_bounded]),
            ciphertext: aes_cbc_encrypt(key, &base64_from_str(plaintexts[ind_bounded]))
        }
    }
}

impl<'a> IsServerOracle for ServerOracle<'a> {
    fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn check_padding(&self, ciphertext: &[u8]) -> bool {
        let iv = [0u8; AES_BLOCK_SIZE]; // We just so happen to know what the IV is
        let pt = aes_cbc_decrypt_nopad(&self.key, ciphertext, &iv);
        match padding_validation(&pt) {
            Ok(_o) => return true,
            Err(_e) => return false
        }
    }
}

// Expects ct to be of length 32
// Returns the plaintext of the second block
// We could inline this for better performance
fn attacker_decrypt_block<T: IsServerOracle>(oracle: &T, ct: &[u8]) -> Vec<u8> {
    assert_eq!(ct.len(), 32);
    let mut new_ciphertext = gen_random_16_bytes().to_vec();
    new_ciphertext.extend_from_slice(&ct[AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE]);

    let mut original_ct = new_ciphertext.to_vec();

    let mut result = vec![0u8; AES_BLOCK_SIZE];
    let mut intermediate = vec![0u8; AES_BLOCK_SIZE];

    let mut ambiguity: usize = 0;
    let mut backtracking: bool = false;

    let mut i = AES_BLOCK_SIZE - 1;
    loop {

        if i >= AES_BLOCK_SIZE {
            // We got some bad random numbers which require too much backtracking
            // Just restart
            new_ciphertext = gen_random_16_bytes().to_vec();
            new_ciphertext.extend_from_slice(&ct[AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE]);
            original_ct = new_ciphertext.to_vec();
            i = AES_BLOCK_SIZE - 1;
            ambiguity = 0;
            backtracking = false;
        }

        let padding_val = AES_BLOCK_SIZE - i;

        // We are setting the new ciphertext values in order
        // to make sure the plaintext will have consistent
        // padding beyond 0x1 (since the padding will have to
        // have the same value across some amount of bytes)
        for j in AES_BLOCK_SIZE - padding_val + 1 .. AES_BLOCK_SIZE {
            new_ciphertext[j] = padding_val as u8 ^ intermediate[j];
        }
        
        // Iterate in reverse in order to make sure
        // we get the smallest `v` candidate
        let mut valid = false;

        let mut new_ambiguity = ambiguity;
        for v in 0..=255 {
            new_ciphertext[i] = v;
            if oracle.check_padding(&new_ciphertext) {
                if new_ambiguity == 0 || !backtracking {
                    if !backtracking {
                        ambiguity = 0;
                    }
                    backtracking = false;
                    intermediate[i] = padding_val as u8 ^ new_ciphertext[i];
                    result[i] = ct[i] ^ intermediate[i];
                    valid = true;
                    println!("Found byte {} {}, A: {}", i, v, ambiguity);
                    break;
                } else {
                    println!("Skipping byte {} {}, A: {}", i, v, ambiguity);
                    new_ambiguity -= 1;
                }
            }
        }

        if !valid {
            ambiguity += 1;
            println!("Failed to find byte at {}, A: {}", i, ambiguity);
            new_ciphertext.truncate(0);
            new_ciphertext.extend_from_slice(&original_ct);
            i += 2;
            backtracking = true;
        }

        if i == 0 {
            break;
        }

        i -= 1;
    }

    result
}

// Good article on this attack:
// https://robertheaton.com/2013/07/29/padding-oracle-attack/
fn attacker<T: IsServerOracle>(oracle: &T) -> Vec<u8> {
    let ct = oracle.get_ciphertext();
    let mut res: Vec<u8> = Vec::new();

    for i in 0..ct.len() / 16 {
        println!("Block # {}", i);
        if i == 0 {
            let mut input = vec![0u8; AES_BLOCK_SIZE];
            input.extend_from_slice(&ct[0..AES_BLOCK_SIZE]);
            res.extend_from_slice(&attacker_decrypt_block(oracle, &input));
        } else {
            res.extend_from_slice(
                &attacker_decrypt_block(
                    oracle,
                    &ct[(i - 1) * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE]
                )
            );
        }
    }

    strip_pkcs7(&mut res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_oracle_test(ind: usize) {
        let key = gen_random_16_bytes();
        let so = ServerOracle::new(&key, ind);
        assert_eq!(attacker(&so), so.plaintext);
    }

    #[test]
    fn test_cbc_padding_oracle() {
        // TODO: This test hangs sometimes (unlucky random numbers seem to cause
        // issues somewhere)
        for i in 0..11{
            run_oracle_test(i);
            println!("Test # {}", i);
        }
    }
}
