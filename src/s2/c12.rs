extern crate base64;
extern crate rand;
use rand::Rng;

extern crate hex;

use openssl::symm::{Cipher, encrypt};

use crate::consts::AES_BLOCK_SIZE;

mod oracle {
    use super::*;

    pub struct AesOracle<'a> {
        secret: &'a [u8],
        key: &'a [u8]
    }
    impl<'a> AesOracle<'a> {
        pub fn new(key: &'a [u8], secret: &'a [u8]) -> AesOracle<'a> {
            if key.len() != AES_BLOCK_SIZE {
                panic!("Inappropriate key length");
            }
            AesOracle {
                secret: secret,
                key: key
            }
        }
        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let cipher = Cipher::aes_128_ecb();
            let mut plaintext_with_secret: Vec<u8> = plaintext.to_vec();
            plaintext_with_secret.extend_from_slice(self.secret);
            let encrypted = encrypt(
                cipher,
                self.key,
                None,
                &plaintext_with_secret
            ).unwrap();
            encrypted
        }
    }
}

mod attacker {
    use super::oracle::AesOracle;

    fn are_blocks_equal(block_size: usize, block_num: usize, b1: &[u8], b2: &[u8]) -> bool {
        let target_block_start = block_num * block_size;
        let target_block_end = (block_num + 1) * block_size;
        b1[target_block_start..target_block_end] == b2[target_block_start..target_block_end]
    }

    pub fn get_oracle_block_size(oracle: &AesOracle) -> usize {

        let mut size_last = oracle.encrypt(&['A' as u8]).len();
        let mut size_changed: bool = false;

        // Q: What are the odds that block size is greater than 64?
        // A: 0
        for i in 1..65 {
            let size_new = oracle.encrypt(&vec!['A' as u8; i]).len();
            if size_new != size_last && size_changed {
                return size_new - size_last;
            }
            if size_new != size_last {
                size_changed = true;
                size_last = size_new;
            }
        }
        0
    }

    pub fn attack_aes_oracle(oracle: &AesOracle) -> Vec<u8> {
        let block_size = get_oracle_block_size(oracle);
        let num_bytes = oracle.encrypt(&[]).len();
        let mut test_vec = vec![0u8; num_bytes];

        let target_block_ind = num_bytes / block_size - 1;
        let target_block_end = (target_block_ind + 1) * block_size;

        'outer: for i in 0..num_bytes {
            let target = oracle.encrypt(&test_vec[0..num_bytes - (i + 1)]);

            // Finds one byte in a block
            loop {
                let result = oracle.encrypt(&test_vec[i..num_bytes + i]);

                if are_blocks_equal(block_size, target_block_ind, &target, &result)
                {
                    test_vec.push(0);
                    break;
                }

                // Padding has started here
                if test_vec[target_block_end - 1 + i] == 255 {
                    test_vec.pop(); // Pop off 255
                    test_vec.pop(); // Pop off first padding byte that got through
                    break 'outer;
                }
                test_vec[target_block_end - 1 + i] += 1;
            }
        }
        println!("{:?}", &test_vec);
        let res = test_vec.drain(num_bytes - 1..).collect();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::oracle::AesOracle;
    use super::attacker;

    fn run_base64_test(base64_secret: &str) {
        let secret = base64::decode(
            base64_secret
        ).unwrap();
        let key: [u8; AES_BLOCK_SIZE] = rand::thread_rng().gen();

        let oracle: AesOracle = AesOracle::new(&key, &secret);
        assert_eq!(attacker::get_oracle_block_size(&oracle), AES_BLOCK_SIZE);

        let res = attacker::attack_aes_oracle(&oracle);
        println!("{}", String::from_utf8_lossy(&res));
        assert_eq!(base64_secret, base64::encode(&res))
    }

    #[test]
    fn aes_byte_at_a_time_decryption() {
        let base64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                             YnkK";
        run_base64_test(&base64_secret);
    }

    #[test]
    fn aes_byte_at_a_time_decryption_1() {
        let base64_secret = "aGVsbG8gd29ybGQ=";
        run_base64_test(&base64_secret);
    }

    #[test]
    fn aes_byte_at_a_time_decryption_2() {
        let base64_secret = "MTIzNDU2Nzc4OWRhdGF3d3diYXNlNjQ=";
        run_base64_test(&base64_secret);
    }

    #[test]
    fn aes_byte_at_a_time_decryption_3() {
        let base64_secret = "QQ==";
        run_base64_test(&base64_secret);
    }
}
