extern crate base64;
extern crate rand;
extern crate hex;

use rand::Rng;
use rand::distributions::Standard;

use crate::aes_utils::*;

use super::c11::detect_ecb_from_stream;

pub mod oracle {
    use super::*;

    pub struct AesOracle<'a> {
        secret: &'a [u8],
        key: Vec<u8>,
        prefix: Vec<u8>
    }
    impl<'a> AesOracle<'a> {
        pub fn new(secret: &'a [u8]) -> AesOracle<'a> {
            let mut rng = rand::thread_rng();

            let key: [u8; AES_BLOCK_SIZE] = rng.gen();

            let prefix_len: usize = rng.gen_range(100, 250);
            let prefix: Vec<u8> = rng.sample_iter(Standard).take(prefix_len).collect();

            AesOracle {
                secret: secret,
                key: key.to_vec(),
                prefix: prefix
            }
        }
        pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut plaintext_with_secret: Vec<u8> = plaintext.to_vec();
            plaintext_with_secret.extend_from_slice(self.secret);
            aes_ecb_encrypt(&self.key, &plaintext_with_secret)
        }

        pub fn encrypt_with_prefix(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut plaintext_with_secret: Vec<u8> = self.prefix.clone();
            plaintext_with_secret.append(&mut plaintext.to_vec());
            plaintext_with_secret.extend_from_slice(self.secret);
            aes_ecb_encrypt(&self.key, &plaintext_with_secret)
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

    // Vec<(length, index)>
    pub fn get_consecutive_equal_ecb_blocks(ciphertext: &[u8], block_size: usize) -> Vec<(usize, usize)> {
        let mut res: Vec<(usize, usize)> = Vec::new();

        // Start at 2 because we won't report memory regions made of 1 consecutive equal block (this describes all
        // blocks)
        let mut curr_count = 1;
        for block_start_index in (block_size..ciphertext.len()).step_by(block_size) {
            // Check if the previous block is equal to the current block
            if ciphertext[block_start_index..block_start_index + block_size] == 
               ciphertext[block_start_index - block_size..block_start_index] {
                curr_count += 1;
            } else if curr_count != 1 {
                res.push((curr_count, block_start_index - curr_count * block_size));
                curr_count = 1;
            }
        }
        // Make sure we get the last block
        if curr_count != 1 {
            res.push((curr_count, ciphertext.len() - ciphertext.len() % block_size - curr_count * block_size));
        }
        res
    }

    pub fn attack_aes_oracle(oracle: &AesOracle) -> Vec<u8> {
        let block_size = get_oracle_block_size(oracle);
        let num_bytes = oracle.encrypt(&[]).len();
        let mut test_vec = vec![0u8; num_bytes * 2];

        let target_block_ind = num_bytes / block_size - 1;
        let target_block_end = (target_block_ind + 1) * block_size;

        'outer: for i in 0..num_bytes {
            let target = oracle.encrypt(&test_vec[0..num_bytes - (i + 1)]);

            // Finds one byte in a block
            loop {
                let result = oracle.encrypt(&test_vec[i..num_bytes + i]);

                if are_blocks_equal(block_size, target_block_ind, &target, &result)
                {
                    break;
                }

                // Padding has started here
                if test_vec[target_block_end - 1 + i] == 255 {
                    // We need to subtract two because one of the padding bytes gets through
                    // and we also have the byte which is 255
                    test_vec.truncate(num_bytes + i - 2);
                    break 'outer;
                }
                test_vec[target_block_end - 1 + i] += 1;
            }
        }
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

        let oracle: AesOracle = AesOracle::new(&secret);

        // Detect ECB as instructions asked us
        let ciphertext = oracle.encrypt(&['A' as u8; 64]);
        assert!(detect_ecb_from_stream(&ciphertext));

        assert_eq!(attacker::get_oracle_block_size(&oracle), AES_BLOCK_SIZE);

        let res = attacker::attack_aes_oracle(&oracle);
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

    #[test]
    fn test_get_consecutive_equal_ecb_blocks() {
        let data: Vec<u8> = vec![0, 0, 1, 1, 3, 3, 8, 9, 6, 5, 2, 2];
        let result: Vec<(usize, usize)> = vec![(2, 0), (2, 2), (2, 4), (2, 10)];
        assert_eq!(
            &attacker::get_consecutive_equal_ecb_blocks(&data, 1),
            &result
        );
    }

    #[test]
    fn test_get_consecutive_equal_ecb_blocks_0() {
        let data: Vec<u8> = vec![32; 32];
        let result: Vec<(usize, usize)> = vec![(2, 0)];
        assert_eq!(
            &attacker::get_consecutive_equal_ecb_blocks(&data, 16),
            &result
        );
    }
}
