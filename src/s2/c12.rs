extern crate base64;
extern crate rand;
extern crate hex;

use rand::Rng;
use rand::distributions::Standard;

use crate::symmetric::aes::*;

pub mod oracle {
    use super::*;

    pub trait IsOracle {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    }

    pub struct AesOracleCore<'a> {
        pub secret: &'a [u8],
        pub key: Vec<u8>,
        pub prefix: Vec<u8>
    }

    impl<'a> AesOracleCore<'a> {
        pub fn new(secret: &'a [u8]) -> AesOracleCore<'a> {
            let mut rng = rand::thread_rng();

            let key: [u8; AES_BLOCK_SIZE] = rng.gen();

            let prefix_len: usize = rng.gen_range(100, 250);
            let prefix: Vec<u8> = rng.sample_iter(Standard).take(prefix_len).collect();

            AesOracleCore {
                secret: secret,
                key: key.to_vec(),
                prefix: prefix
            }
        }
    }

    // This struct allows us to pass an AesOracleCore to an attacker without exposing
    // the secret, keys, and padding. However, it allows the test infrastructure to
    // access these variables. Normally the tests cannot access these because they
    // are in c12::tests and the oracle is in c12::oracle. Therefore private variables
    // remain private.
    //
    // It would have also been possible to write some tests in a submodule of oracle,
    // but then we're testing the attackers code in the oracle module, which feels
    // even dirtier.
    pub struct AesOracle<'a> {
        oracle_core: &'a AesOracleCore<'a>
    }
    impl<'a> IsOracle for AesOracle<'a> {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut plaintext_with_secret: Vec<u8> = plaintext.to_vec();
            plaintext_with_secret.extend_from_slice(self.oracle_core.secret);
            aes_ecb_encrypt(&self.oracle_core.key, &plaintext_with_secret)
        }
    }
    impl<'a> AesOracle<'a> {
        pub fn new(oracle_core: &'a AesOracleCore) -> AesOracle<'a>{
            AesOracle {
                oracle_core: oracle_core
            }
        }
    }

    pub struct AesPrefixOracle<'a> {
        oracle_core: &'a AesOracleCore<'a>
    }
    impl<'a> IsOracle for AesPrefixOracle<'a> {
        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            let mut plaintext_with_secret: Vec<u8> = self.oracle_core.prefix.clone();
            plaintext_with_secret.extend_from_slice(plaintext);
            plaintext_with_secret.extend_from_slice(self.oracle_core.secret);
            aes_ecb_encrypt(&self.oracle_core.key, &plaintext_with_secret)
        }
    }
    impl<'a> AesPrefixOracle<'a> {
        pub fn new(oracle_core: &'a AesOracleCore) -> AesPrefixOracle<'a>{
            AesPrefixOracle {
                oracle_core: oracle_core
            }
        }
    }
}

pub mod attacker {
    use super::oracle::*;

    fn are_blocks_equal(block_size: usize, block_num: usize, b1: &[u8], b2: &[u8]) -> bool {
        let target_block_start = block_num * block_size;
        let target_block_end = target_block_start + block_size;

        let s1 = &b1[target_block_start..target_block_end];
        let s2 = &b2[target_block_start..target_block_end];
        s1 == s2
    }

    pub fn get_oracle_block_size<T: IsOracle>(oracle: &T) -> usize {

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

    // This method finds blocks that are equal and consecutive in a byte slice
    // Returns Vec<(length, index)>
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
                let index = block_start_index - curr_count * block_size;
                assert_eq!(index % block_size, 0);
                res.push((curr_count, index));
                curr_count = 1;
            }
        }
        // Make sure we get the last block
        if curr_count != 1 {
            let index = ciphertext.len() - curr_count * block_size;
            assert_eq!(index % block_size, 0);
            res.push((curr_count, index));
        }
        res
    }

    // Returns (blocks_length, start_index, user_length, total_len)
    fn get_user_data_start_block_<T: IsOracle>(oracle: &T, block_size: usize, padding: u8) -> (usize, usize, usize, usize) {
        let mut test_vec = vec![padding; 0];

        let initial: Vec<(usize, usize)> = get_consecutive_equal_ecb_blocks(&oracle.encrypt(&test_vec), block_size);

        loop {
            let ciphertext = oracle.encrypt(&test_vec);
            let current: Vec<(usize, usize)> = get_consecutive_equal_ecb_blocks(&ciphertext, block_size);

            for i in 0..current.len() {
                if initial.len() <= i || initial[i] != current[i] {
                    assert_eq!(current[i].1 % block_size, 0);
                    return (current[i].0, current[i].1, test_vec.len(), ciphertext.len());
                }
            }

            test_vec.push(padding);
        }
    }

    // Returns (blocks_length, start_index, user_length, total_len)
    pub fn get_user_data_start_block<T: IsOracle>(oracle: &T, block_size: usize) -> (usize, usize, usize, usize) {
        let res1 = get_user_data_start_block_(oracle, block_size, 2);
        let res2 = get_user_data_start_block_(oracle, block_size, 1);

        if res1.2 > res2.2 {
            return res1;
        }
        res2
    }

    pub fn attack_aes_oracle<T: IsOracle>(oracle: &T) -> Vec<u8> {
        let block_size = get_oracle_block_size(oracle);

        let (_blocks_length, start_index, user_length, total_len) = get_user_data_start_block(oracle, block_size);

        let bytes_to_complete_prefix_block = user_length % block_size;

        let bytes_to_extract = total_len - start_index;
        let vecs_length = bytes_to_extract + bytes_to_complete_prefix_block;
        let vec_empty = vec![0u8; vecs_length];
        let mut vec_test = vec![0u8; vecs_length];

        'outer: for current_byte in 0..bytes_to_extract {
            let target = oracle.encrypt(&vec_empty[current_byte + 1..]);

            loop {
                let result = oracle.encrypt(&vec_test);

                if are_blocks_equal(
                    block_size,
                    (vecs_length + start_index - bytes_to_complete_prefix_block) / block_size - 1,
                    &target,
                    &result
                ) {
                    break;
                }

                if vec_test[vecs_length - 1] == 255 {
                    // We need to subtract two because one of the padding bytes gets through
                    // and we also have the byte which is 255
                    vec_test.truncate(vecs_length - 2);
                    vec_test.drain(0..bytes_to_extract - current_byte - 1);
                    break 'outer;
                }
                vec_test[vecs_length - 1] += 1;
            }
            if current_byte + 1 == bytes_to_extract {
                vec_test.pop();
                break;
            }
            vec_test.push(0);
            vec_test.drain(0..1);
        }
        vec_test.drain(0..bytes_to_complete_prefix_block);
        vec_test
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::oracle::*;
    use crate::s2::c11::detect_ecb_from_stream;

    fn run_base64_test(base64_secret: &str) {
        let secret = base64::decode(
            base64_secret
        ).unwrap();

        let oracle_core: AesOracleCore = AesOracleCore::new(&secret);
        let oracle: AesOracle = AesOracle::new(&oracle_core);

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

    #[test]
    fn test_get_user_data_start_block() {
        let secret = b"Hello World";

        let oracle_core: AesOracleCore = AesOracleCore::new(secret);
        let oracle: AesPrefixOracle = AesPrefixOracle::new(&oracle_core);

        let block_size = attacker::get_oracle_block_size(&oracle);
        let (blocks_length, start_index, user_length, total_len) = attacker::get_user_data_start_block(&oracle, block_size);

        let prefix_len = oracle_core.prefix.len();

        // Weak sanity checks. Can add more thorough testing if it is necessary
        assert!(start_index >= prefix_len);
        assert!(start_index < prefix_len + block_size);

        assert!((user_length +  prefix_len) % block_size == 0);

        assert!(blocks_length * block_size <= user_length);
        assert!((blocks_length + 1) * block_size > user_length);

        assert!(total_len >= start_index + blocks_length * block_size);
    }

    #[test]
    fn test_get_user_data_start_block_reg_oracle() {
        let secret = b"Hello World";

        let oracle_core: AesOracleCore = AesOracleCore::new(secret);
        let oracle: AesOracle = AesOracle::new(&oracle_core);

        let block_size = attacker::get_oracle_block_size(&oracle);
        let (blocks_length, start_index, user_length, total_len) = attacker::get_user_data_start_block(&oracle, block_size);

        // Weak sanity checks. Can add more thorough testing if it is necessary
        assert_eq!(start_index, 0);
        assert_eq!(user_length, block_size * 2);
        assert_eq!(blocks_length, 2);

        assert!(total_len >= start_index + blocks_length * block_size);
    }

    #[test]
    fn aes_byte_at_a_time_decryption_no_prefix_random(){
        for _ in 0..25 {
            let mut rng = rand::thread_rng();
            let secret_len: usize = rng.gen_range(100, 250);
            let secret: Vec<u8> = rng.sample_iter(Standard).take(secret_len).collect();

            let oracle_core: AesOracleCore = AesOracleCore::new(&secret);
            let oracle: AesOracle = AesOracle::new(&oracle_core);

            // Detect ECB as instructions asked us
            let ciphertext = oracle.encrypt(&['A' as u8; 64]);
            assert!(detect_ecb_from_stream(&ciphertext));

            assert_eq!(attacker::get_oracle_block_size(&oracle), AES_BLOCK_SIZE);

            let res = attacker::attack_aes_oracle(&oracle);
            assert_eq!(&secret, &res);
        }
    }
}
