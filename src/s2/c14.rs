extern crate base64;

use crate::aes_utils::*;

use super::c11::detect_ecb_from_stream;
use super::c12::oracle::*;
use super::c12::attacker;

use rand::Rng;
use rand::distributions::Standard;

#[cfg(test)]
mod tests {
    use super::*;

    fn run_base64_test(base64_secret: &str) {
        let secret = base64::decode(
            base64_secret
        ).unwrap();

        let oracle_core: AesOracleCore = AesOracleCore::new(&secret);
        let oracle: AesPrefixOracle = AesPrefixOracle::new(&oracle_core);

        // Detect ECB as instructions asked us
        let ciphertext = oracle.encrypt(&['A' as u8; 64]);
        assert!(detect_ecb_from_stream(&ciphertext));

        assert_eq!(attacker::get_oracle_block_size(&oracle), AES_BLOCK_SIZE);

        let res = attacker::attack_aes_oracle(&oracle);
        assert_eq!(base64_secret, base64::encode(&res))
    }

    #[test]
    fn aes_byte_at_a_time_decryption_prefix() {
        let base64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                             YnkK";
        run_base64_test(&base64_secret);
    }

    #[test]
    fn aes_byte_at_a_time_decryption_prefix_random() {
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let secret_len: usize = rng.gen_range(100, 250);
            let secret: Vec<u8> = rng.sample_iter(Standard).take(secret_len).collect();

            let oracle_core: AesOracleCore = AesOracleCore::new(&secret);
            let oracle: AesPrefixOracle = AesPrefixOracle::new(&oracle_core);

            // Detect ECB as instructions asked us
            let ciphertext = oracle.encrypt(&['A' as u8; 64]);
            assert!(detect_ecb_from_stream(&ciphertext));

            assert_eq!(attacker::get_oracle_block_size(&oracle), AES_BLOCK_SIZE);

            let res = attacker::attack_aes_oracle(&oracle);
            assert_eq!(&secret, &res);
        }
    }
}
