extern crate base64;

use super::c12::oracle::AesOracle;

fn attack_prefix_oracle(oracle: AesOracle) {
    let plaintext: Vec<u8> = Vec::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_prefix_oracle() {
        let base64_secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                             YnkK";

        let secret = base64::decode(
            base64_secret
        ).unwrap();

        let oracle: AesOracle = AesOracle::new(&secret);
        println!(
            "{}",
            base64::encode(&oracle.encrypt_with_prefix(b"hello"))
        );
    }
}
