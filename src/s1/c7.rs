#[cfg(test)]
mod tests {
    use openssl::sha;

    use crate::symmetric::aes::*;
    use crate::utils::decode::base64_from_str;

    #[test]
    fn test_aes_ecb () {
        let key = b"YELLOW SUBMARINE";

        // https://cryptopals.com/static/challenge-data/7.txt
        let file_contents: &'static str = include_str!("7.txt");
        let raw_bytes: Vec<u8> = base64_from_str(file_contents);

        let res = aes_ecb_decrypt(key, &raw_bytes);

        assert_eq!(
            hex::decode(
                "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6"
            ).unwrap(),
            sha::sha256(&res)
        );
    }
}
