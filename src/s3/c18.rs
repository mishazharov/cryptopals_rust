use crate::aes_utils::*;
use crate::decode_utils::base64_from_str;

// `aes_ctr_crypt` implemented in aes_utils.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ctr_decrypt() {
        let ct = base64_from_str("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        let key = b"YELLOW SUBMARINE";
        assert_eq!(String::from_utf8_lossy(&aes_ctr_crypt(key, &ct, 0)), "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
    }
}
