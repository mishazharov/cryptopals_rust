use crate::sha1::*;

pub fn sha1_keyed_mac(content: &[u8], key: &[u8]) -> Vec<u8> {
    let mut to_hash = key.to_vec();
    to_hash.extend_from_slice(&content);
    sha1(&to_hash)
}

pub fn sha1_verify_mac(content: &[u8], key: &[u8], hash: &[u8]) -> bool {
    &sha1_keyed_mac(content, key)[..] == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_success() {
        let content = "Intruder alert! Red Spy is in the base!".as_bytes();
        let key = "mentlegen".as_bytes();

        let hash = sha1_keyed_mac(
            content,
            key
        );

        assert!(sha1_verify_mac(content, key, &hash));
    }

    #[test]
    fn test_mac_fail() {
        let content = "Intruder alert! Red Spy is in the base!".as_bytes();
        let key = "mentlegen".as_bytes();

        let hash = sha1_keyed_mac(
            content,
            key
        );

        assert!(
            !sha1_verify_mac(
                // Missing exclamation mark
                "Intruder alert! Red Spy is in the base".as_bytes(),
                key,
                &hash
            )
        );
    }

    #[test]
    fn test_need_key_for_mac() {
        let content = "Intruder alert! Red Spy is in the base!".as_bytes();
        let key = "mentlegn".as_bytes();

        let hash = sha1_keyed_mac(
            content,
            key
        );

        assert!(
            !sha1_verify_mac(
                // Missing exclamation mark
                content,
                "mentlegen".as_bytes(),
                &hash
            )
        );
    }
}
