#[cfg(test)]
mod tests {
    use super::super::peer::Peer;
    use crate::hashing::sha1::sha1;
    use crate::symmetric::aes::*;
    use std::convert::TryInto;

    #[test]
    fn test_dh_no_mitm() {
        let mut alice = Peer::nist();

        // Send p and g to Bob
        let mut bob = Peer::new(&alice.dh.p, &alice.dh.g);

        bob.make_session_key(&alice.dh.public_key);
        alice.make_session_key(&bob.dh.public_key);

        for _ in 0..50 {
            let data = crate::rng::vec::rand_len_range(0, 512);
            let ct = alice.aes_encrypt(&data);
            let pt = bob.aes_decrypt(&ct);
            assert_eq!(data, pt.unwrap());
        }
    }

    #[test]
    fn test_dh_mitm() {
        let mut alice = Peer::nist();

        // Send p and g to Bob
        let mut bob = Peer::new(&alice.dh.p, &alice.dh.g);

        // This is the part that get's mitm'ed
        bob.make_session_key(&alice.dh.p);
        alice.make_session_key(&bob.dh.p);

        for _ in 0..50 {
            let data = crate::rng::vec::rand_len_range(0, 512);
            let ct = alice.aes_encrypt(&data);
            let pt = bob.aes_decrypt(&ct);
            assert_eq!(data, pt.unwrap());

            // Attacker can decrypt
            let mut shared_key = sha1(&vec![0u8]);
            shared_key.truncate(AES_BLOCK_SIZE);

            let ct_len = ct.len();
            let attacker_pt = aes_cbc_decrypt(
                &shared_key,
                &ct[..ct_len - AES_BLOCK_SIZE],
                Some(ct[ct_len - AES_BLOCK_SIZE..].try_into().unwrap())
            );
            assert_eq!(attacker_pt.unwrap(), data);
        }
    }
}
