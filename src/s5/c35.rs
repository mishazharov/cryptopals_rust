#[cfg(test)]
mod tests {
    use super::super::peer::Peer;
    use num_bigint::BigInt;
    use crate::hashing::sha1::sha1;
    use crate::symmetric::aes::*;
    use std::convert::TryInto;

    #[test]
    fn attack_dh_g_equals_one() {
        let mut alice = Peer::nist();
        let mut bob = Peer::new(&alice.dh.p, &1);
        alice.make_session_key(&bob.dh.public_key);
        bob.make_session_key(&alice.dh.public_key);

        assert_eq!(bob.dh.public_key, BigInt::parse_bytes(b"1", 10).unwrap());

        let mut shared_key = sha1(&vec![1u8]);
        shared_key.truncate(AES_BLOCK_SIZE);

        let data = crate::rng::vec::rand_len_range(0, 512);
        let ct = alice.aes_encrypt(&data);
        let ctlen = ct.len();

        assert_eq!(
            alice.aes_decrypt(&ct).unwrap(),
            aes_cbc_decrypt(
                &shared_key,
                &ct[..ctlen - AES_BLOCK_SIZE],
                Some(ct[ctlen - AES_BLOCK_SIZE..].try_into().unwrap())
            ).unwrap()
        );

        // At this point we can re-encrypt and send it to Bob, etc.
    }
}
