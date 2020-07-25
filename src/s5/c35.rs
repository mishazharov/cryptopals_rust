#[cfg(test)]
mod tests {
    use super::super::peer::Peer;
    use num_bigint::BigInt;
    use crate::hashing::sha1::sha1;
    use crate::symmetric::aes::*;
    use num_traits::{Zero, One};
    use std::convert::TryInto;
    use num_bigint::ToBigInt;
    use crate::asymmetric::diffie_hellman::get_nist;

    fn test_fn<T: ToBigInt>(new_g: &T, expected: &BigInt) {
        let mut alice = Peer::nist();
        let mut bob = Peer::new(&alice.dh.p, new_g);
        alice.make_session_key(&bob.dh.public_key);
        bob.make_session_key(&alice.dh.public_key);

        assert_eq!(&bob.dh.public_key, expected);

        let mut shared_key = sha1(&expected.to_bytes_be().1);
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

    #[test]
    fn attack_dh_g_equals_one() {
        test_fn(&1, &One::one())
    }

    #[test]
    fn attack_dh_g_equals_p() {
        let nist_p = get_nist().0;
        test_fn(&nist_p, &Zero::zero())
    }

    // The shared key is either 1 or p - 1
    #[test]
    fn attack_dh_g_equals_p_minus_one() {
        let mut alice = Peer::nist();
        let nist_p = get_nist().0;
        let p_minus_one: BigInt = nist_p.checked_sub(&One::one()).unwrap();
        let mut bob = Peer::new(&alice.dh.p, &p_minus_one);
        alice.make_session_key(&bob.dh.public_key);
        bob.make_session_key(&alice.dh.public_key);

        let expected: BigInt = One::one();

        let mut shared_key = sha1(&expected.to_bytes_be().1);
        shared_key.truncate(AES_BLOCK_SIZE);

        let data = crate::rng::vec::rand_len_range(0, 512);
        let ct = alice.aes_encrypt(&data);
        let ctlen = ct.len();

        match aes_cbc_decrypt(
            &shared_key,
            &ct[..ctlen - AES_BLOCK_SIZE],
            Some(ct[ctlen - AES_BLOCK_SIZE..].try_into().unwrap())
        ) {
            Ok(res) => {
                assert_eq!(
                    alice.aes_decrypt(&ct).unwrap(),
                    res
                );
                return
            },
            _ => println!("Failed to decrypt for guess s=1")
        }

        // s wasn't 1, must be s = p - 1
        shared_key = sha1(&p_minus_one.to_bytes_be().1);
        shared_key.truncate(AES_BLOCK_SIZE);

        assert_eq!(
            alice.aes_decrypt(&ct).unwrap(),
            aes_cbc_decrypt(
                &shared_key, &ct[..ctlen - AES_BLOCK_SIZE],
                Some(ct[ctlen - AES_BLOCK_SIZE..].try_into().unwrap())
            ).unwrap()
        );

        // At this point we can re-encrypt and send it to Bob, etc.
    }
}
