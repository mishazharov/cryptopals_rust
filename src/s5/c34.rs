use crate::asymmetric::diffie_hellman::DiffieHellmanContext;
use num_bigint::BigInt;
use num_bigint::Sign::Plus;
use crate::hashing::sha1::sha1;
use crate::symmetric::aes::*;
use std::convert::TryInto;
use num_bigint::ToBigInt;

struct Peer {
    pub dh: DiffieHellmanContext,
    s_key: Vec<u8>
}

impl Peer {
    pub fn new<T: ToBigInt, Q: ToBigInt>(p: &T, g: &Q) -> Peer {
        let dh = DiffieHellmanContext::new(p, g);
        Peer {
            dh: dh,
            s_key: vec![]
        }
    }

    pub fn nist() -> Peer {
        let dh = DiffieHellmanContext::nist();
        Peer {
            dh: dh,
            s_key: vec![]
        }
    }

    pub fn make_session_key(&mut self, pub_key: &BigInt) {
        let s = self.dh.make_session_key(pub_key);
        let (sign, b) = s.to_bytes_be();
        assert_eq!(sign, Plus);

        self.s_key = sha1(&b);
        self.s_key.truncate(AES_BLOCK_SIZE);
    }

    pub fn aes_encrypt(&self, pt: &[u8]) -> Vec<u8> {
        let iv = gen_random_16_bytes();
        let mut ct = aes_cbc_encrypt(&self.s_key, pt, Some(iv));
        ct.extend_from_slice(&iv);
        ct
    }

    pub fn aes_decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let len = ct.len();

        assert_eq!(len % AES_BLOCK_SIZE, 0);

        // One block for padding, one block for data
        assert!(len >= AES_BLOCK_SIZE * 2);

        aes_cbc_decrypt(
            &self.s_key,
            &ct[..len - AES_BLOCK_SIZE],
            Some(ct[len - AES_BLOCK_SIZE..].try_into().unwrap())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(data, pt);
        }
    }
}
