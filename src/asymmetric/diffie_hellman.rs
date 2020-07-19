use num_bigint::BigInt;
use num_bigint::ToBigInt;
use num_bigint::Sign::Plus;
use rand;
use num_bigint::RandBigInt;
use hex_literal::hex;

const NIST_P: [u8; 192] = hex!(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff"
);

struct DiffieHellmanContext {
    pub p: BigInt,
    pub g: BigInt,
    pub public_key: BigInt,
    private_key: BigInt
}

impl DiffieHellmanContext {
    fn new<T: ToBigInt, Q: ToBigInt>(p: T, g: Q) -> DiffieHellmanContext {
        let p = p.to_bigint().unwrap();
        let g = g.to_bigint().unwrap();

        let private_key = rand::thread_rng().gen_bigint_range(
            &BigInt::from(2),
            &p
        );
        let public_key = g.modpow(&private_key, &p);

        DiffieHellmanContext {
            p: p,
            g: g.to_bigint().unwrap(),
            public_key: public_key,
            private_key: private_key
        }
    }

    fn nist() -> DiffieHellmanContext {
        DiffieHellmanContext::new(
            BigInt::from_radix_be(
                Plus,
                &NIST_P,
                256
            ).unwrap(),
            2
        )
    }

    fn make_session_key(&self, pubkey: &BigInt) -> BigInt {
        let s = pubkey.modpow(&self.private_key, &self.p);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffiehellman() {
        let alice = DiffieHellmanContext::nist();
        let bob = DiffieHellmanContext::nist();

        assert_eq!(
            alice.make_session_key(&bob.public_key),
            bob.make_session_key(&alice.public_key)
        );
    }
}
