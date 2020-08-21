use rand::{self, Rng};
use num_bigint::{BigInt, Sign::Plus};
use openssl::{sha::sha256, sign::Signer, hash::MessageDigest};
use openssl::pkey::PKey;
use openssl::memcmp;
use super::diffie_hellman::DiffieHellmanContext;
use num_bigint::RandBigInt;

fn a_b_to_u(a: &BigInt, b: &BigInt) -> BigInt {
    let mut to_hash = a.to_bytes_be().1;
    let to_append = b.to_bytes_be().1;
    to_hash.extend_from_slice(&to_append);

    let hashed = BigInt::from_bytes_be(Plus, &sha256(&to_hash));
    hashed
}

pub struct SrpServer {
    k: BigInt,
    salt: BigInt,
    v: BigInt,
    c_a: Option<BigInt>,
    c_b: Option<BigInt>,
    c_s: Option<BigInt>,
    c_k: Option<Vec<u8>>,
    dh: DiffieHellmanContext,
    u: Option<BigInt>,
}

impl SrpServer {
    pub fn new(pw: &[u8]) -> SrpServer {
        let dh = DiffieHellmanContext::nist();
        let k: BigInt = From::from(3);

        let salt: BigInt = From::from(rand::thread_rng().gen::<u64>());
        let mut to_hash = salt.to_bytes_be().1;
        to_hash.extend_from_slice(pw);
        let x_h = sha256(&to_hash);
        let x = BigInt::from_bytes_be(Plus, &x_h);
        let v = dh.g.modpow(&x, &dh.p);

        SrpServer {
            k: k,
            salt: salt,
            v: v,
            c_a: None,
            c_b: None,
            c_s: None,
            c_k: None,
            dh: dh,
            u: None,
        }
    }

    // Returns (salt, B)
    pub fn initial_req(&mut self, pubkey: &BigInt) -> Result<(BigInt, BigInt), ()> {
        self.c_a = Some(pubkey.clone());
        self.c_b = Some(&self.k * &self.v + &self.dh.public_key);

        self.u = Some(a_b_to_u(&self.c_a.as_ref().unwrap(), &self.c_b.as_ref().unwrap()));
        self.c_s = Some(
            self.dh.make_session_key(
                &(self.c_a.as_ref().unwrap() * self.v.modpow(self.u.as_ref().unwrap(), &self.dh.p))
            )
        );

        let to_hash = self.c_s.as_ref().unwrap().to_bytes_be().1;
        self.c_k = Some(sha256(&to_hash).to_vec());

        Ok((self.salt.clone(), self.c_b.clone().unwrap()))
    }

    pub fn is_ok(&self, content: &[u8]) -> bool {
        let pkey = PKey::hmac(self.c_k.as_ref().unwrap()).unwrap();
        let mut signer = Signer::new(
            MessageDigest::sha256(),
            &pkey
        ).unwrap();
        signer.update(&self.salt.to_bytes_be().1).unwrap();
        let hmac = signer.sign_to_vec().unwrap();

        memcmp::eq(&hmac, content)
    }

    // Returns (salt, B, u)
    pub fn variant_initial_req(&mut self, pubkey: &BigInt) -> Result<(BigInt, BigInt, BigInt), ()> {
        self.u = Some(BigInt::from(rand::thread_rng().gen::<u128>()));

        let s = self.dh.make_session_key(&(pubkey * self.v.modpow(self.u.as_ref().unwrap(), &self.dh.p)));

        let to_hash = s.to_bytes_be().1;
        self.c_k = Some(sha256(&to_hash).to_vec());

        return Ok((self.salt.clone(), self.dh.public_key.clone(), self.u.as_ref().unwrap().clone()))
    }
}

pub struct SrpClient {
    pub dh: DiffieHellmanContext,
    c_b: Option<BigInt>,
    pub salt: Option<BigInt>,
    u: Option<BigInt>,
    priv_key: BigInt,
    k: BigInt,
    c_k: Option<Vec<u8>>
}

impl SrpClient {
    pub fn new() -> SrpClient {
        let mut dh = DiffieHellmanContext::nist();
        let private_key = rand::thread_rng().gen_bigint_range(
            &BigInt::from(2),
            &dh.p
        );
        dh.set_private_key(&private_key);

        SrpClient{
            dh: dh,
            c_b: None,
            salt: None,
            u: None,
            priv_key: private_key,
            k: From::from(3),
            c_k: None
        }
    }

    pub fn set_salt_and_pkey(&mut self, salt: &BigInt, pkey_b: &BigInt, pw: &[u8]) {
        self.salt = Some(salt.clone());
        self.c_b = Some(pkey_b.clone());
        self.u = Some(a_b_to_u(&self.dh.public_key, pkey_b));

        let mut to_hash = salt.to_bytes_be().1;
        to_hash.extend_from_slice(pw);
        let x_h = sha256(&to_hash);
        let x = BigInt::from_bytes_be(Plus, &x_h);
        let s: BigInt = (
            &(pkey_b - &self.k * self.dh.g.modpow(&x, &self.dh.p))
        ).modpow(
            &(&self.priv_key + self.u.as_ref().unwrap() * x),
            &self.dh.p
        );

        let to_hash = s.to_bytes_be().1;
        self.c_k = Some(sha256(&to_hash).to_vec());
    }

    pub fn set_salt_and_pkey_variant(&mut self, salt: &BigInt, pkey_b: &BigInt, pw: &[u8], u: &BigInt) {
        self.salt = Some(salt.clone());
        let mut to_hash = salt.to_bytes_be().1;
        to_hash.extend_from_slice(pw);
        let x_h = sha256(&to_hash);
        let x = BigInt::from_bytes_be(Plus, &x_h);

        let s = pkey_b.modpow(&(&self.priv_key + u * x), &self.dh.p);
        let to_hash = s.to_bytes_be().1;

        self.c_k = Some(sha256(&to_hash).to_vec());
    }

    pub fn get_hmac(&self) -> Vec<u8> {
        let pkey = PKey::hmac(self.c_k.as_ref().unwrap()).unwrap();
        let mut signer = Signer::new(
            MessageDigest::sha256(),
            &pkey
        ).unwrap();
        signer.update(&self.salt.as_ref().unwrap().to_bytes_be().1).unwrap();
        let hmac = signer.sign_to_vec().unwrap();
        hmac
    }

    // Allow the attacker to set the state of the client
    pub fn attacker_set_shared_key(&mut self, key: Option<Vec<u8>>, salt: &BigInt) {
        self.c_k = key;
        self.salt = Some(salt.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srp_happy_path() {
        let password = b"hunter2";
        let mut server = SrpServer::new(password);

        let mut client = SrpClient::new();
        let res = server.initial_req(&client.dh.public_key).unwrap();

        client.set_salt_and_pkey(&res.0, &res.1, password);
        assert!(server.is_ok(&client.get_hmac()));
    }
}
