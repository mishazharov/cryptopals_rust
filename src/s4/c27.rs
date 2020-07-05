use crate::aes_utils::*;
use crate::s1::c6::xor_vecs;

struct Server<'a> {
    crypter: &'a (dyn CryptoWrapper + 'a)
}

impl<'a> Server<'a> {
    pub fn new(crypter: &'a (dyn CryptoWrapper + 'a)) -> Server<'a> {
        Server {
            crypter: crypter
        }
    }

    pub fn encrypt(&self, text: &[u8]) -> Vec<u8> {
        self.crypter.encrypt(text)
    }

    // Can't implement CryptoWrapper since we have a different return type :(
    pub fn decrypt(&self, ct: &[u8]) -> Result<usize, Vec<u8>> { // Ok(status code), Err(plaintext)
        let pt = self.crypter.decrypt(ct);
        for i in &pt {
            if *i >= 128 {
                return Err(pt);
            }
        }
        return Ok(0);
    }
}

fn attack_server(ct: &[u8], s: Server) -> Vec<u8> {
    let mut new_ct = ct[0..AES_BLOCK_SIZE].to_vec();
    new_ct.extend_from_slice(&[0u8; AES_BLOCK_SIZE]);
    new_ct.extend_from_slice(&ct[0..AES_BLOCK_SIZE]);
    let pt = s.decrypt(&new_ct);
    let vec_pt = match pt {
        Err(e) => e,
        Ok(_) => {
            panic!("Failed because decryption succeeded");
        }
    };

    xor_vecs(&vec_pt[0..AES_BLOCK_SIZE], &vec_pt[AES_BLOCK_SIZE * 2..AES_BLOCK_SIZE * 3]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_key_equals_nonce() {
        let key = gen_random_16_bytes();
        let c= AesCbcWrapper::new(&key, Some(key), false);
        let s = Server::new(&c);
        let pt = "You would not believe your eyes
        If ten million fireflies
        Lit up the world as I fell asleep";
        let ct = s.encrypt(pt.as_bytes());

        let found_key = attack_server(&ct, s);
        assert_eq!(key.to_vec(), found_key);
    }
}
