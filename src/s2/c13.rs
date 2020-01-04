use openssl::symm::{Cipher, decrypt, encrypt};

use crate::consts::AES_BLOCK_SIZE;
extern crate rand;
use rand::Rng;

struct UserAccount {
    email: String,
    uid: u32,
    role: String
}

struct EmailOracle<'a> {
    key: &'a [u8],
    uid: u32
}

impl<'a> EmailOracle <'a> {
    fn new(key: &'a [u8]) -> EmailOracle {
        EmailOracle {
            key: key,
            uid: 1
        }
    }

    fn profile_for(&mut self, email: &str) -> Vec<u8> {
        let mut email = str::replace(&email, "&", "");
        email = str::replace(&email, "=", "");
        let plaintext = format!(
            "email={}&uid={}&role=user",
            email,
            self.uid,
        );
        self.uid += 1;

        let cipher = Cipher::aes_128_ecb();
        encrypt(
            cipher,
            self.key,
            None,
            plaintext.as_bytes()
        ).unwrap()
    }

    fn cookie_to_object(self, cookie: &[u8]) -> UserAccount {
        let cipher = Cipher::aes_128_ecb();
        let plaintext = String::from_utf8(
            decrypt(
                cipher,
                self.key,
                None,
                cookie
            ).unwrap()
        ).unwrap();

        let keys: Vec<&str> = plaintext.split('&').collect();

        if keys.len() != 3 {
            panic!("Incorrect number of keys");
        }

        let email: Vec<&str> = keys[0].split('=').collect();
        let uid: Vec<&str> = keys[1].split('=').collect();
        let roles: Vec<&str> = keys[2].split('=').collect();

        UserAccount {
            email: email[1].to_string(),
            uid: uid[1].parse().unwrap(),
            role: roles[1].to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_ecb_copy_paste() {
        let key: [u8; AES_BLOCK_SIZE] = rand::thread_rng().gen();
        let mut oracle = EmailOracle::new(&key);

        let enc1 = oracle.profile_for(
            "a23456789@admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b.com"
        );

        // TODO: Maybe create a method to return a block by index
        let admin_block = &enc1[AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE];

        let hacker_email = "aesecb@lwn.net";
        let mut enc2 = oracle.profile_for(hacker_email);

        let enc2_len = enc2.len();

        for i in 0..16 {
            enc2[i + enc2_len - AES_BLOCK_SIZE] = admin_block[i];
        }

        let res = oracle.cookie_to_object(&enc2);
        assert_eq!(hacker_email, res.email);
        assert_eq!(2, res.uid);
        assert_eq!("admin", res.role);
    }
}
