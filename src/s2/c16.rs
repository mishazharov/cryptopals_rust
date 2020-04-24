use crate::aes_utils::*;

pub trait IsOracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
}

pub struct ServerOracle<'a> {
    pub key: &'a[u8]
}

impl<'a> ServerOracle<'a> {
    fn is_client_admin(&self, data_encrypted: Vec<u8>) -> bool {
        let data_plaintext = aes_cbc_decrypt(self.key, &data_encrypted);
        let data_decrypted_string = String::from_utf8_lossy(&data_plaintext);
        println!("{}", data_decrypted_string);
        data_decrypted_string.contains(";admin=true;")
    }
}

impl<'a> IsOracle for ServerOracle<'a> {
    fn encrypt(&self, client_data: &[u8]) -> Vec<u8> {
        let mut vec_contents = "comment1=cooking%20MCs;userdata=".as_bytes().to_vec();

        // Pretty terrible filtering but it should prevent an "attacker" from
        // messing with the plaintext directly
        for &i in client_data {
            if i == '\\' as u8 || i == '"' as u8 || i == '=' as u8 {
                vec_contents.push('\\' as u8);
            }
            vec_contents.push(i);
        }

        vec_contents.extend_from_slice(";comment2=%20like%20a%20pound%20of%20bacon".as_bytes());
        
        aes_cbc_encrypt(self.key, &vec_contents)
    }
}

pub fn attack_server<T: IsOracle>(oracle: &T) -> Vec<u8> {
    // "<" is 0x3C. "=" is 0x3D
    // ":" is 0x3A. ";" is 0x3B
    let mut ciphertext = oracle.encrypt(b":admin<true");

    // Need to set the last bit in the 39th byte
    ciphertext[38 - AES_BLOCK_SIZE] = ciphertext[38 - AES_BLOCK_SIZE] ^ 1;

    // Need to set the last bit in the 33rd byte
    ciphertext[32 - AES_BLOCK_SIZE] = ciphertext[32 - AES_BLOCK_SIZE] ^ 1;
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_oracle() {
        let so = ServerOracle {
            key: &gen_random_16_bytes()
        };
        assert_eq!(so.is_client_admin(so.encrypt(b";admin=true;")), false);
    }

    #[test]
    fn test_attack_server_oracle() {
        let so = ServerOracle {
            key: &gen_random_16_bytes()
        };
        assert_eq!(so.is_client_admin(attack_server(&so)), true);
    }
}
