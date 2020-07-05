use crate::aes_utils::*;
use crate::s2::c16::ServerOracle;
use crate::s2::c16::IsOracle;

use rand::Rng;

pub fn attack_server<T: IsOracle>(oracle: &T) -> Vec<u8> {
    // "<" is 0x3C. "=" is 0x3D
    // ":" is 0x3A. ";" is 0x3B
    let mut ciphertext = oracle.encrypt(b":admin<true");

    // Need to set the last bit in the 39th byte
    ciphertext[38] = ciphertext[38] ^ 1;

    // Need to set the last bit in the 33rd byte
    ciphertext[32] = ciphertext[32] ^ 1;
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_oracle() {
        let key = gen_random_16_bytes();
        let crypter = AesCtrWrapper::new(&key, rand::thread_rng().gen());
        let so = ServerOracle::new(&crypter);
        assert_eq!(so.is_client_admin(so.encrypt(b";admin=true;")), false);
    }

    #[test]
    fn test_attack_server_oracle() {
        let key = gen_random_16_bytes();
        let crypter = AesCtrWrapper::new(&key, rand::thread_rng().gen());
        let so = ServerOracle::new(&crypter);
        assert_eq!(so.is_client_admin(attack_server(&so)), true);
    }
}
