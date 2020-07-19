pub fn hmac(key: &[u8], message: &[u8], hash_fn: fn (&Vec<u8>) -> Vec<u8>, blocksize: usize) -> Vec<u8> {
    let mut new_key = key.to_vec();

    if new_key.len() > blocksize {
        new_key = hash_fn(&new_key);
    }

    if new_key.len() < blocksize {
        new_key.resize(blocksize, 0);
    }

    let mut o_key_pad: Vec<u8> = new_key.iter().map(|&x| x ^ 0x5C).collect();
    let mut i_key_pad: Vec<u8> = new_key.iter().map(|&x| x ^ 0x36).collect();

    i_key_pad.extend_from_slice(message);

    let res = hash_fn(&i_key_pad);
    o_key_pad.extend_from_slice(&res);
    hash_fn(&o_key_pad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use rand::{distributions::Standard, Rng, self};
    use crate::hashing::sha1::*;
    use crate::hashing::hash_padding::HASH_BLOCK_LEN_BYTES;

    fn t_hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8>  {
        let new_key = PKey::hmac(key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha1(), &new_key).unwrap();
        signer.update(message).unwrap();
        signer.sign_to_vec().unwrap()
    }

    #[test]
    fn test_sha1_hmac() {
        for i in 0..500 {
            let mut rng = rand::thread_rng();
            let data: Vec<u8> = rng
                .sample_iter(Standard)
                .take(i)
                .collect();

            let key: Vec<u8> = rng
                .sample_iter(Standard)
                .take(rng.gen_range(0, 512))
                .collect();

            assert_eq!(
                t_hmac_sha1(&key, &data),
                hmac(&key, &data, sha1, HASH_BLOCK_LEN_BYTES),
                "\ndata {}\nkey {}",
                data.iter().map(|x| format!("{:#04x}, ", x)).collect::<String>(),
                key.iter().map(|x| format!("{:#04x}, ", x)).collect::<String>()
            );
        }
    }
}
