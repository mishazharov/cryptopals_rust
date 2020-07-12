use crate::hashing::md4::*;
use crate::hashing::hash_padding::HashPaddable;
use std::convert::TryInto;

fn md4_keyed_mac(content: &[u8], key: &[u8]) -> Vec<u8> {
    let mut to_hash = key.to_vec();
    to_hash.extend_from_slice(&content);
    md4(&to_hash)
}

fn md4_verify_mac(content: &[u8], key: &[u8], hash: &[u8]) -> bool {
    &md4_keyed_mac(content, key)[..] == hash
}

// Mutates res into the new hash, and returns the new text
fn break_md4_mac(hash_orig: &[u8], message: &[u8], to_append: &[u8], keysize: usize, res: &mut [u32; 4]) -> Vec<u8> {
    for i in 0..4 {
        res[i] = u32::from_le_bytes(hash_orig[i * 4..i * 4 + 4].try_into().unwrap())
    }

    let mut new_data = to_append.hashpad(false);
    let new_data_len = new_data.len();

    let mut ret = vec![0u8; keysize as usize];
    ret.extend_from_slice(message);
    ret = ret.hashpad(false);
    let pre_append_len = ret.len();
    ret.extend_from_slice(to_append);
    ret.drain(0..keysize as usize);

    let total_len = (pre_append_len + to_append.len()) * 8;
    new_data[new_data_len - 8..].copy_from_slice(
        &(total_len as u64).to_le_bytes()
    );

    md4_process_block(res, &new_data);

    ret
}

#[cfg(test)]
mod tests {
    use rand;
    use rand::Rng;
    use rand::distributions::Standard;
    use super::*;

    #[test]
    fn test_break_md4_mac() {
        let key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(
            rand::thread_rng().gen_range(1, 20)
        ).collect();

        let content = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
        let hash = md4_keyed_mac(content, &key);
        let to_append = ";admin=true".as_bytes();

        // Cracking begins
        let mut res =  [0u32; 4];
        let mut cracked_content: Vec<u8>;

        let mut keylen = 0;
        loop {
            cracked_content = break_md4_mac(&hash, content, to_append, keylen, &mut res);

            let new_hash: Vec<u8> = res.iter().flat_map(|x| x.to_le_bytes().to_vec()).collect();

            // Ask the server to verify
            if md4_verify_mac(&cracked_content, &key, &new_hash) {
                let cl = cracked_content.len();
                assert_eq!(&cracked_content[cl - to_append.len()..], to_append);
                break;
            }

            // If the server fails to verify we try again
            keylen += 1;

            if keylen > 5 {
                assert!(false);
            }
        }
    }
}
