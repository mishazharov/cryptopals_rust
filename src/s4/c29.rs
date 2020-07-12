use crate::hashing::sha1::*;
use crate::hashing::hash_padding::HashPaddable;
use std::convert::TryInto;


// Mutates res into the new hash, and returns the new text
fn break_sha1_mac(hash_orig: &[u8], message: &[u8], to_append: &[u8], keysize: usize, res: &mut [u32; 5]) -> Vec<u8> {
    for i in 0..5 {
        res[i] = u32::from_be_bytes(hash_orig[i * 4..i * 4 + 4].try_into().unwrap())
    }

    let mut new_data = to_append.hashpad(true);
    let new_data_len = new_data.len();

    let mut ret = vec![0u8; keysize as usize];
    ret.extend_from_slice(message);
    ret = ret.hashpad(true);
    let pre_append_len = ret.len();
    ret.extend_from_slice(to_append);
    ret.drain(0..keysize as usize);

    let total_len = (pre_append_len + to_append.len()) * 8;
    new_data[new_data_len - 8..].copy_from_slice(
        &(total_len as u64).to_be_bytes()
    );

    sha1_process_block(res, &new_data);

    ret
}

#[cfg(test)]
mod tests {
    use rand;
    use rand::Rng;
    use rand::distributions::Standard;
    use crate::s4::c28::*;
    use super::*;

    #[test]
    fn test_break_sha1_mac() {
        let key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(
            rand::thread_rng().gen_range(1, 20)
        ).collect();

        let content = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
        let hash = sha1_keyed_mac(content, &key);
        let to_append = ";admin=true".as_bytes();

        // Cracking begins
        let mut res =  [0u32; 5];
        let mut cracked_content: Vec<u8>;

        let mut keylen = 0;
        loop {
            cracked_content = break_sha1_mac(&hash, content, to_append, keylen, &mut res);

            let new_hash: Vec<u8> = res.iter().flat_map(|x| x.to_be_bytes().to_vec()).collect();

            // Ask the server to verify
            if sha1_verify_mac(&cracked_content, &key, &new_hash) {
                let cl = cracked_content.len();
                assert_eq!(&cracked_content[cl - to_append.len()..], to_append);
                break;
            }

            // If the server fails to verify we try again
            keylen += 1;
        }
    }
}
