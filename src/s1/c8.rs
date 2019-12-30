extern crate hex;

use crate::decode_utils::hex_arr_from_str;

use std::error::Error;

use std::collections::HashMap;

const AES_BLOCK_SIZE: usize = 16;

// The array passed in should be a multiple of 16 if it's ecb
fn is_aes_ecb(candidate: &[u8]) -> Result<bool, Box<dyn Error>> {
    if candidate.len() % 16 != 0 {
        return Err(
            From::from(
                "The length of the data is not a multiple of the AES block size"
            )
        )
    }
    let mut seen_map: HashMap<&[u8], i32> = HashMap::new();
    let num_blocks = candidate.len() / AES_BLOCK_SIZE;

    for i in 0..num_blocks {
        let curr_block: &[u8] = &candidate[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE];
        if seen_map.contains_key(curr_block) {
            return Ok(true)
        }
        seen_map.insert(curr_block, 1);
    }
    return Ok(false)
}

fn detect_aes_ecb(candidates: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut res: Vec<Vec<u8>> = Default::default();

    for vec in candidates {
        if is_aes_ecb(&vec).unwrap() {
            res.push(vec.clone());
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_aes_ecb() {
        // `8.txt` can be found here: https://cryptopals.com/static/challenge-data/8.txt
        let file_contents: &'static str = include_str!("8.txt");
        let bytes_vecs = hex_arr_from_str(&file_contents);
        let res = detect_aes_ecb(&bytes_vecs);
        assert_eq!(res.len(), 1);
        assert_eq!(
            hex::encode(&res[0]),
            "d880619740a8a19b\
             7840a8a31c810a3d\
             08649af70dc06f4f\
             d5d2d69c744cd283\
             e2dd052f6b641dbf\
             9d11b0348542bb57\
             08649af70dc06f4f\
             d5d2d69c744cd283\
             9475c9dfdbc1d465\
             97949d9c7e82bf5a\
             08649af70dc06f4f\
             d5d2d69c744cd283\
             97a93eab8d6aecd5\
             66489154789a6b03\
             08649af70dc06f4f\
             d5d2d69c744cd283\
             d403180c98c8f6db\
             1f2a3f9c4040deb0\
             ab51b29933f2c123\
             c58386b06fba186a"
        );
    }
}
