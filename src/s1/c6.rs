extern crate base64;
extern crate hex;
extern crate openssl;

use std::cmp;
use std::error::Error;

use super::c4::xor_break;
use super::c5::xor_encrypt;

struct XorRepeatingResult {
    plaintext: Vec<u8>,
    key: Vec<u8>
}

pub fn xor_vecs(str_1: &[u8], str_2: &[u8]) -> Result<Vec<u8>, &'static str> {
    if str_1.len() != str_2.len() {
        return Err("Bytes are not of equal length")
    }
    // https://users.rust-lang.org/t/how-to-xor-two-vec-u8/31071/2
    let res: Vec<u8> = str_1.iter().zip(str_2.iter()).map(|(&x,&y)| x ^ y).collect();
    Ok(res)
}

fn hamming_distance(str_1: &[u8], str_2: &[u8]) -> Result<u32, Box<dyn Error>> {
    let xored_bytes: Vec<u8> = xor_vecs(str_1, str_2)?;
    let mut res: u32 = 0;
    xored_bytes.iter().for_each(|&x| res += x.count_ones());
    Ok(res)
}

fn get_avg_hd_on_block(byte_arr: &[u8], key_size: usize) -> u32 {
    let mut res: u32 = 0;
    let block_count: usize = byte_arr.len() / key_size as usize;
    for i in 0..block_count - 1 {
        let start_b1: usize = key_size * i;
        let end_b1: usize = key_size * (i + 1);
        res += hamming_distance(
            &byte_arr[start_b1..end_b1],
            &byte_arr[end_b1..end_b1 + key_size]
        ).unwrap();
    }
    res / block_count as u32
}

// The reason this works is described here: https://crypto.stackexchange.com/a/8118/29392
// Returns a sorted vector of possible keysizes in a tuple (key_length, hamming_distance)
fn get_key_sizes(byte_arr: &[u8], range_low: usize, range_high: usize) -> Vec<(usize, f64)> {
    let mut res: Vec<(usize, f64)> = Vec::new();
    for cand_key_len in range_low..cmp::min(range_high, byte_arr.len() / 2) {
        let hd: u32 = get_avg_hd_on_block(byte_arr, cand_key_len);
        res.push((cand_key_len, hd as f64 / (cand_key_len as f64)));
    }
    res.sort_by(|a, b| f64::partial_cmp(&a.1, &b.1).unwrap());
    res
}

fn xor_break_repeating(byte_arr: &[u8]) -> XorRepeatingResult {
    let key_sizes: Vec<(usize, f64)> = get_key_sizes(byte_arr, 2, 40);
    let key_size: usize = key_sizes[0].0;
    let mut key: Vec<u8> = Vec::new();
    let mut plaintext: Vec<u8> = byte_arr.to_vec();
    let num_blocks = byte_arr.len() / key_size;

    let mut to_decode: Vec<u8> = vec![0; num_blocks];
    for x in 0..key_size {
        for y in 0..num_blocks {
            to_decode[y] = byte_arr[y * key_size + x]
        }
        let col_res = xor_break(&to_decode);
        key.push(col_res.key);
    }

    xor_encrypt(&key, &mut plaintext);

    let res = XorRepeatingResult {
        plaintext: plaintext,
        key: key
    };

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::decode::base64_from_str;
    use openssl::sha;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!").unwrap(), 37);
    }

    #[test]
    fn test_xor_vecs() {
        assert_eq!(
            xor_vecs(
                &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
                &hex::decode("686974207468652062756c6c277320657965").unwrap()
            ).unwrap(),
            hex::decode("746865206b696420646f6e277420706c6179").unwrap()
        );
    }

    #[test]
    fn test_xor_break_repeating() {
        // `6.txt` can be found here: https://cryptopals.com/static/challenge-data/6.txt
        let file_contents: &'static str = include_str!("6.txt");
        let raw_bytes: Vec<u8> = base64_from_str(file_contents);

        let res = xor_break_repeating(&raw_bytes);
        assert_eq!(String::from_utf8_lossy(&res.key), "Terminator X: Bring the noise");

        assert_eq!(
            hex::decode(
                "24df84533fc2778495577c844bcf3fe1d4d17c68d8c5cbc5a308286db58c69b6"
            ).unwrap(),
            sha::sha256(&res.plaintext)
        );
    }
}
