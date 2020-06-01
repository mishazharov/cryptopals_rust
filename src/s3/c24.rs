use crate::mt19937::Mt19937;
use rand::{self, Rng};
use crate::s1::c6::xor_vecs;
use std::convert::TryInto;

fn ctr_mt19937 (key: u16, data: &[u8]) -> Vec<u8> {
    let mut res = data.to_vec();

    let mut prng = Mt19937::new(key as u64);

    let mut count = 8;
    let mut curr_int_arr: [u8; 8] = [0; 8];
    for i in 0..res.len() {
        if count == 8 {
            curr_int_arr = prng.extract().to_ne_bytes();
            count = 0;
        }

        res[i] = res[i] ^ curr_int_arr[count];
        count += 1;
    }

    res
}

fn prefix_plaintext(key: u16, known_pt: &[u8]) -> Vec<u8> {
    let mut pt: Vec<u8> = Vec::new();
    let mut rng = rand::thread_rng();

    for _ in 0..rng.gen_range(50, 200) {
        pt.push(rng.gen());
    }

    pt.extend_from_slice(known_pt);

    ctr_mt19937(key, &pt)
}

fn break_ctr_mt19937(known_pt: &[u8], ct: &[u8]) -> u16 {
    // Tests shouldn't trigger this
    if known_pt.len() < 16 || known_pt.len() > ct.len() {
        panic!("Known PT is too short")
    }

    let known_ct = ct[ct.len() - known_pt.len()..ct.len()].to_vec();
    let keystr: Vec<u8> = xor_vecs(&known_ct, known_pt).unwrap();
    let rem = ct.len() % 8;
    let target_val: u64 = u64::from_ne_bytes(
        keystr[keystr.len() - 8 - rem..keystr.len() - rem].try_into().expect("should be of correct len")
    );
    let at_pos = ct.len() / 8 - 1;
    println!("At pos {}", at_pos);
    println!("Targ {}", target_val);
    for i in 0..=std::u16::MAX {
        let mut mt = Mt19937::new(i as u64);

        for _ in 0..at_pos {
            println!("{}", mt.extract());
        }

        let g = mt.extract();
        println!("{}", g);
        if g == target_val {
            return i;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_mt19937_ident() {
        let mut rng = rand::thread_rng();
        let key: u16 = rng.gen();

        let mut data: [u8; 2048] = [0; 2048];
        for i in 0..data.len() {
            data[i] = rng.gen();
        }

        assert_eq!(data.to_vec(), ctr_mt19937(key, &ctr_mt19937(key, &data)));
    }

    #[test]
    fn test_break_ctr_mt19937() {
        let mut rng = rand::thread_rng();
        let known_pt = b"AAAAAAAAAAAAAAAAAAAA";
        let key = rng.gen();
        let ct = prefix_plaintext(key, known_pt);

        assert_eq!(break_ctr_mt19937(known_pt, &ct), key);
    }
}
