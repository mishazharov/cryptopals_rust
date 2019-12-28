use super::c5::enc_repeating_key_xor;
extern crate hex;

pub struct XorResult {
    plaintext: Vec<u8>,
    key: u8,
    weight: usize
}

fn ascii_lower(c: u8) -> u8 {
    (c as char).to_lowercase().nth(0).unwrap() as u8
}

pub fn score_u8(c: u8) -> usize {
    let c_lower: u8 = ascii_lower(c);
    match c_lower as char {
        'e' => 13,
        't' => 9,
        'a' => 8,
        'o' => 8,
        'i' => 7,
        'n' => 7,
        's' => 6,
        'h' => 6,
        'r' => 6,
        'd' => 4,
        'l' => 4,
        'u' => 3,
        'w' => 3,
        'm' => 2,
        'f' => 2,
        'c' => 2,
        'g' => 2,
        'y' => 2,
        'p' => 2,
        'b' => 1,
        'k' => 1,
        'v' => 1,
        _   => 0
    }
}

pub fn score_vec_u8(slice_to_score: &[u8]) -> usize {
    let mut freq = vec![0; 26];
    let total = slice_to_score.len();

    for i in slice_to_score {
        if (*i as char).is_ascii_lowercase() {
            let j = ascii_lower(*i) - ('a' as u8);
            freq[j as usize] += 1;
        }
    }

    let mut res = 0;

    for i in 0..freq.len() {
        let lhs = freq[i] * 100 / total;
        let rhs = score_u8(i as u8 + ('a' as u8));
        // println!("lhs {} rhs {}", lhs, rhs);

        if lhs > rhs {
            res += lhs - rhs;
        } else {
            res += rhs - lhs;
        }

    }

    // println!("res {}", res);

    res
}

pub fn break_single_xor(slice_to_break: &[u8]) -> XorResult {
    
    let mut min = usize::max_value();
    let mut plaintext: Vec<u8> = Default::default();
    let mut key: u8 = 0;

    for i in 0..=255 {
        let mut temp_vec = slice_to_break.to_vec();
        enc_repeating_key_xor(&[i], &mut temp_vec);
        let score = score_vec_u8(&temp_vec);

        println!("{} score: {}", String::from_utf8_lossy(&temp_vec), score);

        if score < min {
            min = score;
            plaintext = temp_vec;
            key = i;
        }
    }

    let res = XorResult {
        weight: min,
        plaintext: plaintext,
        key: key
    };
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_break_single_xor() {
        let c = break_single_xor(
            &hex::decode(
                "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            ).unwrap()
        );
        println!(
            "plaintext: {} weight: {} key: {}",
            String::from_utf8_lossy(&c.plaintext),
            &c.weight,
            &c.key
        );

        // This is for challenge 3
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            String::from_utf8_lossy(&c.plaintext)
        )
    }
}