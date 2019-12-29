use super::c5::xor_encrypt;
extern crate hex;

pub struct XorSingleResult {
    pub plaintext: Vec<u8>,
    pub key: u8,
    pub weight: u32
}

fn ascii_lower(c: u8) -> u8 {
    (c as char).to_lowercase().nth(0).unwrap() as u8
}

fn score_byte(c: u8) -> u32 {
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

fn score_vec(slice_to_score: &[u8]) -> u32 {
    let mut freq: Vec<u32> = vec![0; 26];
    let total = slice_to_score.len();

    for i in slice_to_score {
        if (*i as char).is_ascii_lowercase() {
            let j = ascii_lower(*i) - ('a' as u8);
            freq[j as usize] += 1;
        }
    }

    let mut res = 0;

    for i in 0..freq.len() {
        let lhs: u32 = freq[i] * 100 / total as u32;
        let rhs: u32 = score_byte(i as u8 + ('a' as u8));

        if lhs > rhs {
            res += lhs - rhs;
        } else {
            res += rhs - lhs;
        }

    }

    res
}

// Solution for challenge 3
pub fn xor_break(slice_to_break: &[u8]) -> XorSingleResult {
    
    let mut res = XorSingleResult {
        weight: u32::max_value(),
        plaintext: vec![0; slice_to_break.len()],
        key: 0
    };

    let mut temp_vec = vec![0; slice_to_break.len()];

    for i in 0..=255 {
        temp_vec.copy_from_slice(slice_to_break);
        xor_encrypt(&[i], &mut temp_vec);
        let score = score_vec(&temp_vec);

        if score < res.weight {
            res.weight = score;
            res.plaintext.copy_from_slice(&temp_vec);
            res.key = i;
        }
    }

    res
}

// This function is the solution for challenge 4
fn xor_break_multi(vecs: &Vec<Vec<u8>>) -> XorSingleResult {

    let mut res = XorSingleResult {
        weight: u32::max_value(),
        plaintext: Default::default(),
        key: 0
    };

    for vec in vecs {
        let cand: XorSingleResult = xor_break(vec);

        if cand.weight < res.weight {
            res = cand;
        }
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_break() {
        let c = xor_break(
            &hex::decode(
                "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            ).unwrap()
        );

        // This is for challenge 3
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            String::from_utf8_lossy(&c.plaintext)
        )
    }

    #[test]
    fn test_xor_break_multi() {
        
        // `4.txt` can be found here: https://cryptopals.com/static/challenge-data/4.txt
        let file_contents: &'static str = include_str!("4.txt");
        let split_file_contents: Vec<&str> = file_contents.split('\n').collect();

        let bytes_vecs: Vec<Vec<u8>> = split_file_contents.iter().map(
            |x| hex::decode(x).unwrap()
        ).collect();

        let res: XorSingleResult = xor_break_multi(&bytes_vecs);
        assert_eq!(
            "Now that the party is jumping\n",
            String::from_utf8_lossy(&res.plaintext)
        );
    }
}
