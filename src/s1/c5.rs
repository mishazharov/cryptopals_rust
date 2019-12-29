extern crate hex;

// In place repeating key xor encryption (solution for challenge 5)
pub fn xor_encrypt(key: &[u8], content: &mut [u8]) {
    let modulo = key.len();

    if modulo == 0 {
        return;
    }

    // Example at https://doc.rust-lang.org/std/iter/struct.Map.html#notes-about-side-effects
    let mut counter = 0;
    content.iter_mut().for_each(|x| {*x ^= key[counter]; counter = (counter + 1) % modulo});
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_encrypt() {
        let mut content_1 = String::from(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        ).into_bytes();

        xor_encrypt(b"ICE", &mut content_1);

        assert_eq!(
            hex::encode(content_1),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263\
             24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028\
             3165286326302e27282f"
        );
    }
}
