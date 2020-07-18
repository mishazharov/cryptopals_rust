use crate::symmetric::aes::*;
use rand;
use rand::Rng;

struct CtrContainer {
    key: [u8; 16],
    ct: Vec<u8>,
    nonce: u64
}

// None of this is efficient ¯\_(ツ)_/¯
impl CtrContainer {
    fn new(key: [u8; 16], pt: &[u8]) -> CtrContainer {
        let nonce: u64 = rand::thread_rng().gen();
        CtrContainer {
            key: key,
            ct: aes_ctr_crypt(&key, &pt, nonce),
            nonce
        }
    }

    fn get_ct(&self) -> Vec<u8> {
        return self.ct.to_vec();
    }

    fn edit(&mut self, offset: usize, newtext: &[u8]) {
        // Special case where the new content would increase the size of the array
        if offset + newtext.len() >= self.ct.len() {
            self.ct.truncate(offset);

            let mut pt = aes_ctr_crypt(&self.key, &self.ct, self.nonce);
            pt.extend_from_slice(newtext);

            self.ct = aes_ctr_crypt(&self.key, &pt, self.nonce);
            return;
        }

        let mut pt = aes_ctr_crypt(&self.key, &self.ct, self.nonce);
        pt[offset..newtext.len()].copy_from_slice(newtext);
        self.ct = aes_ctr_crypt(&self.key, &pt, self.nonce);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s1::c6::xor_vecs;

    #[test]
    fn test_ctr_edit_decrypt() {
        let file_contents: &'static str = include_str!("7ans.hex");
        let raw_bytes: Vec<u8> = hex::decode(file_contents).unwrap();

        let mut cont = CtrContainer::new(gen_random_16_bytes(), &raw_bytes);

        // Hacking in progress
        let orig_ct = cont.get_ct();
        cont.edit(0, &vec![0u8; orig_ct.len()]);
        let new_ct = cont.get_ct();
        let pt = xor_vecs(&new_ct, &orig_ct).unwrap();

        // Hacking done
        assert_eq!(pt, raw_bytes);
    }
}
