use crate::symmetric::aes::*;

use crate::s1::c4::xor_break;

trait CtProvider {
    fn get_ct(&self, ind: usize) -> Option<&[u8]>;
}

struct CtManager {
    key: Vec<u8>,
    ciphertexts: Vec<Vec<u8>>
}

impl CtManager {
    pub fn new() -> CtManager {
        CtManager {
            key: gen_random_16_bytes().to_vec(),
            ciphertexts: Vec::new()
        }
    }

    pub fn add_pt(&mut self, pt: &[u8]) {
        self.ciphertexts.push(aes_ctr_crypt(&self.key, pt, 0));
    }

    pub fn get_ct(&self, ind: usize) -> Option<&[u8]> {
        if self.ciphertexts.len() > ind {
            return Some(&self.ciphertexts[ind]);
        }
        None
    }
}

impl CtProvider for CtManager {
    fn get_ct(&self, ind: usize) -> Option<&[u8]> {
        self.get_ct(ind)
    }
}

// Returns the keystream
fn attacker<T: CtProvider>(ct_provider: &T) -> Vec<u8> {
    let mut ind: usize = 0;
    let mut cols: Vec<Vec<u8>> = Vec::new();

    loop {
        let ct = match ct_provider.get_ct(ind) {
            Some(c) => c,
            None => break
        };

        while cols.len() < ct.len() {
            cols.push(Vec::new());
        }

        for i in 0..ct.len() {
            cols[i].push(ct[i]);
        }

        ind += 1;
    }

    let mut res: Vec<u8> = Vec::new();

    for col in cols {
        res.push(xor_break(&col).key);
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s1::c6::xor_vecs;
    use crate::utils::decode::base64_from_str;

    #[test]
    fn test_break_aes_ctr() {
        let mut ct_manager = CtManager::new();

        let pts = [
            "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
        ];
        
        for ind in 0..pts.len() {
            ct_manager.add_pt(&base64_from_str(pts[ind]));
        }

        let keystream = attacker(&ct_manager);
        let mut ind: usize = 0;

        loop {
            let ct = match ct_manager.get_ct(ind) {
                Some(c) => c,
                None => break
            };

            let mut xored = xor_vecs(
                &ct,
                &keystream[0..ct.len()]
            ).unwrap();
            
            xored[0] = (xored[0] as char).to_uppercase().next().unwrap() as u8;

            let part_res = String::from_utf8_lossy(
                &xored
            );

            println!(
                "{}",
                part_res
            );

            // Just checking a prefix since we don't have enough data
            // for the some of the chars near the end
            let prefix_len = 20;
            assert_eq!(
                part_res[0..prefix_len],
                String::from_utf8_lossy(&base64_from_str(pts[ind]))[0..prefix_len]
            );

            ind += 1;
        }
    }
}
