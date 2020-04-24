use crate::aes_utils::*;

use crate::s2::c15::padding_validation;

pub trait IsServerOracle {
    fn get_ciphertext(&self) -> &[u8];
    fn check_padding(&self, ciphertext: &[u8]) -> bool;
}

pub struct ServerOracle<'a> {
    key: &'a [u8],
    ciphertext: Vec<u8>
}

impl<'a> ServerOracle<'a> {
    fn new(key: &'a [u8], ind: usize) -> ServerOracle<'a> {

        let plaintexts = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ];

        let ind_bounded = usize::min(ind, plaintexts.len() - 1);
        ServerOracle {
            key: key,
            ciphertext: aes_cbc_encrypt(key, plaintexts[ind_bounded].as_bytes())
        }
    }
}

impl<'a> IsServerOracle for ServerOracle<'a> {
    fn get_ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn check_padding(&self, ciphertext: &[u8]) -> bool {
        let iv = [0u8; 16]; // We just so happen to know what the IV is
        match padding_validation(&aes_cbc_decrypt_nopad(&self.key, ciphertext, &iv)) {
            Ok(o) => return true,
            Err(e) => return false
        }
    }
}
