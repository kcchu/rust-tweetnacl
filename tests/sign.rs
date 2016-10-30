//
// Test vectors adapted from libsodium
//

extern crate tweetnacl;
extern crate rustc_serialize;

use rustc_serialize::hex::FromHex;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[test]
fn sign() {
    let r = BufReader::new(File::open("tests/test_sign.txt").unwrap());
    for mline in r.lines() {
        let line = mline.unwrap();
        let mut fields = line.split(',');
        let mut sk = fields.next().unwrap().from_hex().unwrap();
        let pk = fields.next().unwrap().from_hex().unwrap();
        let sig = fields.next().unwrap().from_hex().unwrap();
        let m = fields.next().unwrap().from_hex().unwrap();

        assert_eq!(sk.len(), 64);
        assert_eq!(pk.len(), 32);
        assert_eq!(sig.len(), 64);

        let mut sm: Vec<u8> = vec![0u8; m.len() + 64];
        let mut m2: Vec<u8> = vec![0u8; m.len() + 64];
        let mut smlen = 0usize;
        let mut mlen = 0isize;
        sk[32..].copy_from_slice(&pk[0..32]);
        assert!(tweetnacl::crypto_sign(&mut sm, &mut smlen, &m, &sk).is_ok());
        assert_eq!(sm[..64], sig[..]);
        assert!(tweetnacl::crypto_sign_open(&mut m2, &mut mlen, &sm[..smlen], &pk).is_ok());
        assert_eq!(&m2[..mlen as usize], &m[..]);
    }
}