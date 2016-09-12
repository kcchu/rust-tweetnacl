#![feature(test)]
#![allow(non_upper_case_globals)]

extern crate rand;
extern crate tweetnacl;
extern crate test;

use rand::Rng;
use test::Bencher;

const firstkey: [u8; 32]
    = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
        0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
        0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];

const nonce: [u8; 24]
    = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];

#[bench]
fn secretbox1k(b: &mut Bencher) {
    let mut m = [0u8; 1024];
    let mut m2 = [0u8; 1024];
    let mut c = [0u8; 1024];
    rand::os::OsRng::new().unwrap().fill_bytes(&mut m[32..]);

    b.iter(|| {
        let rs = tweetnacl::crypto_secretbox(&mut c, &m, &nonce, &firstkey);
        assert!(rs.is_ok());
        tweetnacl::crypto_secretbox_open(&mut m2, &c, &nonce, &firstkey)
    });
}

#[bench]
fn secretbox1m(b: &mut Bencher) {
    let mut m = [0u8; 1024 * 1024];
    let mut m2 = [0u8; 1024 * 1024];
    let mut c = [0u8; 1024 * 1024];
    rand::os::OsRng::new().unwrap().fill_bytes(&mut m[32..]);

    b.iter(|| {
        let rs = tweetnacl::crypto_secretbox(&mut c, &m, &nonce, &firstkey);
        assert!(rs.is_ok());
        tweetnacl::crypto_secretbox_open(&mut m2, &c, &nonce, &firstkey)
    });
}