#![feature(test)]
#![allow(non_upper_case_globals)]

extern crate tweetnacl;
extern crate test;

use test::Bencher;

const firstkey: [u8; 32]
    = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
        0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
        0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];

const nonce: [u8; 24]
    = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];

const s1k: usize = 1024;
const s1m: usize = 1024 * 1024;

#[bench]
fn secretbox1k(b: &mut Bencher) {
    let mut ms = [255u8; s1k];
    let mut out = [0u8; s1k];
    /* API requires first 32 bytes to be 0 */
    ms[..32].copy_from_slice(&[0; 32]);

    b.iter(|| {
        tweetnacl::crypto_secretbox(&mut out, &ms, &nonce, &firstkey)
    });
}

#[bench]
fn secretbox1m(b: &mut Bencher) {
    let mut ms = [255u8; s1m];
    let mut out = [0u8; s1m];
    /* API requires first 32 bytes to be 0 */
    ms[..32].copy_from_slice(&[0; 32]);

    b.iter(|| {
        tweetnacl::crypto_secretbox(&mut out, &ms, &nonce, &firstkey)
    });
}