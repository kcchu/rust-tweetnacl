#![feature(test)]
#![allow(non_upper_case_globals)]

extern crate rand;
extern crate tweetnacl;
extern crate test;

use test::Bencher;
use rand::Rng;

fn randombytes(x: &mut [u8]) {
    rand::os::OsRng::new().unwrap().fill_bytes(x);
}

fn hash(b: &mut Bencher, s: usize) {
    let mut buf = vec![0u8; s];
    let mut h = [0u8; 64];
    randombytes(&mut buf);
    b.iter(|| {
        tweetnacl::crypto_hash(&mut h[..], &buf)
    });
}

#[bench]
fn hash16(b: &mut Bencher) {
    hash(b, 16)
}

#[bench]
fn hash64(b: &mut Bencher) {
    hash(b, 16)
}

#[bench]
fn hash256(b: &mut Bencher) {
    hash(b, 256)
}

#[bench]
fn hash1024(b: &mut Bencher) {
    hash(b, 1024)
}

#[bench]
fn hash8192(b: &mut Bencher) {
    hash(b, 8192)
}