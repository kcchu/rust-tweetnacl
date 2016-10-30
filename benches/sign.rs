#![feature(test)]
#![allow(non_upper_case_globals)]

extern crate rand;
extern crate test;
extern crate tweetnacl;

use rand::Rng;
use test::Bencher;

fn randombytes(x: &mut [u8]) {
    rand::os::OsRng::new().unwrap().fill_bytes(x);
}

#[allow(unused_must_use)]
fn sign(b: &mut Bencher, mlen: usize) {
    let mut m = vec![0u8; mlen];
    let mut sm = vec![0u8; mlen + 64];
    let mut smlen = 0usize;
    let mut m2 = vec![0u8; mlen + 64];
    let mut m2len = 0isize;
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];
    unsafe { tweetnacl::init(randombytes) }
    tweetnacl::crypto_sign_keypair(&mut pk, &mut sk);
    randombytes(&mut m);
    b.iter(|| {
        tweetnacl::crypto_sign(&mut sm, &mut smlen, &m, &sk);
        tweetnacl::crypto_sign_open(&mut m2, &mut m2len, &sm, &pk)
    });
}

#[bench]
fn sign16(b: &mut Bencher) {
    sign(b, 16)
}

#[bench]
fn sign64(b: &mut Bencher) {
    sign(b, 64)
}

#[bench]
fn sign256(b: &mut Bencher) {
    sign(b, 256)
}

#[bench]
fn sign1024(b: &mut Bencher) {
    sign(b, 1024)
}

#[bench]
fn sign8192(b: &mut Bencher) {
    sign(b, 8192)
}