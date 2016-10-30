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
fn do_box(b: &mut Bencher, mlen: usize) {
    let mut m_ = vec![0u8; mlen + 32];
    let mut m2 = vec![0u8; mlen + 32];
    let mut c_ = vec![0u8; mlen + 32];
    let mut alicesk_ = [0u8; 32];
    let mut alicepk_ = [0u8; 32];
    let mut bobsk_ = [0u8; 32];
    let mut bobpk_ = [0u8; 32];
    let mut n_ = [0u8; 24];
    unsafe { tweetnacl::init(randombytes) }
    tweetnacl::crypto_box_keypair(&mut alicepk_, &mut alicesk_);
    tweetnacl::crypto_box_keypair(&mut bobpk_, &mut bobsk_);
    randombytes(&mut n_);
    randombytes(&mut m_[32..mlen+32]);
    b.iter(|| {
        let _ = tweetnacl::crypto_box(&mut c_, &m_, &n_, &bobpk_, &alicesk_);
        tweetnacl::crypto_box_open(&mut m2, &c_, &n_, &alicepk_, &bobsk_)
    });
}

#[bench]
fn box16(b: &mut Bencher) {
    do_box(b, 16)
}

#[bench]
fn box64(b: &mut Bencher) {
    do_box(b, 64)
}

#[bench]
fn box256(b: &mut Bencher) {
    do_box(b, 256)
}

#[bench]
fn box1024(b: &mut Bencher) {
    do_box(b, 1024)
}

#[bench]
fn box8192(b: &mut Bencher) {
    do_box(b, 8192)
}