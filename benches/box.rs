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

fn do_box(b: &mut Bencher, mlen: usize) {
    let mut m_ = [0u8; 1024*1024+32];
    let mut m2 = [0u8; 1024*1024+32];
    let mut c_ = [0u8; 1024*1024+32];
    let mut alicesk_ = [0u8; 32];
    let mut alicepk_ = [0u8; 32];
    let mut bobsk_ = [0u8; 32];
    let mut bobpk_ = [0u8; 32];
    let mut n_ = [0u8; 24];
    unsafe { tweetnacl::randombytes_impl = randombytes }
    tweetnacl::crypto_box_keypair(&mut alicepk_, &mut alicesk_);
    tweetnacl::crypto_box_keypair(&mut bobpk_, &mut bobsk_);
    randombytes(&mut n_);
    randombytes(&mut m_[32..mlen+32]);
    b.iter(|| {
        let rs = tweetnacl::crypto_box(&mut c_[..mlen+32], &m_[..mlen+32], &n_, &bobpk_, &alicesk_);
        assert!(rs.is_ok());
        tweetnacl::crypto_box_open(&mut m2[..mlen+32], &c_[..mlen+32], &n_, &alicepk_, &bobsk_)
    });
}

#[bench]
fn box1k(b: &mut Bencher) {
    do_box(b, 1024);
}

#[bench]
fn box1m(b: &mut Bencher) {
    do_box(b, 1024 * 1024);
}