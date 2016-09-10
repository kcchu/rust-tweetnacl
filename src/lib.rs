#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use std::cmp::min;

macro_rules! sl4 {
    (&mut $s:expr, $b:expr) => {
        &mut $s[($b)..(($b) + 4)];
    };
    (& $s:expr, $b:expr) => {
        & $s[($b)..(($b) + 4)];
    };
}

pub struct CryptoError;

type gf = [i64; 16];

const _0: [u8; 16] = [0; 16];
const _9: [u8; 32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const gf0: gf = [0; 16];
const gf1: gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const _121665: gf = [0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const D: gf = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
const D2: gf = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
const X: gf = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
const Y: gf = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
const I: gf = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

fn L32(x: u32, c: isize) -> u32 {
    (x << c) | ((x & 0xffffffff) >> (32 - c))
}

fn ld32(x: &[u8]) -> u32 {
    debug_assert_eq!(x.len(), 4);
    let mut u = x[3] as u32;
    u = (u << 8) | x[2] as u32;
    u = (u << 8) | x[1] as u32;
    (u << 8) | x[0] as u32
}

fn dl64(x: &[u8]) -> u64 {
    debug_assert_eq!(x.len(), 8);
    let mut u = 0u64;
    for i in 0..8 { u = (u << 8) | x[i] as u64 }
    u
}

fn st32(x: &mut [u8], u: u32) {
    debug_assert_eq!(x.len(), 4);
    let mut u = u;
    for i in 0..4 { x[i] = u as u8; u >>= 8; }
}

fn ts64(x: &mut [u8], u: u64) {
    debug_assert_eq!(x.len(), 8);
    let mut u = u;
    for i in (0..8).rev() { x[i] = u as u8; u >>= 8; }
}

fn vn(x: &[u8], y: &[u8]) -> isize {
    // panic if length of x and y are not equal
    assert_eq!(x.len(), y.len());
    let n = x.len();
    let mut d = 0u32;
    for i in 0..n {
        d |= (x[i] ^ y[i]) as u32;
    }
    (1 & (d.wrapping_sub(1) >> 8)).wrapping_sub(1) as isize /* returns 0 if equal, 0xFF..FF otherwise */
}

fn crypto_verify_16(x: &[u8], y: &[u8]) -> isize {
    debug_assert_eq!(x.len(), 16);
    vn(x, y)
}

fn crypto_verify_32(x: &[u8], y: &[u8]) -> isize {
    debug_assert_eq!(x.len(), 32);
    vn(x, y)
}

fn core(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8], h: bool) {
    debug_assert_eq!(out.len(), if h { 32 } else { 64 });
    debug_assert_eq!(inp.len(), 16);
    debug_assert_eq!(k.len(), 32);
    debug_assert_eq!(c.len(), 16);

    let mut w = [0u32; 16];
    let mut x = [0u32; 16];
    let mut y = [0u32; 16];
    let mut t = [0u32; 4];

    for i in 0..4 {
        x[5*i] = ld32(sl4!(&c, 4*i));
        x[1+i] = ld32(sl4!(&k, 4*i));
        x[6+i] = ld32(sl4!(&inp, 4*i));
        x[11+i] = ld32(sl4!(&k, 16+4*i));
    }

    for i in 0..16 { y[i] = x[i] }

    for _ in 0..20 {
        for j in 0..4 {
            for m in 0..4 { t[m] = x[(5*j+4*m)%16] }
            t[1] ^= L32(t[0].wrapping_add(t[3]), 7);
            t[2] ^= L32(t[1].wrapping_add(t[0]), 9);
            t[3] ^= L32(t[2].wrapping_add(t[1]),13);
            t[0] ^= L32(t[3].wrapping_add(t[2]),18);
            for m in 0..4 { w[4*j+(j+m)%4] = t[m] }
        }
        for m in 0..16 { x[m] = w[m] }
    }

    if h {
        for i in 0..16 { x[i] = x[i].wrapping_add(y[i]) }
        for i in 0..4 {
            x[5*i] = x[5*i].wrapping_sub(ld32(sl4!(&c, 4*i)));
            x[6+i] = x[6+i].wrapping_sub(ld32(sl4!(&inp, 4*i)));
        }
        for i in 0..4 {
            st32(sl4!(&mut out, 4*i), x[5*i]);
            st32(sl4!(&mut out, 16+4*i), x[6+i]);
        }
    } else {
        for i in 0..16 { st32(sl4!(&mut out, 4*i), x[i].wrapping_add(y[i])) }
    }
}

pub fn crypto_core_salsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8])
{
    core(out, inp, k, c, false);
}

pub fn crypto_core_hsalsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8])
{
    core(out, inp, k, c, true);
}

const SIGMA: &'static [u8; 16] = b"expand 32-byte k";

pub fn crypto_stream_salsa20_xor(mut c: &mut[u8], mut m: &[u8], n: &[u8], k: &[u8]) {
    debug_assert!(m.len() == 0 || m.len() == c.len());
    debug_assert!(n.len() >= 8);
    let mut b = c.len();
    let mut z = [0u8; 16];
    let mut x = [0u8; 64];
    let mut u: u32;
    if b == 0 {
        return;
    }
    // omitted: FOR(i,16) z[i] = 0;
    for i in 0..8 {
        z[i] = n[i];
    }
    while b >= 64 {
        crypto_core_salsa20(&mut x, &z, k, SIGMA);
        for i in 0..64 {
            c[i] = if m.len() > 0 { m[i] } else { 0u8 } ^ x[i]; // c[i] = (m?m[i]:0) ^ x[i];
        }
        u = 1;
        for i in 8..16 {
            u += z[i] as u32;
            z[i] = u as u8;
            u >>= 8;
        }
        b -= 64;
        c = &mut {c}[64..];
        if m.len() > 0 {
            m = &m[64..];
        }
    }
    if b > 0 {
        crypto_core_salsa20(&mut x, &z, k, SIGMA);
        for i in 0..b {
            c[i] = if m.len() > 0 { m[i] } else { 0 } ^ x[i]; // c[i] = (m?m[i]:0) ^ x[i];
        }
    }
}

pub fn crypto_stream_salsa20(c: &mut[u8], n: &[u8], k: &[u8]) {
    crypto_stream_salsa20_xor(c, &[], n, k)
}

pub fn crypto_stream(c: &mut[u8], n: &[u8], k: &[u8]) {
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s, &n[..16], k, SIGMA);
    crypto_stream_salsa20(c, &n[16..], &s)
}

pub fn crypto_stream_xor(c: &mut[u8], m: &[u8], n: &[u8], k: &[u8]) {
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s, &n[..16], k, SIGMA);
    crypto_stream_salsa20_xor(c, m, &n[16..], &s)
}

fn add1305(h: &mut [u32], c: &[u32]) {
    debug_assert_eq!(h.len(), 17);
    debug_assert_eq!(c.len(), 17);
    let mut u = 0u32;
    for j in 0..17 {
        u = u.wrapping_add(h[j].wrapping_add(c[j]));
        h[j] = u & 255;
        u >>= 8;
    }
}

const minusp : [u32; 17] = [
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];

pub fn crypto_onetimeauth(out: &mut[u8], mut m: &[u8], k: &[u8]) {
    debug_assert_eq!(out.len(), 16);
    let mut n = m.len();

    let s: u32;
    let mut u: u32;
    let mut x = [0u32; 17];
    let mut r = [0u32; 17];
    let mut h = [0u32; 17];
    let mut c = [0u32; 17];
    let mut g = [0u32; 17];

    // omitted: FOR(j,17) r[j]=h[j]=0;
    for j in 0..16 { r[j] = k[j] as u32 }
    r[3]&=15;
    r[4]&=252;
    r[7]&=15;
    r[8]&=252;
    r[11]&=15;
    r[12]&=252;
    r[15]&=15;

    while n > 0 {
        for j in 0..17 { c[j] = 0 }
        let j_end = min(16, n);
        for j in 0..j_end { c[j] = m[j] as u32 }
        c[j_end] = 1;
        m = &m[j_end..]; n -= j_end;
        add1305(&mut h, &c);
        for i in 0..17 {
            x[i] = 0;
            for j in 0..17 {
                x[i] = x[i].wrapping_add(h[j].wrapping_mul(if j <= i { r[i-j] } else { 320u32.wrapping_mul(r[i+17-j]) }));
            }
        }
        for i in 0..17 { h[i] = x[i] }
        u = 0;
        for j in 0..16 {
            u = u.wrapping_add(h[j]);
            h[j] = u & 255;
            u >>= 8;
        }
        u = u.wrapping_add(h[16]); h[16] = u & 3;
        u = 5u32.wrapping_mul(u >> 2);
        for j in 0..16 {
            u = u.wrapping_add(h[j]);
            h[j] = u & 255;
            u >>= 8;
        }
        u = u.wrapping_add(h[16]); h[16] = u;
    }

    for j in 0..17 { g[j] = h[j] }
    add1305(&mut h, &minusp);
    s = (h[16] >> 7).wrapping_neg();
    for j in 0..17 { h[j] ^= s & (g[j] ^ h[j]) }

    for j in 0..16 { c[j] = k[j + 16] as u32 }
    c[16] = 0;
    add1305(&mut h, &c);
    for j in 0..16 { out[j] = h[j] as u8 }
}

pub fn crypto_onetimeauth_verify(h: &[u8], m: &[u8], k: &[u8]) -> isize {
    let mut x = [0u8; 16];
    crypto_onetimeauth(&mut x, m, k);
    crypto_verify_16(&h[..16], &x)
}

pub fn crypto_secretbox(c: &mut[u8], m: &[u8], n: &[u8], k: &[u8]) -> Result<(),CryptoError> {
    debug_assert_eq!(c.len(), m.len());
    if c.len() < 32 { return Err(CryptoError) }
    crypto_stream_xor(c, m, n, k);
    let mut x = [0u8; 16];
    crypto_onetimeauth(&mut x, &c[32..], c);
    c[16..32].copy_from_slice(&x);
    for i in 0..16 { c[i] = 0 }
    Ok(())
}

pub fn crypto_secretbox_open(m: &mut[u8], c: &[u8], n: &[u8], k: &[u8]) -> Result<(),CryptoError> {
    debug_assert_eq!(m.len(), c.len());
    let mut x = [0u8; 32];
    if m.len() < 32 { return Err(CryptoError) }
    crypto_stream(&mut x, n, k);
    if crypto_onetimeauth_verify(&c[16..], &c[32..], &x) != 0 {
        return Err(CryptoError);
    }
    crypto_stream_xor(m, c, n, k);
    for i in 0..32 { m[i] = 0 }
    Ok(())
}
