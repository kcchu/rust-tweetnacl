#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

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


macro_rules! sl32 {
    (&mut $s:expr, $b:expr) => {
        &mut $s[($b)..(($b) + 4)];
    };
    (& $s:expr, $b:expr) => {
        & $s[($b)..(($b) + 4)];
    };
}

#[inline(always)]
fn L32(x: u32, c: isize) -> u32 {
    (x << c) | ((x & 0xffffffff) >> (32 - c))
}

#[inline(always)]
fn ld32(x: &[u8]) -> u32 {
    debug_assert_eq!(x.len(), 4);
    let mut u = x[3] as u32;
    u = (u << 8) | x[2] as u32;
    u = (u << 8) | x[1] as u32;
    (u << 8) | x[0] as u32
}

#[inline(always)]
fn dl64(x: &[u8]) -> u64 {
    debug_assert_eq!(x.len(), 8);
    let mut u = 0u64;
    for i in 0..8 { u = (u << 8) | x[i] as u64 }
    u
}

#[inline(always)]
fn st32(x: &mut [u8], u: u32) {
    debug_assert_eq!(x.len(), 4);
    let mut u = u;
    for i in 0..4 { x[i] = u as u8; u >>= 8; }
}

#[inline(always)]
fn ts64(x: &mut [u8], u: u64) {
    debug_assert_eq!(x.len(), 8);
    let mut u = u;
    for i in (0..8).rev() { x[i] = u as u8; u >>= 8; }
}

#[inline(always)]
fn vn(x: &[u8], y: &[u8]) -> isize {
    debug_assert_eq!(x.len(), y.len());
    let mut d = 0u32;
    for i in 0..x.len() {
        d |= (x[i] ^ y[i]) as u32;
    }
    (1 & (d.wrapping_sub(1) >> 8)).wrapping_sub(1) as isize /* returns 0 if equal, 0xFF..FF otherwise */
}

fn crypto_verify_16(x: &[u8], y: &[u8]) -> isize {
    debug_assert_eq!(x.len(), 16);
    debug_assert_eq!(y.len(), 16);
    vn(x, y)
}

fn crypto_verify_32(x: &[u8], y: &[u8]) -> isize {
    debug_assert_eq!(x.len(), 32);
    debug_assert_eq!(y.len(), 32);
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
        x[5*i] = ld32(sl32!(&c, 4*i));
        x[1+i] = ld32(sl32!(&k, 4*i));
        x[6+i] = ld32(sl32!(&inp, 4*i));
        x[11+i] = ld32(sl32!(&k, 16+4*i));
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
            x[5*i] = x[5*i].wrapping_sub(ld32(sl32!(&c, 4*i)));
            x[6+i] = x[6+i].wrapping_sub(ld32(sl32!(&inp, 4*i)));
        }
        for i in 0..4 {
            st32(sl32!(&mut out, 4*i), x[5*i]);
            st32(sl32!(&mut out, 16+4*i), x[6+i]);
        }
    } else {
        for i in 0..16 { st32(sl32!(&mut out, 4*i), x[i].wrapping_add(y[i])) }
    }
}

pub fn crypto_core_salsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8]) -> isize
{
    core(out, inp, k, c, false);
    0
}


pub fn crypto_core_hsalsa20(out: &mut[u8], inp: &[u8], k: &[u8], c: &[u8]) -> isize
{
    core(out, inp, k, c, true);
    0
}

const SIGMA: &'static [u8; 16] = b"expand 32-byte k";

pub fn crypto_stream_salsa20_xor(mut c: &mut[u8], mut m: &[u8], mut b: usize, n: &[u8], k: &[u8]) -> isize {
    debug_assert_eq!(c.len(), b as usize);
    debug_assert!(m.len() == 0 || m.len() == c.len());
    let mut z = [0u8; 16];
    let mut x = [0u8; 64];
    let mut u: u32;
    if b == 0 {
        return 0;
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
    0
}

pub fn crypto_stream_salsa20(c: &mut[u8], d: usize, n: &[u8], k: &[u8]) -> isize {
    crypto_stream_salsa20_xor(c, &[], d, n, k)
}

pub fn crypto_stream(c: &mut[u8], d: usize, n: &[u8], k: &[u8]) -> isize {
    debug_assert_eq!(n.len(), 24);
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s, &n[..16], k, SIGMA);
    crypto_stream_salsa20(c, d, &n[16..], &s)
}


pub fn crypto_stream_xor(c: &mut[u8], m: &[u8], d: usize, n: &[u8], k: &[u8]) -> isize {
    let mut s = [0u8; 32];
    crypto_core_hsalsa20(&mut s, &n[..16], k, SIGMA);
    crypto_stream_salsa20_xor(c, m, d, &n[16..], &s)
}