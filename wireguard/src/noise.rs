//! This module implements the NOISE framework part of the Wireguard
//! implementation.
//!
//! This is taken from wireguard-rs (MIT licensed)

use crate::{STRING_WG_CONSTRUCTION, STRING_WG_IDENTIFIER, message::InitiatorToResponder};

use chacha20poly1305::ChaCha20Poly1305;
use clear_on_drop::clear::Clear;

use generic_array::*;

use aead::{Aead, NewAead, Payload};
use blake2::Blake2s;
use hmac::Hmac;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

type HMACBlake2s = Hmac<Blake2s>;

const ZERO_NONCE: [u8; 12] = [0u8; 12];

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.update($input);
        )*
        Into::<[u8; 32]>::into(hsh.finalize())
    }};
}

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::{Mac, NewMac};
        let mut mac = HMACBlake2s::new_varkey($key).unwrap();
        $(
            mac.update($input);
        )*
        mac.finalize().into_bytes()
    }};
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        Into::<[u8; 32]>::into(t1)
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1, t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();
        (t1, t2, t3)
    }};
}

macro_rules! SEAL {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .encrypt(&ZERO_NONCE.into(), Payload { msg: $pt, aad: $ad })
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    };
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(&ZERO_NONCE.into(), Payload { msg: $ct, aad: $ad })
            //.map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    };
}

fn debug_hi(hash: &[u8; 32]) {
    println!("Hi: {hash:02x?}");
}

fn debug_ci(hash: &[u8; 32]) {
    println!("Ci: {hash:02x?}");
}

// Computes an X25519 shared secret.
//
// This function wraps dalek to add a zero-check.
// This is not recommended by the Noise specification,
// but implemented in the kernel with which we strive for absolute equivalent behavior.
#[inline(always)]
fn shared_secret(sk: &StaticSecret, pk: &PublicKey) -> Result<SharedSecret, ()> {
    let ss = sk.diffie_hellman(pk);
    if ss.as_bytes().ct_eq(&[0u8; 32]).into() {
        panic!();
        //Err(HandshakeError::InvalidSharedSecret)
    } else {
        Ok(ss)
    }
}

pub fn run_itor(itor: &InitiatorToResponder, s_pub_r: PublicKey, s_priv_r: StaticSecret) {
    let ci: [u8; 32] = HASH!(STRING_WG_CONSTRUCTION.as_bytes());
    debug_ci(&ci);

    let hi = HASH!(&ci, STRING_WG_IDENTIFIER.as_bytes());
    debug_hi(&hi);

    let hi = HASH!(&hi, s_pub_r.as_bytes());
    debug_hi(&hi);

    let ci = KDF1!(&ci, &itor.ephemeral);
    debug_ci(&ci);

    let hi = HASH!(&hi, itor.ephemeral);
    debug_hi(&hi);

    let e_pub_i = PublicKey::from(itor.ephemeral);
    let (ci, key) = KDF2!(&ci, shared_secret(&s_priv_r, &e_pub_i).unwrap().as_bytes());
    let ci: [u8; 32] = ci.into();
    debug_ci(&ci);

    let mut s_pub_i = [0u8; 32];
    OPEN!(
        &key,
        &hi,            // ad
        &mut s_pub_i,   // pt
        &itor.k_static  // ct || tag
    )
    .unwrap();

    println!("SpubI: {:02x?}", s_pub_i);
    let s_pub_i = PublicKey::from(s_pub_i);

    let hi = HASH!(hi, itor.k_static);
    debug_hi(&hi);
    let (ci, key) = KDF2!(&ci, shared_secret(&s_priv_r, &s_pub_i).unwrap().as_bytes());
    let ci: [u8; 32] = ci.into();
    debug_ci(&ci);

    let mut timestamp = [0u8; 12];
    OPEN!(
        &key,
        &hi,             // ad
        &mut timestamp,  // pt
        &itor.timestamp  // ct || tag
    )
    .unwrap();

    println!("Timestamp: {timestamp:02x?}");

    let hi = HASH!(hi, itor.timestamp);
    debug_hi(&hi);
}
