//! This module implements the NOISE framework part of the Wireguard
//! implementation.
//!
//! This is taken from wireguard-rs (MIT licensed)

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub const ZERO_NONCE: [u8; 12] = [0u8; 12];

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::{Digest, Blake2s256};
        let mut hsh = Blake2s256::new();
        $(
            hsh.update($input);
        )*
        Into::<[u8; 32]>::into(hsh.finalize())
    }};
}

macro_rules! MAC {
    ( $key:expr, $($input:expr),* ) => {{
        use blake2::Blake2sMac;
        use hmac::KeyInit;
        use blake2::digest::{Update, FixedOutput};
        use chacha20poly1305::Key;
        use generic_array::typenum::U16;

        let key = Key::from($key);

        let mut mac = Blake2sMac::<U16>::new(&key);
        $(
            mac.update($input);
        )*
        Into::<[u8; 16]>::into(mac.finalize_fixed())
    }};
}

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::{SimpleHmac, KeyInit, Mac};
        type HMACBlake2s = SimpleHmac<blake2::Blake2s256>;
        let mut mac = HMACBlake2s::new_from_slice($key).unwrap();
        $(
            mac.update($input);
        )*
        Into::<[u8; 32]>::into(mac.finalize().into_bytes())
    }};
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        use crate::noise::HMAC;
        use clear_on_drop::clear::Clear;
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        Into::<[u8; 32]>::into(t1)
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        use crate::noise::HMAC;
        use clear_on_drop::clear::Clear;
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1, t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        use crate::noise::HMAC;
        use clear_on_drop::clear::Clear;
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();
        (t1, t2, t3)
    }};
}

macro_rules! SEAL {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, Key, KeyInit, Payload},
        };
        let key = Key::<ChaCha20Poly1305>::from($key);
        ChaCha20Poly1305::new(&key)
            .encrypt(
                &crate::noise::ZERO_NONCE.into(),
                Payload { msg: $pt, aad: $ad },
            )
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    }};
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, Key, KeyInit, Payload},
        };
        let key = Key::<ChaCha20Poly1305>::from($key);
        ChaCha20Poly1305::new(&key)
            .decrypt(
                &crate::noise::ZERO_NONCE.into(),
                Payload { msg: $ct, aad: $ad },
            )
            //.map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    }};
}

pub(crate) use {HASH, HMAC, KDF1, KDF2, KDF3, MAC, OPEN, SEAL};

// Computes an X25519 shared secret.
//
// This function wraps dalek to add a zero-check.
// This is not recommended by the Noise specification,
// but implemented in the kernel with which we strive for absolute equivalent behavior.
#[inline(always)]
pub fn shared_secret(sk: &StaticSecret, pk: &PublicKey) -> Result<SharedSecret, ()> {
    let ss = sk.diffie_hellman(pk);
    if ss.as_bytes().ct_eq(&[0u8; 32]).into() {
        panic!();
        //Err(HandshakeError::InvalidSharedSecret)
    } else {
        Ok(ss)
    }
}
