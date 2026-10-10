//! This module implements the NOISE framework part of the Wireguard
//! implementation.
//!
//! This is taken from wireguard-rs (MIT licensed)

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub const ZERO_NONCE: [u8; 12] = [0u8; 12];

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = blake2::Blake2s::new();
        $(
            hsh.update($input);
        )*
        Into::<[u8; 32]>::into(hsh.finalize())
    }};
}

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::{Mac, NewMac, Hmac};
        type HMACBlake2s = Hmac<blake2::Blake2s>;
        let mut mac = HMACBlake2s::new_varkey($key).unwrap();
        $(
            mac.update($input);
        )*
        mac.finalize().into_bytes()
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
            .encrypt(
                &crate::noise::ZERO_NONCE.into(),
                Payload { msg: $pt, aad: $ad },
            )
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    };
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {{
        use aead::{Aead, NewAead, Payload};
        chacha20poly1305::ChaCha20Poly1305::new(generic_array::GenericArray::from_slice($key))
            .decrypt(
                &crate::noise::ZERO_NONCE.into(),
                Payload { msg: $ct, aad: $ad },
            )
            //.map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    }};
}

pub(crate) use {HASH, HMAC, KDF1, KDF2, OPEN, SEAL};

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
