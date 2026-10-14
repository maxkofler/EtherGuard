//! Wireguard handshake handling from the `Responder` side

use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::{IntoBytes, little_endian::U32};
use zeroize::{ZeroizeOnDrop, zeroize_stack};

use crate::{
    STRING_WG_CONSTRUCTION, STRING_WG_IDENTIFIER, STRING_WG_LABEL_MAC1,
    message::{InitiatorToResponder, ResponderToInitiator},
    noise::{HASH, MAC, SEAL},
    state::State,
};

const ZEROIZE_STACK_OCTETS: usize = 4096;

#[derive(ZeroizeOnDrop)]
pub struct ResponderState {
    c: [u8; 32],
    h: [u8; 32],

    // TODO: Move this out!!!
    e_pub_i: PublicKey,
    s_pub_i: PublicKey,
}

impl State for ResponderState {
    fn set_c(&mut self, c: [u8; 32]) {
        println!("C update: {c:02X?}");
        self.c = c
    }

    fn get_c(&self) -> &[u8; 32] {
        &self.c
    }

    fn set_h(&mut self, h: [u8; 32]) {
        println!("H update: {h:02X?}");
        self.h = h;
    }

    fn get_h(&self) -> &[u8; 32] {
        &self.h
    }
}

impl ResponderState {
    pub fn new() -> Self {
        let c: [u8; 32] = HASH!(STRING_WG_CONSTRUCTION.as_bytes());
        let h = HASH!(&c, STRING_WG_IDENTIFIER.as_bytes());

        let s = Self {
            c,
            h,
            e_pub_i: PublicKey::from([0; 32]),
            s_pub_i: PublicKey::from([0; 32]),
        };
        s.debug_c();
        s.debug_h();
        s
    }

    fn debug_h(&self) {
        println!("H: {:02X?}", self.h)
    }

    fn debug_c(&self) {
        println!("C: {:02X?}", self.c)
    }

    pub fn consume_itor(&mut self, itor: &InitiatorToResponder, s_priv_r: &StaticSecret) {
        self.inner_consume_itor(itor, s_priv_r);
        zeroize_stack::<ZEROIZE_STACK_OCTETS>();
    }

    #[inline(never)]
    fn inner_consume_itor(&mut self, itor: &InitiatorToResponder, s_priv_r: &StaticSecret) {
        let key = self.derive_key_static(s_priv_r, &PublicKey::from(itor.ephemeral));
        let s_pub_i = self.open_static(key, &itor.k_static);
        self.chain_hash_h(&itor.k_static);
        println!("Public Key: {:02X?}", s_pub_i.as_bytes());

        let key = self.derive_key_timestamp(s_priv_r, &s_pub_i);
        let timestamp = self.open_timestamp(key, &itor.timestamp);
        self.chain_hash_h(&itor.timestamp);

        self.s_pub_i = s_pub_i;
        self.e_pub_i = PublicKey::from(itor.ephemeral);

        println!("Timestamp: {timestamp:02X?}");
    }

    pub fn create_rtoi<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        sender: U32,
        receiver: U32,
    ) -> ResponderToInitiator {
        let r = self.inner_create_rtoi(rng, sender, receiver);
        zeroize_stack::<ZEROIZE_STACK_OCTETS>();
        r
    }

    fn inner_create_rtoi<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        sender: U32,
        receiver: U32,
    ) -> ResponderToInitiator {
        let e_priv_r = StaticSecret::random_from_rng(rng);
        let e_pub_r = PublicKey::from(&e_priv_r);
        let e_pub_i = self.e_pub_i.clone();
        let s_pub_i = self.s_pub_i.clone();

        let key = self.derive_key_empty(&e_priv_r, [0; 32], &e_pub_i, &s_pub_i);

        let mut empty = [0u8; 16];
        SEAL!(
            key,
            &self.h,    // ad
            &[],        // pt
            &mut empty  // ct || tag
        );

        self.chain_hash_h(&empty);

        let x = HASH!(STRING_WG_LABEL_MAC1.as_bytes(), self.s_pub_i.as_bytes());

        let mut r = ResponderToInitiator {
            sender,
            receiver,
            ephemeral: e_pub_r.to_bytes(),
            empty,
            mac1: [0; 16],
            mac2: [0; 16],
        };

        let rtoi = r.as_bytes();
        let mut data = vec![0u8; rtoi.len() + 4];
        data[0] = 0x2;
        (&mut data[4..]).copy_from_slice(rtoi);

        let mac1 = MAC!(x, &data[..(data.len() - 32)]);
        r.mac1 = mac1;

        r
    }
}
