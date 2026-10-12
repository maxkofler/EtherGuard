use rand::{CryptoRng, Rng};
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::{IntoBytes, little_endian::U32};
use zeroize::{ZeroizeOnDrop, zeroize_stack};

use crate::{
    STRING_WG_CONSTRUCTION, STRING_WG_IDENTIFIER, STRING_WG_LABEL_MAC1,
    message::{InitiatorToResponder, ResponderToInitiator},
    noise::{HASH, KDF1, KDF2, KDF3, MAC, OPEN, SEAL, shared_secret},
};

const ZEROIZE_STACK_OCTETS: usize = 4096;

#[derive(ZeroizeOnDrop)]
pub struct HandshakeState {
    c: [u8; 32],
    h: [u8; 32],

    // TODO: Move this out!!!
    e_pub_i: PublicKey,
    s_pub_i: PublicKey,
}

impl HandshakeState {
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
        let s_pub_r = PublicKey::from(s_priv_r);
        self.h = HASH!(&self.h, s_pub_r.as_bytes());
        self.debug_h();

        self.c = KDF1!(&self.c, &itor.ephemeral);
        self.debug_c();

        self.h = HASH!(&self.h, itor.ephemeral);
        self.debug_h();

        self.e_pub_i = PublicKey::from(itor.ephemeral);
        let (c, key) = KDF2!(
            &self.c,
            shared_secret(&s_priv_r, &self.e_pub_i).unwrap().as_bytes()
        );
        self.c = c.into();
        self.debug_c();

        let mut s_pub_i = [0u8; 32];
        OPEN!(
            key,
            &self.h,        // ad
            &mut s_pub_i,   // pt
            &itor.k_static  // ct || tag
        )
        .unwrap();
        self.s_pub_i = PublicKey::from(s_pub_i);

        println!("SpubI: {:02x?}", s_pub_i);
        let s_pub_i = PublicKey::from(s_pub_i);

        self.h = HASH!(self.h, itor.k_static);
        self.debug_h();
        let (c, key) = KDF2!(
            &self.c,
            shared_secret(&s_priv_r, &s_pub_i).unwrap().as_bytes()
        );
        self.c = c.into();
        self.debug_c();

        let mut timestamp = [0u8; 12];
        OPEN!(
            key,
            &self.h,         // ad
            &mut timestamp,  // pt
            &itor.timestamp  // ct || tag
        )
        .unwrap();

        println!("Timestamp: {timestamp:02x?}");

        self.h = HASH!(self.h, itor.timestamp);
        self.debug_h();
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
        //let eph_sk = StaticSecret::new(rng);
        let e_priv_r = StaticSecret::random_from_rng(rng);
        let e_pub_r = PublicKey::from(&e_priv_r);

        self.c = KDF1!(&self.c, e_pub_r.as_bytes());
        self.debug_c();

        self.h = HASH!(self.h, e_pub_r.as_bytes());
        self.debug_h();

        self.c = KDF1!(
            &self.c,
            shared_secret(&e_priv_r, &self.e_pub_i).unwrap().as_bytes()
        );
        self.debug_c();

        self.c = KDF1!(
            &self.c,
            shared_secret(&e_priv_r, &self.s_pub_i).unwrap().as_bytes()
        );
        self.debug_c();

        let preshared_key = [0u8; 32];
        let (c, t, k) = KDF3!(&self.c, &preshared_key);
        self.c = c;
        self.debug_c();

        self.h = HASH!(self.h, t);
        self.debug_h();

        let mut empty = [0u8; 16];
        SEAL!(
            k,
            &self.h,    // ad
            &[],        // pt
            &mut empty  // ct || tag
        );

        self.h = HASH!(self.h, empty);
        self.debug_h();

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
