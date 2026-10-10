use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    STRING_WG_CONSTRUCTION, STRING_WG_IDENTIFIER,
    message::InitiatorToResponder,
    noise::{HASH, KDF1, KDF2, OPEN, shared_secret},
};

pub struct HandshakeState {
    c: [u8; 32],
    h: [u8; 32],
}

impl HandshakeState {
    pub fn new() -> Self {
        let c: [u8; 32] = HASH!(STRING_WG_CONSTRUCTION.as_bytes());
        let h = HASH!(&c, STRING_WG_IDENTIFIER.as_bytes());

        let s = Self { c, h };
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
        let s_pub_r = PublicKey::from(s_priv_r);
        self.h = HASH!(&self.h, s_pub_r.as_bytes());
        self.debug_h();

        self.c = KDF1!(&self.c, &itor.ephemeral);
        self.debug_c();

        self.h = HASH!(&self.h, itor.ephemeral);
        self.debug_h();

        let e_pub_i = PublicKey::from(itor.ephemeral);
        let (c, key) = KDF2!(
            &self.c,
            shared_secret(&s_priv_r, &e_pub_i).unwrap().as_bytes()
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
}
