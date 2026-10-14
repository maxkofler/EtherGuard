use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    STRING_WG_CONSTRUCTION, STRING_WG_IDENTIFIER,
    noise::{HASH, KDF1, KDF2, KDF3, OPEN, shared_secret},
};

pub mod responder;

pub(crate) trait State {
    fn set_c(&mut self, c: [u8; 32]);
    fn get_c(&self) -> &[u8; 32];

    fn set_h(&mut self, h: [u8; 32]);
    fn get_h(&self) -> &[u8; 32];
    fn chain_hash_h(&mut self, data: &[u8]) {
        let h = self.get_h();
        self.set_h(HASH!(h, data));
    }

    fn derive_key_static(&mut self, s_priv_r: &StaticSecret, e_pub_i: &PublicKey) -> [u8; 32] {
        let s_pub_r = PublicKey::from(s_priv_r);

        self.set_c(HASH!(STRING_WG_CONSTRUCTION.as_bytes()));
        self.set_h(HASH!(self.get_c(), STRING_WG_IDENTIFIER.as_bytes()));
        self.chain_hash_h(s_pub_r.as_bytes());
        self.set_c(KDF1!(self.get_c(), e_pub_i.as_bytes()));
        self.chain_hash_h(e_pub_i.as_bytes());

        let (c, k) = KDF2!(
            self.get_c(),
            shared_secret(s_priv_r, e_pub_i).unwrap().as_bytes()
        );
        self.set_c(c);

        k
    }

    fn open_static(&mut self, key: [u8; 32], sealed_static: &[u8; 48]) -> PublicKey {
        let mut opened_static = [0u8; 32];
        OPEN!(key, self.get_h(), &mut opened_static, sealed_static).unwrap();

        PublicKey::from(opened_static)
    }

    fn derive_key_timestamp(&mut self, s_priv_r: &StaticSecret, s_pub_i: &PublicKey) -> [u8; 32] {
        let (c, k) = KDF2!(
            self.get_c(),
            shared_secret(s_priv_r, s_pub_i).unwrap().as_bytes()
        );
        self.set_c(c);

        k
    }

    fn open_timestamp(&mut self, key: [u8; 32], sealed_timestamp: &[u8; 28]) -> [u8; 12] {
        let mut opened_timestamp = [0u8; 12];
        OPEN!(
            key,
            self.get_h(),          // ad
            &mut opened_timestamp, // pt
            sealed_timestamp       // ct || tag
        )
        .unwrap();

        opened_timestamp
    }

    fn derive_key_empty(
        &mut self,
        e_priv_r: &StaticSecret,
        preshared_key: [u8; 32],
        e_pub_i: &PublicKey,
        s_pub_i: &PublicKey,
    ) -> [u8; 32] {
        let e_pub_r = PublicKey::from(e_priv_r);

        self.set_c(KDF1!(self.get_c(), e_pub_r.as_bytes()));
        self.chain_hash_h(e_pub_r.as_bytes());

        self.set_c(KDF1!(
            self.get_c(),
            shared_secret(&e_priv_r, e_pub_i).unwrap().as_bytes()
        ));

        self.set_c(KDF1!(
            self.get_c(),
            shared_secret(&e_priv_r, s_pub_i).unwrap().as_bytes()
        ));

        let (c, t, k) = KDF3!(self.get_c(), &preshared_key);
        self.set_c(c);

        self.chain_hash_h(&t);

        k
    }
}
