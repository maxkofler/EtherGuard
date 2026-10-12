use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, little_endian::U32};

/// The `Initiator to Responder` message
#[derive(Debug, FromBytes, KnownLayout, Immutable)]
#[repr(packed)]
pub struct InitiatorToResponder {
    pub sender: U32,
    pub ephemeral: [u8; 32],
    pub k_static: [u8; 48],
    pub timestamp: [u8; 28],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(packed)]
pub struct ResponderToInitiator {
    pub sender: U32,
    pub receiver: U32,
    pub ephemeral: [u8; 32],
    pub empty: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}
