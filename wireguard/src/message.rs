use zerocopy::{FromBytes, Immutable, KnownLayout, little_endian::U32};

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
