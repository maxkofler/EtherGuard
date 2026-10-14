use base64::prelude::*;
use rand::rngs::StdRng;
use std::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::{FromBytes, IntoBytes, little_endian::U32};

use wireguard::{message::InitiatorToResponder, state::responder::ResponderState};

fn main() {
    println!("Hello, world!");

    let socket = UdpSocket::bind("0.0.0.0:51821").unwrap();
    loop {
        let mut buf = [0u8; 4096];
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        let buf = &buf[..len];

        //println!("RX: {:x?} ({})", buf, buf.len());
        let ret = match buf[0] {
            0x01 => handle_itor(&buf[4..]),
            _ => {
                println!("Unknown Message!");
                Vec::new()
            }
        };

        if !ret.is_empty() {
            //println!("TX: {:x?}", ret);
            socket.send_to(&ret, src).unwrap();
        }
    }
}

fn handle_itor(data: &[u8]) -> Vec<u8> {
    let itor = InitiatorToResponder::ref_from_bytes(data).unwrap();

    let pk = BASE64_STANDARD
        .decode("OBiSWNtYtsQ/iItAuEasPAZStJeTQ10cg1mzl2LSA1k=")
        .unwrap();
    let mut pkey = [0u8; 32];
    pkey.copy_from_slice(&pk);
    let privk = StaticSecret::from(pkey);
    let pubk = PublicKey::from(&privk);

    println!("Public key: {}", BASE64_STANDARD.encode(pubk.as_bytes()));

    let mut state = ResponderState::new();
    state.consume_itor(itor, &privk);

    println!("\n\n");

    let sender = U32::new(0x12345678);

    let mut rng: StdRng = rand::make_rng();
    let rtoi = state.create_rtoi(&mut rng, sender, itor.sender);

    let rtoi = rtoi.as_bytes();
    let mut data = vec![0u8; rtoi.len() + 4];
    data[0] = 0x2;
    (&mut data[4..]).copy_from_slice(rtoi);

    //data
    Vec::new()
}
