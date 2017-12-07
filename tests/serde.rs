#![cfg(feature="serde")]
#![cfg(feature="ring")]

extern crate rmp_serde;
extern crate merkle_rs;
extern crate serde;


use merkle_rs::KeyPair;
use serde::Serialize;


#[test]
fn keypair_serde() {
    let kp = KeyPair::new().unwrap();
    let mut buf = Vec::new();
    kp.serialize(&mut rmp_serde::Serializer::new(&mut buf))
        .unwrap();
    let buf2 = buf.clone();
    let mut de = rmp_serde::Deserializer::new(&buf[..]);
    let x: KeyPair = serde::Deserialize::deserialize(&mut de).unwrap();
    let mut buf = Vec::new();
    x.serialize(&mut rmp_serde::Serializer::new(&mut buf))
        .unwrap();
    assert!(buf == buf2);
    assert!(kp.pub_key() == x.pub_key());
}
