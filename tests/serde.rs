#![cfg(feature = "serde")]
#![cfg(feature = "ring")]

extern crate byteorder;
extern crate merkle_rs;
extern crate rmp_serde;
extern crate serde;
extern crate sha2;

use byteorder::{BigEndian, ByteOrder};
use merkle_rs::{digest, KeyPair, MerkleTree};
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

#[test]
fn tree_serde() {
    let mut mt = MerkleTree::<sha2::Sha256>::new();
    let hash = <sha2::Sha256 as digest::Digest>::hash_elem(&A(1));
    mt.insert(hash.clone());
    let mut buf = Vec::new();
    mt.serialize(&mut rmp_serde::Serializer::new(&mut buf))
        .unwrap();
    let buf2 = buf.clone();
    let mut de = rmp_serde::Deserializer::new(&buf[..]);
    let x: MerkleTree<sha2::Sha256> =
        serde::Deserialize::deserialize(&mut de).unwrap();
    let mut buf = Vec::new();
    x.serialize(&mut rmp_serde::Serializer::new(&mut buf))
        .unwrap();
    assert!(buf == buf2);
    assert!(x.inclusion_proof(hash).is_some());
}

#[derive(Hash, Eq, PartialEq)]
struct A(usize);

impl digest::Digestible for A {
    fn hash_bytes(&self, digest: &mut digest::Input) {
        let mut b = [0; 8];
        BigEndian::write_u64(&mut b, self.0 as u64);
        digest.process(&b)
    }
}
