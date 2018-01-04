#![cfg(feature = "ring")]
extern crate byteorder;
extern crate merkle_rs;
extern crate ring;
extern crate sha2;
extern crate untrusted;

use byteorder::{BigEndian, ByteOrder};
use merkle_rs::{MerkleTree, OwningMerkleTree};
use merkle_rs::{SignedMerkleTree, SignedOwningMerkleTree};
use merkle_rs::KeyPair;
use merkle_rs::digest;
use std::iter::FromIterator;

#[test]
fn large_tree() {
    let max_size = 129;

    let kp = KeyPair::new().unwrap();
    let okp = KeyPair::new().unwrap();
    let pubk = kp.pub_key();
    let opubk = okp.pub_key();
    let mut mt = MerkleTree::<sha2::Sha256>::new();
    let mut omt = OwningMerkleTree::<A, sha2::Sha256>::new();
    let mut smt = SignedMerkleTree::<sha2::Sha256>::new(kp);
    let mut somt = SignedOwningMerkleTree::<A, sha2::Sha256>::new(okp);
    let mut heads = Vec::new();
    let mut oheads = Vec::new();
    let mut sheads = Vec::new();
    let mut soheads = Vec::new();

    let mut hashes = Vec::new();

    for i in 0..max_size {
        hashes.push(<sha2::Sha256 as digest::Digest>::hash_elem(&A(i)));
    }

    for i in 0..max_size {
        assert_eq!(mt.head().size(), i as u64);
        assert_eq!(omt.head().size(), i as u64);
        assert_eq!(smt.head().size(), i as u64);
        assert_eq!(somt.head().size(), i as u64);

        mt.insert(hashes[i]);
        omt.insert(A(i));
        smt.insert(hashes[i]);
        somt.insert(A(i));

        heads.push(mt.head());
        oheads.push(omt.head());
        sheads.push(smt.head());
        soheads.push(somt.head());

        assert!(sheads[i].verify(&pubk));
        assert!(soheads[i].verify(&opubk));

        assert!(!sheads[i].verify(&opubk));
        assert!(!soheads[i].verify(&pubk));

        assert!(heads[i].root_hash() == oheads[i].root_hash());
        assert!(heads[i].root_hash() == sheads[i].root_hash());
        assert!(heads[i].root_hash() == soheads[i].root_hash());

        for j in 0..i + 1 {
            assert!(!mt.insert(hashes[j]));
            assert!(!omt.insert(A(j)));
            assert!(!smt.insert(hashes[j]));
            assert!(!somt.insert(A(j)));

            assert!(mt.inclusion_proof(hashes[j]).unwrap().verify());
            assert!(omt.inclusion_proof(hashes[j]).unwrap().verify());
            assert!(omt.inclusion_proof(&A(j)).unwrap().verify());

            assert!(smt.inclusion_proof(hashes[j]).unwrap().verify(&pubk));
            assert!(somt.inclusion_proof(hashes[j]).unwrap().verify(&opubk));
            assert!(somt.inclusion_proof(&A(j)).unwrap().verify(&opubk));

            assert!(
                mt.consistency_proof(j as u64 + 1,)
                    .unwrap()
                    .verify(heads[j].root_hash(),)
            );
            assert!(
                omt.consistency_proof(j as u64 + 1,)
                    .unwrap()
                    .verify(heads[j].root_hash(),)
            );
            assert!(
                smt.consistency_proof(j as u64 + 1,)
                    .unwrap()
                    .verify(heads[j].root_hash(), &pubk,)
            );
            assert!(
                somt.consistency_proof(j as u64 + 1,)
                    .unwrap()
                    .verify(heads[j].root_hash(), &opubk,)
            );
        }

        #[cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]
        for j in i + 1..max_size {
            assert!(mt.inclusion_proof(hashes[j]).is_none());
            assert!(omt.inclusion_proof(hashes[j]).is_none());
            assert!(omt.inclusion_proof(&A(j)).is_none());

            assert!(smt.inclusion_proof(hashes[j]).is_none());
            assert!(somt.inclusion_proof(hashes[j]).is_none());
            assert!(somt.inclusion_proof(&A(j)).is_none());

            assert!(mt.consistency_proof(j as u64 + 1).is_none());
            assert!(omt.consistency_proof(j as u64 + 1).is_none());
            assert!(smt.consistency_proof(j as u64 + 1).is_none());
            assert!(somt.consistency_proof(j as u64 + 1).is_none());
        }
    }

    let kp = KeyPair::new().unwrap();
    let okp = KeyPair::new().unwrap();
    let pubk = kp.pub_key();
    let opubk = okp.pub_key();
    let mut bulkmt =
        MerkleTree::<sha2::Sha256>::from_iter(hashes.iter().cloned());
    let mut bulkomt =
        OwningMerkleTree::<A, sha2::Sha256>::from_iter((0..max_size).map(A));
    let mut bulksmt = SignedMerkleTree::<sha2::Sha256>::new(kp);
    let mut bulksomt = SignedOwningMerkleTree::<A, sha2::Sha256>::new(okp);

    assert!(bulkmt.head().root_hash() == heads[max_size - 1].root_hash());
    bulkmt.extend(hashes.iter().cloned());
    assert!(bulkmt.head().root_hash() == heads[max_size - 1].root_hash());

    assert!(bulkomt.head().root_hash() == oheads[max_size - 1].root_hash());
    bulkomt.extend((0..max_size).map(A));
    assert!(bulkomt.head().root_hash() == heads[max_size - 1].root_hash());

    bulksmt.extend(hashes.iter().cloned());
    assert!(bulksmt.head().root_hash() == sheads[max_size - 1].root_hash());
    assert!(bulksmt.head().verify(&pubk));

    bulksomt.extend((0..max_size).map(A));
    assert!(bulksomt.head().root_hash() == heads[max_size - 1].root_hash());
    assert!(bulksomt.head().verify(&opubk));
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
