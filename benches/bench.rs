#![feature(test)]

#![cfg(feature = "ring")]
extern crate ring;
extern crate sha2;
extern crate untrusted;
extern crate merkle_rs;
extern crate byteorder;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use byteorder::{BigEndian, ByteOrder};
use merkle_rs::{MerkleTree, OwningMerkleTree};
use merkle_rs::{SignedMerkleTree, SignedOwningMerkleTree};
use merkle_rs::KeyPair;
use merkle_rs::digest;

macro_rules! treetest {
    ( $size:expr, $fn1:ident, $fn2:ident, $fn3:ident, $fn4:ident ) => {
        #[bench]
        fn $fn1(b: &mut Bencher) {
            let mut hashes = Vec::new();
            for i in 0..$size {
                hashes.push(<sha2::Sha256 as digest::Digest>::hash_elem(&A(i)));
            }

            b.iter(|| {
                let mut mt = MerkleTree::<sha2::Sha256>::new();
                for i in 0..$size {
                    mt.insert(hashes[i]);
                }
                mt
            })
        }

        #[bench]
        fn $fn2(b: &mut Bencher) {

            b.iter(|| {
                let mut mt = OwningMerkleTree::<A, sha2::Sha256>::new();
                for i in 0..$size {
                    mt.insert(A(i));
                }
                mt
            })
        }

// Disabled for now, see XXX comment below for why.
//        #[cfg(feature = "ring")]
//        #[bench]
//        fn $fn3(b: &mut Bencher) {
//            let mut hashes = Vec::new();
//            for i in 0..$size {
//                hashes.push(<sha2::Sha256 as digest::Digest>::hash_elem(&A(i)));
//            }
//
//            b.iter(|| {
//                // XXX Creating the key here is dumb. It makes the benchmark kind of worthless
//                // because it might be expensive. We should do it above once KeyPair can be Clone.
//                let kp = KeyPair::new().unwrap();
//                let mut mt = SignedMerkleTree::<sha2::Sha256>::new(kp);
//                for i in 0..$size {
//                    mt.insert(hashes[i]);
//                }
//                mt
//            })
//        }
//
//        #[cfg(feature = "ring")]
//        #[bench]
//        fn $fn4(b: &mut Bencher) {
//
//            b.iter(|| {
//                // XXX see above
//                let kp = KeyPair::new().unwrap();
//                let mut mt = SignedOwningMerkleTree::<A, sha2::Sha256>::new(kp);
//                for i in 0..$size {
//                    mt.insert(A(i));
//                }
//                mt
//            })
//        }
    }
}


fn create_tree(c: &mut Criterion) {
    c.bench_function("create tree",
                     |b| b.iter(|| MerkleTree::<sha2::Sha256>::new()));
}

fn tree_insert(c: &mut Criterion) {
    let mut arr = [0; 3];
    for i in 0..3 {
        arr[i] = i;
    }
    c.bench_function_over_inputs("insert elem",
                                 |b, &&size| {
        b.iter_with_setup(move || {
            let mut mt = MerkleTree::<sha2::Sha256>::new();
            for i in 1..size {
                mt.insert(<sha2::Sha256 as digest::Digest>::hash_elem(&A(i)));
            }
            mt
        }, |mut tree| tree.insert(<sha2::Sha256 as digest::Digest>::hash_elem(&A(size))))
    },
    arr.iter());
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

criterion_group!(benches, create_tree, tree_insert);
criterion_main!(benches);
