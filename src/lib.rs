extern crate digest as extern_digest;
extern crate untrusted;
extern crate typenum;

#[cfg(feature = "ring")]
extern crate ring;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod merkle;
#[cfg(feature = "ring")]
mod signed_merkle;
pub mod digest;
pub mod proof;

pub use merkle::MerkleTree;
pub use merkle::OwningMerkleTree;
pub use merkle::TreeHead;
pub use proof::{InclusionProof, ConsistencyProof};

#[cfg(feature = "ring")]
pub use signed_merkle::{KeyPair,PubKey};
#[cfg(feature = "ring")]
pub use signed_merkle::SignedMerkleTree;
#[cfg(feature = "ring")]
pub use signed_merkle::SignedOwningMerkleTree;
#[cfg(feature = "ring")]
pub use signed_merkle::SignedTreeHead;
#[cfg(feature = "ring")]
pub use proof::{SignedInclusionProof,SignedConsistencyProof};
