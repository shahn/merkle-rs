extern crate digest as extern_digest;
extern crate untrusted;

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
#[cfg(feature = "ring")]
pub use signed_merkle::KeyPair;
#[cfg(feature = "ring")]
pub use signed_merkle::SignedMerkleTree;
#[cfg(feature = "ring")]
pub use signed_merkle::SignedOwningMerkleTree;
