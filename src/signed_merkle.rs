use digest::{Digest, Digestible};
use digest::Hash;

use merkle::{MerkleTree, TreeHead};
use proof::*;

use proof::SignedInclusionProof;
use ring::{rand, signature};
#[cfg(feature = "serde")]
use serde::de::{self, Deserialize, Deserializer};

use std::{fmt, iter};
use std::error::Error;
use untrusted;

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone)]
pub struct SignedTreeHead<D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    th: TreeHead<D>,
    sig: Vec<u8>,
}

impl<D: Digest> SignedTreeHead<D> {
    fn new(kp: &KeyPair, th: TreeHead<D>) -> Self {
        Self {
            sig: Vec::from(kp.sign(th.root_hash().as_slice()).as_ref()),
            th,
        }
    }

    pub fn verify(&self, pubkey: &PubKey) -> bool {
        signature::verify(
            &signature::ED25519,
            untrusted::Input::from(&pubkey.0[..]),
            untrusted::Input::from(self.th.root_hash()),
            untrusted::Input::from(self.sig.as_slice()),
        ).is_ok()
    }

    pub fn size(&self) -> u64 {
        self.th.size()
    }

    pub fn root_hash(&self) -> &Hash<D> {
        self.th.root_hash()
    }
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SignedMerkleTree<D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    mt: MerkleTree<D>,
    keypair: KeyPair,
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    sth: SignedTreeHead<D>,
}

impl<D: Digest> SignedMerkleTree<D> {
    pub fn new(keypair: KeyPair) -> Self {

        let mt = MerkleTree::new();
        let sth = SignedTreeHead::new(&keypair, mt.head());

        Self { mt, keypair, sth }
    }

    pub fn insert(&mut self, hash: Hash<D>) -> bool {
        if self.mt.insert(hash) {
            self.sth = SignedTreeHead::new(&self.keypair, self.mt.head());
            true
        } else {
            false
        }
    }

    pub fn head(&self) -> SignedTreeHead<D> {
        self.sth.clone()
    }

    pub fn inclusion_proof(
        &self,
        h: Hash<D>,
    ) -> Option<SignedInclusionProof<D>> {
        InclusionProofBase::new(h, &self.mt).map(|x| {
            SignedInclusionProof::new(x, self.head())
        })
    }

    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Option<SignedConsistencyProof<D>> {
        ConsistencyProofBase::new(old_size, &self.mt).map(|x| {
            SignedConsistencyProof::new(x, self.head())
        })
    }

    pub fn new_from_merkle_tree(keypair: KeyPair, mt: MerkleTree<D>) -> Self {
        let sth = SignedTreeHead::new(&keypair, mt.head());
        Self { mt, keypair, sth }
    }
}

impl<D: Digest> iter::Extend<Hash<D>> for SignedMerkleTree<D> {
    fn extend<T: IntoIterator<Item = Hash<D>>>(&mut self, iter: T) {
        self.mt.extend(iter);
        self.sth = SignedTreeHead::new(&self.keypair, self.mt.head());
    }
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SignedOwningMerkleTree<T: Digestible, D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    smt: SignedMerkleTree<D>,
    objs: Vec<T>,
}

impl<T: Digestible, D: Digest> SignedOwningMerkleTree<T, D> {
    pub fn new(keypair: KeyPair) -> Self {
        Self {
            smt: SignedMerkleTree::new(keypair),
            objs: Vec::new(),
        }
    }

    pub fn insert(&mut self, elem: T) -> bool {
        let hash = D::hash_elem(&elem);

        if self.smt.insert(hash) {
            self.objs.push(elem);
            true
        } else {
            false
        }
    }

    pub fn head(&self) -> SignedTreeHead<D> {
        self.smt.sth.clone()
    }

    pub fn inclusion_proof(
        &self,
        h: Hash<D>,
    ) -> Option<SignedInclusionProof<D>> {
        self.smt.inclusion_proof(h)
    }

    pub fn inclusion_proof_for_elem(
        &self,
        elem: &T,
    ) -> Option<SignedInclusionProof<D>> {
        self.smt.inclusion_proof(D::hash_elem(elem))
    }

    pub fn consistency_proof(
        &self,
        old_count: u64,
    ) -> Option<SignedConsistencyProof<D>> {
        self.smt.consistency_proof(old_count)
    }
}

// XXX this is super inefficient. This should do a bulk-update. Have to be
// careful not to insert duplicates into self.objs, though.
impl<T: Digestible, D: Digest> iter::Extend<T>
    for SignedOwningMerkleTree<T, D> {
    fn extend<S: IntoIterator<Item = T>>(&mut self, iter: S) {
        for x in iter {
            self.insert(x);
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct KeyPair {
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    kp: signature::Ed25519KeyPair,
    #[cfg(feature = "serde")]
    bytes: [[u8; 17]; 5], // Same size as signature::ED25519_PKCS8_V2_LEN
}

impl KeyPair {
    pub fn new() -> Result<Self, RingError> {
        let rng = rand::SystemRandom::new();
        let k_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let kp = signature::Ed25519KeyPair::from_pkcs8(
            untrusted::Input::from(&k_bytes),
        )?;
        Ok(Self {
            kp,
            #[cfg(feature = "serde")]
            bytes: unsafe { ::std::mem::transmute(k_bytes) },
        })
    }

    pub fn new_from_bytes(
        bytes: [u8; signature::ED25519_PKCS8_V2_LEN],
    ) -> Result<Self, RingError> {
        Ok(Self {
            kp: signature::Ed25519KeyPair::from_pkcs8(
                untrusted::Input::from(&bytes),
            )?,
            #[cfg(feature = "serde")]
            bytes: unsafe { ::std::mem::transmute(bytes) },
        })
    }

    pub fn pub_key(&self) -> PubKey {
        PubKey::new(self.kp.public_key_bytes())
    }

    fn sign(&self, d: &[u8]) -> signature::Signature {
        self.kp.sign(d)
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq)]
pub struct PubKey([u8; signature::ED25519_PUBLIC_KEY_LEN]);

impl PubKey {
    pub fn new(bytes: &[u8]) -> Self {
        let mut arr = [0; signature::ED25519_PUBLIC_KEY_LEN];
        arr.copy_from_slice(bytes);
        PubKey(arr)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        struct Bytes([[u8; 17]; 5]);

        let bytes = Bytes::deserialize(deserializer)?;

        let cbytes: [u8; signature::ED25519_PKCS8_V2_LEN] =
            unsafe { ::std::mem::transmute(bytes.0) };
        KeyPair::new_from_bytes(cbytes).map_err(de::Error::custom)
    }
}

#[derive(Debug)]
pub struct RingError;

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl Error for RingError {
    fn description(&self) -> &str {
        "An unspecified error occurred during key generation"
    }
}

impl From<::ring::error::Unspecified> for RingError {
    fn from(_: ::ring::error::Unspecified) -> Self {
        RingError
    }
}

impl<D: Digest> From<SignedMerkleTree<D>> for MerkleTree<D> {
    fn from(smt: SignedMerkleTree<D>) -> Self {
        smt.mt
    }
}

impl<T: Digestible, D: Digest> From<SignedOwningMerkleTree<T, D>>
    for MerkleTree<D> {
    fn from(somt: SignedOwningMerkleTree<T, D>) -> Self {
        somt.smt.mt
    }
}

impl<T: Digestible, D: Digest> From<SignedOwningMerkleTree<T, D>>
    for SignedMerkleTree<D> {
    fn from(somt: SignedOwningMerkleTree<T, D>) -> Self {
        somt.smt
    }
}
