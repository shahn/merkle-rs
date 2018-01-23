use digest::{Digest, Digestible};
use digest::AsHash;
use digest::Hash;
use merkle::{MerkleTree, OwningMerkleTree, TreeHead};
use proof::*;
use proof::SignedInclusionProof;
use ring::{rand, signature};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
use std::{fmt, iter};
use std::error::Error;
use untrusted;

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SignedTreeHead<D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    th: TreeHead<D>,
    sig: Vec<u8>,
}

impl<D: Digest> Clone for SignedTreeHead<D> {
    fn clone(&self) -> Self {
        SignedTreeHead {
            th: self.th.clone(),
            sig: self.sig.clone(),
        }
    }
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

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SignedOwningMerkleTree<T: Digestible, D: Digest> {
    #[cfg_attr(feature = "serde", serde(
            bound(serialize = "OwningMerkleTree<T, D>: Serialize",
                  deserialize = "OwningMerkleTree<T, D>: Deserialize<'de>")))]
    mt: OwningMerkleTree<T, D>,
    keypair: KeyPair,
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    sth: SignedTreeHead<D>,
}

macro_rules! impl_signed_tree {
    ( $name:ident, $base: ident, ($( $par:ident : $bound:ident, )*),
    $elt:ident, ($( $et_bound:ident, )*) ) => {
        impl<$( $par: $bound, )* D: Digest> $name<$( $par, )* D> {
            pub fn new(keypair: KeyPair) -> Self {
                let mt = $base::new();
                let sth = SignedTreeHead::new(&keypair, mt.head());

                Self { mt, keypair, sth }
            }

            pub fn from_unsigned(keypair: KeyPair,
                                 mt: $base<$( $par, )* D>) -> Self {
                let sth = SignedTreeHead::new(&keypair, mt.head());
                Self { mt, keypair, sth }
            }

            pub fn insert<$( $elt: AsHash<$et_bound> )*>(&mut self,
                                                         elem: $elt) -> bool {
                if self.mt.insert(elem) {
                    self.sth = SignedTreeHead::new(&self.keypair,
                                                   self.mt.head());
                    true
                } else {
                    false
                }
            }

            pub fn head(&self) -> SignedTreeHead<D> {
                self.sth.clone()
            }

            pub fn inclusion_proof<H: AsHash<D>>(
                &self,
                h: H,
            ) -> Option<SignedInclusionProof<D>> {
                let h = h.as_hash();
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
        }

        impl<$( $par: $bound, )* $( $elt: AsHash<$et_bound>, )* D: Digest>
                iter::Extend<$elt> for $name<$( $par, )* D> {
            fn extend<S: IntoIterator<Item = $elt>>(&mut
            self, iter: S) {
                self.mt.extend(iter);
                self.sth = SignedTreeHead::new(&self.keypair, self.mt.head())
            }
        }

        impl<$( $par: $bound, )* D: Digest> From<$name<$( $par, )* D>> for
        $base<$( $par, )* D> {
            fn from(mt: $name<$( $par, )* D>) -> Self {
                mt.mt
            }
        }
    }
}

impl_signed_tree!(SignedMerkleTree, MerkleTree, (), H, (D,));
impl_signed_tree!(
    SignedOwningMerkleTree,
    OwningMerkleTree,
    (T: Digestible,),
    T,
    ()
);

impl<T: Digestible, D: Digest> From<SignedOwningMerkleTree<T, D>>
    for MerkleTree<D>
{
    fn from(somt: SignedOwningMerkleTree<T, D>) -> Self {
        let omt: OwningMerkleTree<T, D> = From::from(somt);
        From::from(omt)
    }
}

impl<T: Digestible, D: Digest> From<SignedOwningMerkleTree<T, D>>
    for SignedMerkleTree<D>
{
    fn from(somt: SignedOwningMerkleTree<T, D>) -> Self {
        SignedMerkleTree {
            mt: somt.mt.into(),
            keypair: somt.keypair,
            sth: somt.sth,
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
    fn new(bytes: &[u8]) -> Self {
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
        KeyPair::new_from_bytes(cbytes).map_err(SerdeError::custom)
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
