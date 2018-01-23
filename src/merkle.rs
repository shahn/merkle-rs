use digest::AsHash;
use digest::Digest;
use digest::Digestible;
use digest::Hash;
use proof::*;
use proof::AsMerkleTree;
use std::collections::{hash_map, HashMap};
use std::iter;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TreeHead<D: Digest> {
    count: u64,
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    hash: Hash<D>,
}

impl<D: Digest> Clone for TreeHead<D> {
    fn clone(&self) -> Self {
        TreeHead {
            count: self.count,
            hash: self.hash.clone(),
        }
    }
}

impl<D: Digest> TreeHead<D> {
    pub fn size(&self) -> u64 {
        self.count
    }

    pub fn root_hash(&self) -> &Hash<D> {
        &self.hash
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct MerkleTree<D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    pub(crate) map: HashMap<Hash<D>, usize>,
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    pub(crate) tree: Vec<Hash<D>>,
}

impl<D: Digest> MerkleTree<D> {
    pub fn new() -> MerkleTree<D> {
        let empty = D::default().fixed_result();
        let mut m = MerkleTree::<D> {
            map: HashMap::new(),
            tree: Vec::new(),
        };
        m.tree.push(empty.clone());
        m.tree.push(empty);
        m
    }

    pub fn insert<H: AsHash<D>>(&mut self, hash: H) -> bool {
        let hash = hash.as_hash();

        let mut tlen = self.tree.len();
        let count = self.len();

        let leaf_hash = D::hash_leaf(&hash);

        match self.map.entry(hash) {
            hash_map::Entry::Occupied(_) => return false,
            e @ hash_map::Entry::Vacant(_) => e.or_insert(count),
        };

        if self.tree.len() / 2 <= count {
            self.inc_height();
            tlen = self.tree.len();
        }
        let mut pos = tlen / 2 + count;

        self.tree[pos] = leaf_hash;

        while pos > 1 {
            if pos % 2 == 0 {
                self.tree[pos / 2] = self.tree[pos].clone();
            } else {
                self.tree[pos / 2] =
                    D::hash_inner(&self.tree[pos - 1], &self.tree[pos]);
            }
            pos /= 2;
        }

        true
    }

    fn inc_height(&mut self) {
        let t = &mut self.tree;
        let old_len = t.len();
        let new_len = old_len * 2;
        t.reserve(new_len);
        let x = D::default().fixed_result();
        t.extend(iter::repeat(x).take(old_len));
        let mut rem_len = new_len;
        while rem_len > 2 {
            let a_len = rem_len / 2;
            let (a, b) = t.split_at_mut(a_len);
            b[..a_len / 2].clone_from_slice(&a[a_len / 2..]);
            rem_len = a_len;
        }
    }

    pub fn head(&self) -> TreeHead<D> {
        TreeHead {
            count: self.len() as u64,
            hash: self.tree[1].clone(),
        }
    }

    pub fn inclusion_proof<H: AsHash<D>>(
        &self,
        h: H,
    ) -> Option<InclusionProof<D>> {
        let h = h.as_hash();

        InclusionProofBase::new(h, self)
            .map(|x| InclusionProof::new(x, self.head()))
    }

    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Option<ConsistencyProof<D>> {
        ConsistencyProofBase::new(old_size, self)
            .map(|x| ConsistencyProof::new(x, self.head()))
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn get_offset(&self) -> u64 {
        self.len().next_power_of_two() as u64
    }

    pub(crate) fn hash_from_range(&self, left: u64, right: u64) -> Hash<D> {
        let diff = right + 1 - left;
        let next_pow_2 = diff.next_power_of_two();
        self.tree[((self.get_offset() + left) / next_pow_2) as usize].clone()
    }
}

impl<D: Digest> Default for MerkleTree<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest, H: AsHash<D>> iter::FromIterator<H> for MerkleTree<D> {
    fn from_iter<T: IntoIterator<Item = H>>(iter: T) -> Self {
        let mut mt = MerkleTree::new();
        mt.extend(iter);
        mt
    }
}

impl<D: Digest, H: AsHash<D>> iter::Extend<H> for MerkleTree<D> {
    fn extend<T: IntoIterator<Item = H>>(&mut self, iter: T) {
        for x in iter {
            self.insert(x);
        }
    }
}

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct OwningMerkleTree<T: Digestible, D: Digest> {
    #[cfg_attr(feature = "serde", serde(bound = ""))]
    mt: MerkleTree<D>,
    objs: Vec<T>,
}

impl<T: Digestible, D: Digest> OwningMerkleTree<T, D> {
    pub fn new() -> OwningMerkleTree<T, D> {
        OwningMerkleTree {
            mt: MerkleTree::new(),
            objs: Vec::new(),
        }
    }

    pub fn insert(&mut self, elem: T) -> bool {
        let hash = D::hash_elem(&elem);

        if self.mt.insert(hash) {
            self.objs.push(elem);
            true
        } else {
            false
        }
    }

    pub fn head(&self) -> TreeHead<D> {
        self.mt.head()
    }

    pub fn inclusion_proof<H: AsHash<D>>(
        &self,
        h: H,
    ) -> Option<InclusionProof<D>> {
        self.mt.inclusion_proof(h)
    }

    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Option<ConsistencyProof<D>> {
        self.mt.consistency_proof(old_size)
    }
}

impl<T: Digestible, D: Digest> Default for OwningMerkleTree<T, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Digestible, D: Digest> iter::FromIterator<T>
    for OwningMerkleTree<T, D> {
    fn from_iter<S: IntoIterator<Item = T>>(iter: S) -> Self {
        let mut mt = OwningMerkleTree::new();
        mt.extend(iter);
        mt
    }
}

impl<T: Digestible, D: Digest> iter::Extend<T> for OwningMerkleTree<T, D> {
    fn extend<S: IntoIterator<Item = T>>(&mut self, iter: S) {
        for x in iter {
            self.insert(x);
        }
    }
}

impl<T: Digestible, D: Digest> From<OwningMerkleTree<T, D>> for MerkleTree<D> {
    fn from(omt: OwningMerkleTree<T, D>) -> Self {
        omt.mt
    }
}

impl<D: Digest> AsMerkleTree<D> for MerkleTree<D> {
    fn as_merkle_tree(&self) -> &MerkleTree<D> {
        self
    }
}

impl<T: Digestible, D: Digest> AsMerkleTree<D> for OwningMerkleTree<T, D> {
    fn as_merkle_tree(&self) -> &MerkleTree<D> {
        &self.mt
    }
}
