use digest::{Digest, Hash};
use merkle::{MerkleTree, TreeHead};

#[cfg(feature = "ring")]
use signed_merkle::{PubKey, SignedTreeHead};

pub(crate) struct InclusionProofBase<D: Digest> {
    obj: Hash<D>,
    pos: u64,
    hashes: Vec<Hash<D>>,
}

impl<D: Digest> InclusionProofBase<D> {
    pub(crate) fn new(h: Hash<D>, mt: &MerkleTree<D>) -> Option<Self> {
        if let Some(&i) = mt.map.get(&h) {
            let mut hashes = Vec::new();
            let offset = mt.get_offset();
            let mut pos = offset as usize + i;
            while pos > 1 {
                let parent = pos / 2;
                // Check parent for equality (unbalanced (sub)tree)
                if mt.tree[pos] != mt.tree[parent] {
                    if pos % 2 == 0 {
                        hashes.push(mt.tree[pos + 1].clone());
                    } else {
                        hashes.push(mt.tree[pos - 1].clone());
                    }
                }
                pos = parent;
            }
            Some(Self {
                obj: h,
                pos: i as u64,
                hashes,
            })
        } else {
            None
        }
    }


    fn calc(&self, mut n: u64) -> Hash<D> {
        let mut hash = D::hash_leaf(&self.obj);

        let mut order = Vec::new();

        let mut m = self.pos;
        for _ in 0..self.hashes.len() {
            let k = n.next_power_of_two() / 2;
            if m < k {
                n = k;
                order.push(Order::Left);
            } else {
                n -= k;
                m -= k;
                order.push(Order::Right);
            }
        }

        for (h, o) in self.hashes.iter().zip(order.iter().rev()) {
            hash = match *o {
                Order::Left => D::hash_inner(&hash, h),
                Order::Right => D::hash_inner(h, &hash),
            };
        }
        hash
    }
}

pub(crate) struct ConsistencyProofBase<D: Digest> {
    old_size: u64,
    hashes: Vec<Hash<D>>,
}

impl<D: Digest> ConsistencyProofBase<D> {
    pub(crate) fn new(old_size: u64, mt: &MerkleTree<D>) -> Option<Self> {

        let mut n = mt.len() as u64;
        let mut m = old_size;
        let mut hashes = Vec::new();
        if m > n {
            return None;
        } else if m == n {
            return Some(ConsistencyProofBase { old_size, hashes });
        }
        let mut b = true;
        let mut offset = 0;
        while m < n {
            let k = n.next_power_of_two() / 2;
            if m <= k {
                hashes.push(mt.hash_from_range(offset + k, offset + n - 1));
                n = k;
            } else {
                hashes.push(mt.hash_from_range(offset, offset + k - 1));
                b = false;
                m -= k;
                offset += k;
                n -= k;
            }
        }
        if !b {
            hashes.push(mt.hash_from_range(offset, offset + m - 1))
        }

        if old_size.is_power_of_two() {
            hashes.push(mt.hash_from_range(0, m - 1));
        }

        Some(ConsistencyProofBase {
            old_size: old_size,
            hashes,
        })
    }

    fn calc_old(&self, mut n1: u64, old_treehead: &Hash<D>) -> Hash<D> {

        if self.hashes.is_empty() {
            return old_treehead.clone();
        }

        let mut n0 = self.old_size;
        let mut hashes: Vec<&Hash<D>> = Vec::new();
        let mut flag = false;
        for h in &self.hashes {
            if flag {
                hashes.push(h);
                break;
            }
            let k = n1.next_power_of_two() / 2;
            if n0 < k {
                n1 = k;
            } else if n0 == k {
                flag = true;
            } else {
                hashes.push(h);
                n0 -= k;
                n1 -= k;
            }

        }
        /* XXXif !flag {
            return false;
        }*/

        let mut hashcalc = hashes[hashes.len() - 1].clone();
        for h in hashes.iter().rev().skip(1) {
            hashcalc = D::hash_inner(h, &hashcalc);
        }
        hashcalc
    }

    fn calc_new(&self, mut n1: u64, old_treehead: &Hash<D>) -> Hash<D> {

        if self.hashes.is_empty() {
            return old_treehead.clone();
        }

        let mut order = Vec::new();
        let mut n0 = self.old_size;
        for _ in 0..self.hashes.len() - 2 {
            let k = n1.next_power_of_two() / 2;
            if n0 < k {
                order.push(Order::Right);
                n1 = k;
            } else {
                order.push(Order::Left);
                n0 -= k;
                n1 -= k;
            }
        }
        order.push(Order::Right);


        let mut hashcalc = self.hashes[self.hashes.len() - 1].clone();

        assert!(self.hashes.len() == order.len() + 1);

        for (h, o) in self.hashes.iter().rev().skip(1).zip(order.iter().rev()) {
            hashcalc = match *o {
                Order::Left => D::hash_inner(h, &hashcalc),
                Order::Right => D::hash_inner(&hashcalc, h),
            };
        }

        hashcalc
    }
}


pub struct InclusionProof<D: Digest> {
    base: InclusionProofBase<D>,
    th: TreeHead<D>,
}

impl<D: Digest> InclusionProof<D> {
    pub(crate) fn new(base: InclusionProofBase<D>, th: TreeHead<D>) -> Self {
        Self { base, th }
    }

    pub fn verify(&self) -> bool {
        self.base.calc(self.th.size()) == *self.th.root_hash()
    }
}

pub struct ConsistencyProof<D: Digest> {
    base: ConsistencyProofBase<D>,
    th: TreeHead<D>,
}

impl<D: Digest> ConsistencyProof<D> {
    pub(crate) fn new(
        base: ConsistencyProofBase<D>,
        th: TreeHead<D>,
    ) -> ConsistencyProof<D> {
        ConsistencyProof { base, th }
    }

    pub fn verify(&self, old_treehead: &Hash<D>) -> bool {
        if self.base.calc_old(self.th.size(), old_treehead) != *old_treehead {
            return false;
        }

        self.base.calc_new(self.th.size(), old_treehead) == *self.th.root_hash()
    }
}

#[cfg(feature = "ring")]
pub struct SignedInclusionProof<D: Digest> {
    base: InclusionProofBase<D>,
    sth: SignedTreeHead<D>,
}

#[cfg(feature = "ring")]
impl<D: Digest> SignedInclusionProof<D> {
    pub(crate) fn new(
        base: InclusionProofBase<D>,
        sth: SignedTreeHead<D>,
    ) -> Self {
        Self { base, sth }
    }

    pub fn verify(&self, pk: &PubKey) -> bool {
        if self.sth.verify(pk) {
            self.base.calc(self.sth.size()) == *self.sth.root_hash()
        } else {
            false
        }
    }
}

#[cfg(feature = "ring")]
pub struct SignedConsistencyProof<D: Digest> {
    base: ConsistencyProofBase<D>,
    sth: SignedTreeHead<D>,
}

#[cfg(feature = "ring")]
impl<D: Digest> SignedConsistencyProof<D> {
    pub(crate) fn new(
        base: ConsistencyProofBase<D>,
        sth: SignedTreeHead<D>,
    ) -> Self {
        Self { base, sth }

    }

    pub fn verify(&self, old_treehead: &Hash<D>, pk: &PubKey) -> bool {
        if self.sth.verify(pk) {
            if self.base.calc_old(self.sth.size(), old_treehead) !=
                *old_treehead
            {
                return false;
            }
            self.base.calc_new(self.sth.size(), old_treehead) ==
                *self.sth.root_hash()
        } else {
            false
        }
    }
}

#[derive(PartialEq, Eq)]
enum Order {
    Left,
    Right,
}
