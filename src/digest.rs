use extern_digest;
use extern_digest::generic_array;
use std::hash;

pub type Hash<D> = generic_array::GenericArray<
    u8,
    <D as extern_digest::FixedOutput>::OutputSize,
>;

pub use extern_digest::Input;

/// Digestible
pub trait Digestible: Eq + hash::Hash {
    fn hash_bytes(&self, digest: &mut extern_digest::Input);
}

pub trait Digest: extern_digest::Digest + Clone {
    fn hash_elem<T: Digestible>(elem: &T) -> Hash<Self>;
    fn hash_leaf(elem: &Hash<Self>) -> Hash<Self>;
    fn hash_inner(l: &Hash<Self>, r: &Hash<Self>) -> Hash<Self>;
}

impl<T> Digest for T
where
    T: extern_digest::Digest + Clone,
{
    fn hash_elem<R: Digestible>(elem: &R) -> Hash<Self> {
        let mut hasher = Self::default();
        elem.hash_bytes(&mut hasher);
        hasher.fixed_result()
    }

    fn hash_leaf(elem: &Hash<Self>) -> Hash<Self> {
        let mut hasher = Self::default();
        hasher.process(&[0x00]);
        hasher.process(elem);
        hasher.fixed_result()
    }

    fn hash_inner(l: &Hash<Self>, r: &Hash<Self>) -> Hash<Self> {
        let mut hasher = Self::default();
        hasher.process(&[0x01]);
        hasher.process(l);
        hasher.process(r);
        hasher.fixed_result()
    }
}

impl<T: AsRef<[u8]> + Eq + hash::Hash> Digestible for T {
    fn hash_bytes(&self, digest: &mut extern_digest::Input) {
        digest.process(self.as_ref());
    }
}

pub trait AsHash<D: Digest> {
    fn as_hash(self) -> Hash<D>;
}

impl<D: Digest> AsHash<D> for Hash<D> {
    fn as_hash(self) -> Hash<D> {
        self
    }
}

impl<'a, T: Digestible, D: Digest> AsHash<D> for &'a T {
    fn as_hash(self) -> Hash<D> {
        D::hash_elem(self)
    }
}
