use extern_digest;
use extern_digest::generic_array;
use std::hash;
use typenum::Unsigned;

pub type Hash<D> =
    generic_array::GenericArray<
        u8,
        <D as extern_digest::FixedOutput>::OutputSize,
    >;

pub use extern_digest::Input;

/// Digestible
pub trait Digestible: Eq + hash::Hash {
    fn hash_bytes(&self, digest: &mut extern_digest::Input);
}

pub trait Digest: extern_digest::Digest + Clone {
    type Hash;

    fn hash_elem<T: Digestible>(elem: &T) -> Hash<Self>;
    fn hash_leaf(elem: &Hash<Self>) -> Hash<Self>;
    fn hash_inner(l: &Hash<Self>, r: &Hash<Self>) -> Hash<Self>;
    fn from_slice(&[u8]) -> Result<Hash<Self>, ()>;
}

impl<T> Digest for T
where
    T: extern_digest::Digest + Clone,
{
    type Hash = extern_digest::generic_array::GenericArray<u8, <Self as
    extern_digest::FixedOutput>::OutputSize>;

    fn hash_elem<R: Digestible>(elem: &R) -> Self::Hash {
        let mut hasher = Self::default();
        elem.hash_bytes(&mut hasher);
        hasher.fixed_result()
    }

    fn hash_leaf(elem: &Hash<Self>) -> Self::Hash {
        let mut hasher = Self::default();
        hasher.process(&[0x00]);
        hasher.process(elem);
        hasher.fixed_result()
    }

    fn hash_inner(l: &Hash<Self>, r: &Hash<Self>) -> Self::Hash {
        let mut hasher = Self::default();
        hasher.process(&[0x01]);
        hasher.process(l);
        hasher.process(r);
        hasher.fixed_result()
    }

    fn from_slice(sl: &[u8]) -> Result<Hash<Self>, ()> {
        if sl.len() != <Self as extern_digest::FixedOutput>::OutputSize::to_usize() {
            return Err(())
        }
        Ok(generic_array::GenericArray::clone_from_slice(sl))
    }
}

impl<T: AsRef<[u8]> + Eq + hash::Hash> Digestible for T {
    fn hash_bytes(&self, digest: &mut extern_digest::Input) {
        digest.process(self.as_ref());
    }
}
