use std::io;
use std::str;
use std::ops::Add;

use sha2::{self, Digest};
use blake2::Blake2b;
use typenum::U32;
use generic_array::{ArrayLength, GenericArray};
use digest_writer::{Writer as DWriter, FixedOutput};


pub trait Hash {
    type OutputSize: ArrayLength<u8> + Add;
    type Digest: Digest;
    fn name(&self) -> &str;
    fn total_hasher(&self) -> Self::Digest;
    fn total_hash(&self, d: &Self::Digest) -> GenericArray<u8, Self::OutputSize>;

    fn hash_file<F: io::Read>(&self, f: F, block_size: u64)
        -> io::Result<GenericArray<u8, Self::OutputSize>>
    {
        let mut digest = DWriter::new(self.total_hasher());
        io::copy(&mut f.take(block_size), &mut digest)?;
        let d = digest.into_inner();
        Ok(self.total_hash(&d))
    }
}

#[allow(non_camel_case_types)]
pub struct Sha512_256;

#[allow(non_camel_case_types)]
pub struct Blake2b_256;

impl Hash for Sha512_256 {
    type OutputSize = U32;
    type Digest = sha2::Sha512;
    fn name(&self) -> &str {
        "sha512/256"
    }
    fn total_hasher(&self) -> Self::Digest {
        sha2::Sha512::new()
    }
    fn total_hash(&self, d: &Self::Digest)
        -> GenericArray<u8, Self::OutputSize>
    {
        *GenericArray::from_slice(&d.fixed_result()[..32])
    }
}

impl Hash for Blake2b_256 {
    type OutputSize = U32;
    type Digest = Blake2b;
    fn name(&self) -> &str {
        "blake2b/256"
    }
    fn total_hasher(&self) -> Self::Digest {
        Blake2b::new()
    }
    fn total_hash(&self, d: &Self::Digest)
        -> GenericArray<u8, Self::OutputSize>
    {
        *GenericArray::from_slice(&d.fixed_result()[..32])
    }
}
