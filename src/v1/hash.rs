use std::io;
use std::fmt;
use std::str;

use sha2::{self, Digest, Sha512Trunc256};
use blake2::Blake2b;
use blake2::digest::{VariableOutput, FixedOutput};
use generic_array::GenericArray;
use digest_writer::Writer as DWriter;


static LOWER_CHARS: &'static[u8] = b"0123456789abcdef";


pub trait Hash: Copy + Send + Sync + 'static {
    type Output: HashOutput + fmt::LowerHex;
    type Digest: Digest;
    fn name(&self) -> &str;
    fn total_hasher(&self) -> Self::Digest;
    fn total_hash(&self, d: Self::Digest) -> Self::Output;

    fn hash_file<F: io::Read>(&self, f: F, block_size: u64)
        -> io::Result<Self::Output>
    {
        let mut digest = DWriter::new(self.total_hasher());
        io::copy(&mut f.take(block_size), &mut digest)?;
        let d = digest.into_inner();
        Ok(self.total_hash(d))
    }
}

pub trait HashOutput {
    fn result(&self) -> &[u8];
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub struct Sha512_256;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub struct Blake2b_256;

#[allow(non_camel_case_types)]
pub struct Sha512_256_Res(GenericArray<u8, <Sha512Trunc256 as FixedOutput>::OutputSize>);

#[allow(non_camel_case_types)]
pub struct Blake2b_256_Res([u8; 32]);

impl Hash for Sha512_256 {
    type Output = Sha512_256_Res;
    type Digest = sha2::Sha512Trunc256;
    fn name(&self) -> &str {
        "sha512/256"
    }
    fn total_hasher(&self) -> Self::Digest {
        sha2::Sha512Trunc256::new()
    }
    fn total_hash(&self, d: Self::Digest) -> Self::Output {
        Sha512_256_Res(d.fixed_result())
    }
}

impl Hash for Blake2b_256 {
    type Output = Blake2b_256_Res;
    type Digest = Blake2b;
    fn name(&self) -> &str {
        "blake2b/256"
    }
    fn total_hasher(&self) -> Self::Digest {
        VariableOutput::new(32).expect("Valid length")
    }
    fn total_hash(&self, d: Self::Digest) -> Self::Output {
        let mut val = [0u8; 32];
        d.variable_result(&mut val).expect("valid length");
        Blake2b_256_Res(val)
    }
}

impl HashOutput for Sha512_256_Res {
    fn result(&self) -> &[u8] {
        &self.0[..]
    }
}

impl HashOutput for Blake2b_256_Res {
    fn result(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::LowerHex for Sha512_256_Res {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let data = &self.0[..32];  // Truncated hash!
        assert!(data.len() == 32);
        let max_digits = f.precision().unwrap_or(data.len()*2);
        let mut res = [0u8; 64];
        for (i, c) in data.iter().take(max_digits/2+1).enumerate() {
            res[i*2] = LOWER_CHARS[(c >> 4) as usize];
            res[i*2+1] = LOWER_CHARS[(c & 0xF) as usize];
        }
        f.write_str(unsafe {
            str::from_utf8_unchecked(&res[..max_digits])
        })?;
        Ok(())
    }
}

impl fmt::LowerHex for Blake2b_256_Res {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let data = &self.0[..32];
        assert!(data.len() == 32);
        let max_digits = f.precision().unwrap_or(data.len()*2);
        let mut res = [0u8; 64];
        for (i, c) in data.iter().take(max_digits/2+1).enumerate() {
            res[i*2] = LOWER_CHARS[(c >> 4) as usize];
            res[i*2+1] = LOWER_CHARS[(c & 0xF) as usize];
        }
        f.write_str(unsafe {
            str::from_utf8_unchecked(&res[..max_digits])
        })?;
        Ok(())
    }
}
