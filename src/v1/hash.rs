use std::io;
use std::fmt;
use std::str;

use digest::{FixedOutputDirty, Reset, Update, VariableOutput};
use sha2::Sha512Trunc256;
use blake2::VarBlake2b;
use generic_array::GenericArray;

pub(crate) static LOWER_CHARS: &'static[u8] = b"0123456789abcdef";

pub trait Hash: Clone + Send + Sync + io::Write + 'static {
    type Output: HashOutput + fmt::LowerHex;

    fn name(&self) -> &str;

    fn update(&mut self, data: &[u8]);

    fn total_hash(&mut self) -> Self::Output;

    fn hash_file<F: io::Read>(&mut self, f: F, block_size: u64)
        -> io::Result<Self::Output>
    {
        io::copy(&mut f.take(block_size), self)?;
        Ok(self.total_hash())
    }

    fn hash_and_size<F: io::Read>(&mut self, f: F, block_size: u64)
        -> io::Result<(u64, Self::Output)>
    {
        let bytes = io::copy(&mut f.take(block_size), self)?;
        Ok((bytes, self.total_hash()))
    }
}

pub trait HashOutput {
    fn result(&self) -> &[u8];
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub struct Sha512_256(Sha512Trunc256);

impl Sha512_256 {
    pub fn new() -> Self {
        Self(Sha512Trunc256::default())
    }
}

impl io::Write for Sha512_256 {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.0.flush()
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug)]
pub struct Blake2b_256(VarBlake2b);

impl Blake2b_256 {
    pub fn new() -> Self {
        Self(VarBlake2b::new(32).expect("Valid length"))
    }
}

impl io::Write for Blake2b_256 {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.0.flush()
    }
}

#[allow(non_camel_case_types)]
pub struct Sha512_256_Res(GenericArray<u8, <Sha512Trunc256 as FixedOutputDirty>::OutputSize>);

#[allow(non_camel_case_types)]
pub struct Blake2b_256_Res([u8; 32]);

impl Hash for Sha512_256 {
    type Output = Sha512_256_Res;

    fn name(&self) -> &str {
        "sha512/256"
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn total_hash(&mut self) -> Self::Output {
        let mut digest = GenericArray::<u8, <Sha512Trunc256 as FixedOutputDirty>::OutputSize>::default();
        self.0.finalize_into_dirty(&mut digest);
        self.0.reset();
        Sha512_256_Res(digest)
    }
}

impl Hash for Blake2b_256 {
    type Output = Blake2b_256_Res;

    fn name(&self) -> &str {
        "blake2b/256"
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn total_hash(&mut self) -> Self::Output {
        let mut h: [u8; 32] = Default::default();
        self.0.finalize_variable_reset(|d| h.copy_from_slice(d));
        Blake2b_256_Res(h)
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
