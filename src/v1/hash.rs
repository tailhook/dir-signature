use std::io;
use std::fmt;
use std::str;

use sha2::{self, Digest};
use typenum::U64;
use generic_array::GenericArray;
use digest_writer::Writer as DWriter;


static LOWER_CHARS: &'static[u8] = b"0123456789abcdef";


pub trait Hash {
    type HexOutput: fmt::LowerHex;
    fn name(&self) -> &str;
    fn hash<F: io::Read>(&self, f: F, block_size: u64)
        -> io::Result<Self::HexOutput>;
}

#[allow(non_camel_case_types)]
pub struct Sha512_256;

#[allow(non_camel_case_types)]
pub struct Sha512_256_Hex(GenericArray<u8, U64>);

impl Hash for Sha512_256 {
    type HexOutput = Sha512_256_Hex;
    fn name(&self) -> &str {
        "sha512/256"
    }
    fn hash<F: io::Read>(&self, f: F, block_size: u64)
        -> io::Result<Sha512_256_Hex>
    {
        let mut digest = DWriter::new(sha2::Sha512::new());
        io::copy(&mut f.take(block_size), &mut digest)?;
        let d = digest.into_inner();
        Ok(Sha512_256_Hex(d.result()))
    }
}

impl fmt::LowerHex for Sha512_256_Hex {
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
