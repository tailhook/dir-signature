use std::str::FromStr;
use {Error};

/// A type of hash supported by the library
#[derive(Copy, Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum HashType {
    /// A SHA512 checksum truncated to 256 bits
    Sha512_256,
    /// The 256bits (32 bytes) Blake2b checksum
    Blake2b_256,
}

impl HashType {
    /// Get the digest size in bytes
    pub fn output_bytes(self) -> usize {
        match self {
            HashType::Sha512_256 | HashType::Blake2b_256 => 32,
        }
    }
}

impl FromStr for HashType {
    type Err = Error;
    fn from_str(val: &str) -> Result<HashType, Self::Err> {
        match val {
            "sha512/256" => Ok(HashType::Sha512_256),
            "blake2b/256" => Ok(HashType::Blake2b_256),
            _ => Err(Error::UnsupportedHash),
        }
    }
}
