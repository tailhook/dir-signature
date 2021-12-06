use std::fmt;
use std::str::FromStr;

use crate::{Error, HashType, HashTypeEnum};


impl HashType {

    /// Constructs SHA512/256 checksum truncated to 256 bits
    pub fn sha512_256() -> HashType {
        HashType(HashTypeEnum::Sha512_256)
    }

    /// Constructs 256bits (32 bytes) Blake2b checksum
    pub fn blake2b_256() -> HashType {
        HashType(HashTypeEnum::Blake2b_256)
    }

    /// Get the digest size in bytes
    pub fn output_bytes(self) -> usize {
        match self.0 {
            HashTypeEnum::Sha512_256 | HashTypeEnum::Blake2b_256 => 32,
        }
    }
}

impl FromStr for HashType {
    type Err = Error;
    fn from_str(val: &str) -> Result<HashType, Self::Err> {
        match val {
            "sha512/256" => Ok(HashType(HashTypeEnum::Sha512_256)),
            "blake2b/256" => Ok(HashType(HashTypeEnum::Blake2b_256)),
            _ => Err(Error::UnsupportedHash),
        }
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            HashTypeEnum::Sha512_256 => "sha512/256",
            HashTypeEnum::Blake2b_256 => "blake2b/256",
        }.fmt(f)
    }
}
