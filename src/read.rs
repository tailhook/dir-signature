use std::str::{from_utf8, FromStr};
use std::io::{self, Read, Seek, SeekFrom};

use {HashType};


fn hex_to_digit(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v & 0x0f),
        b'a'..=b'f' | b'A'..=b'F' => Some((v & 0x0f) + 9),
        _ => None
    }
}

/// Get a hash from an index file
///
/// That hash is a last line of the index file. It may serve either as a
/// checksum of the file or as identifier if this image/directory
pub fn get_hash<F: Read+Seek>(f: &mut F) -> Result<Vec<u8>, io::Error> {
    let einval = io::ErrorKind::InvalidData;
    let mut signature = [0u8; 32];
    f.read(&mut signature)?;
    if &signature[..16] != b"DIRSIGNATURE.v1 " {
        return Err(einval.into());
    }
    let hash = signature[16..].iter().position(|&x| x == b' ')
        .and_then(|e| from_utf8(&signature[16..16+e]).ok())
        .and_then(|s| HashType::from_str(s).ok())
        .ok_or(einval)?;

    let nbytes = hash.output_bytes()*2+2;
    f.seek(SeekFrom::End(- (nbytes as i64)))?;
    let mut buf = [0u8; 100];
    assert!(buf.len() >= nbytes);
    if f.read(&mut buf)? != nbytes {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if buf[0] != b'\n' || buf[nbytes-1] != b'\n' {
        return Err(einval.into());
    }
    let mut hash = Vec::with_capacity(hash.output_bytes());
    for d in buf[1..nbytes-1].chunks(2) {
        hash.push(
            (hex_to_digit(d[0]).ok_or(einval)? << 4)
            | hex_to_digit(d[1]).ok_or(einval)?);
    }

    return Ok(hash);
}

#[cfg(test)]
mod test {
    use super::get_hash;
    use std::io::Cursor;

    const DATA: &'static [u8] = b"\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
  test.txt f 0
/subdir
  .hidden f 7 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  file.txt f 10 9ce28248299290fe84340d7821adf01b3b6a579ef827e1e58bc3949de4b7e5d9
11928917e3e44838af46bad1c7a43a8c16eb26052997f70328d7b07ae4dd6eac
";

    #[test]
    fn read() {
        let hash = get_hash(&mut Cursor::new(DATA)).unwrap();
        assert_eq!(hash,
            vec![0x11, 0x92, 0x89, 0x17, 0xe3, 0xe4, 0x48, 0x38, 0xaf,
                 0x46, 0xba, 0xd1, 0xc7, 0xa4, 0x3a, 0x8c, 0x16, 0xeb,
                 0x26, 0x05, 0x29, 0x97, 0xf7, 0x03, 0x28, 0xd7, 0xb0,
                 0x7a, 0xe4, 0xdd, 0x6e, 0xac]);
    }
}
