extern crate dir_signature;
extern crate difference;

use dir_signature::{HashType, ScannerConfig, v1};
use difference::assert_diff;


#[test]
fn test_dir1() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir1", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
  test.txt f 0
/subdir
  .hidden f 7 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  file.txt f 10 9ce28248299290fe84340d7821adf01b3b6a579ef827e1e58bc3949de4b7e5d9
11928917e3e44838af46bad1c7a43a8c16eb26052997f70328d7b07ae4dd6eac
", "\n", 0);

}

#[test]
fn test_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  file2.txt f 18 c4cadd1e2e2aded1cdb2ba48fdfe8a831d9236042aec16472725d45b001c1ad5
/sub2
  hello.txt f 6 e0494295cc1dfdd443d09f81913881a112745174778cc0c224ccc7137024fe41
/subdir
  bigdata.bin f 81920 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 6eb7f16cf7afcabe9bdea88bdab0469a7937eb715ada9dfd8f428d9d38d86133
  file3.txt f 12 b130fa20a2ba5a3d9976e6c15e8a59ad9e5cbbc52536a4458952872cda5c218d
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
", "\n", 0);
}

#[test]
fn test_dir1_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir1", "/");
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  file2.txt f 18 c4cadd1e2e2aded1cdb2ba48fdfe8a831d9236042aec16472725d45b001c1ad5
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
  test.txt f 0
/sub2
  hello.txt f 6 e0494295cc1dfdd443d09f81913881a112745174778cc0c224ccc7137024fe41
/subdir
  .hidden f 7 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  bigdata.bin f 81920 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 6eb7f16cf7afcabe9bdea88bdab0469a7937eb715ada9dfd8f428d9d38d86133
  file.txt f 10 9ce28248299290fe84340d7821adf01b3b6a579ef827e1e58bc3949de4b7e5d9
  file3.txt f 12 b130fa20a2ba5a3d9976e6c15e8a59ad9e5cbbc52536a4458952872cda5c218d
0a8f363c76c92aa58c67cae711b83b3f44d47c370cce42fae114c8d8541237cb
", "\n", 0);
}

#[test]
fn test_blake2b_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.hash(HashType::Blake2b_256);
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff(&String::from_utf8_lossy(&buf), "\
        DIRSIGNATURE.v1 blake2b/256 block_size=32768
/
  file2.txt f 18 3ae02016c534f640b87b21d5bb94bf39a29c4cfa8e1bcdfcdea28993301255f9
/sub2
  hello.txt f 6 1bb580f57655aff3424d7832686c80195b61b5f228702e426c5332941211aff8
/subdir
  bigdata.bin f 81920 e9334020344bcb418f16c532a4fad5465ef530cff3eaaee6411bddf59e210e50 e9334020344bcb418f16c532a4fad5465ef530cff3eaaee6411bddf59e210e50 087e8b8bdc8b93f4f83212c1d6c01af4c55d3c1d3412da45112e903df797c1cd
  file3.txt f 12 47fc3debf75989703259c26b1c7f7dec735fd7f80b5d02f5c7f07e7794433e18
2a74fd7919473f3dde830ee4a8e3e108a6954731a319e9198ef483f9c9e82992
", "\n", 0);
}
