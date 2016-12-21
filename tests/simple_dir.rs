extern crate dir_signature;

use dir_signature::{ScannerConfig, v1};


#[test]
fn test_dir1() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir1", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_eq!(String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  hello.txt f 6 8dd499a36d950b8732f85a3bffbc8d8bee4a0af391e8ee2bb0aa0c4553b6c0fc
  test.txt f 0
/subdir
  .hidden f 7 24f72d3a930b5f7933ddd91a5c7cb7ba09a093f936a04bf6486c8b1763c59819
  file.txt f 10 9ce28248299290fe84340d7821adf01b3b6a579ef827e1e58bc3949de4b7e5d9
11928917e3e44838af46bad1c7a43a8c16eb26052997f70328d7b07ae4dd6eac
",
        "");
}

#[test]
fn test_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_eq!(String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  file2.txt f 18 c4cadd1e2e2aded1cdb2ba48fdfe8a831d9236042aec16472725d45b001c1ad5
/sub2
  hello.txt f 6 e0494295cc1dfdd443d09f81913881a112745174778cc0c224ccc7137024fe41
/subdir
  bigdata.bin f 81920 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 768007e06b0cd9e62d50f458b9435c6dda0a6d272f0b15550f97c478394b7433 6eb7f16cf7afcabe9bdea88bdab0469a7937eb715ada9dfd8f428d9d38d86133
  file3.txt f 12 b130fa20a2ba5a3d9976e6c15e8a59ad9e5cbbc52536a4458952872cda5c218d
c23f2579827456818fc855c458d1ad7339d144b57ee247a6628e4fc8e39958bb
",
        "");
}
