extern crate dir_signature;
#[macro_use] extern crate difference;

use dir_signature::{ScannerConfig, v1};


#[test]
fn test_dir1() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir1", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff!(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  hello.txt f 6 a79eef66019bfb9a41f798f2cff2d2d36ed294cc3f96bf53bbfc5192ebe60192
  test.txt f 0
/subdir
  .hidden f 7 6d7f5f9804ee4dbc1ff7e12c7665387e0119e8ea629996c52d38b75c12ad0acf
  file.txt f 10 0119865c765e02554f6fc5a06fa76aa92c590c09225775c092144079f9964899
552ca5730ee95727e890a2155c88609d244624034ff70de264cf88220d11d6df
", "\n", 0);
}

#[test]
fn test_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff!(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  file2.txt f 18 961cd6357f94b5bfe98fa4fde8aa25c4501e12923fd484a63bf4979d26d23ce1
/sub2
  hello.txt f 6 243189de0f3e8517e144fe9f58e1bdc9102d5ac21e7fba1ca4c4e60cf7988d9b
/subdir
  bigdata.bin f 81920 620797b6a249553166433873ead3ab6aadd24e1750b3e71edd642a91c006d1d0 620797b6a249553166433873ead3ab6aadd24e1750b3e71edd642a91c006d1d0 f978c70629cb4bdfad23126759e243e476404000b71e1a20558ed6e05035dd72
  file3.txt f 12 14c96f4f7646417092d1cf2460c1823dfcb40fdd94a27aaeb18907040487c7bb
bc18ac1d4df874f0ddff29f3b989bb219bd6814feaea8d0c440dab9ba64393b8
", "\n", 0);
}

#[test]
fn test_dir1_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.add_dir("tests/dir1", "/");
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff!(&String::from_utf8_lossy(&buf), "\
DIRSIGNATURE.v1 sha512/256 block_size=32768
/
  file2.txt f 18 961cd6357f94b5bfe98fa4fde8aa25c4501e12923fd484a63bf4979d26d23ce1
  hello.txt f 6 a79eef66019bfb9a41f798f2cff2d2d36ed294cc3f96bf53bbfc5192ebe60192
  test.txt f 0
/sub2
  hello.txt f 6 243189de0f3e8517e144fe9f58e1bdc9102d5ac21e7fba1ca4c4e60cf7988d9b
/subdir
  .hidden f 7 6d7f5f9804ee4dbc1ff7e12c7665387e0119e8ea629996c52d38b75c12ad0acf
  bigdata.bin f 81920 620797b6a249553166433873ead3ab6aadd24e1750b3e71edd642a91c006d1d0 620797b6a249553166433873ead3ab6aadd24e1750b3e71edd642a91c006d1d0 f978c70629cb4bdfad23126759e243e476404000b71e1a20558ed6e05035dd72
  file.txt f 10 0119865c765e02554f6fc5a06fa76aa92c590c09225775c092144079f9964899
  file3.txt f 12 14c96f4f7646417092d1cf2460c1823dfcb40fdd94a27aaeb18907040487c7bb
141a80ae97aa3ed18cc84004b0cabb37b75619bb2c9cba753d9a710270f85e70
", "\n", 0);
}
