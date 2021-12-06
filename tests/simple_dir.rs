
#[macro_use] extern crate difference;

use dir_signature::{HashType, ScannerConfig, v1};


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

#[cfg(feature="threads")]
mod threads {

    use dir_signature::{ScannerConfig, v1};

    #[test]
    fn test_dir1() {
        let mut cfg = ScannerConfig::new();
        cfg.add_dir("tests/dir1", "/");
        cfg.threads(4);
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
        cfg.threads(4);
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
        cfg.threads(4);
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
}

#[test]
fn test_blake2b_dir2() {
    let mut cfg = ScannerConfig::new();
    cfg.hash(HashType::blake2b_256());
    cfg.add_dir("tests/dir2", "/");
    let mut buf = Vec::new();
    v1::scan(&cfg, &mut buf).unwrap();
    assert_diff!(&String::from_utf8_lossy(&buf), "\
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
