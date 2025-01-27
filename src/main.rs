use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::x509::X509;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_DIGEST_SIZE: usize = 64;
const IMA_XATTR_DIGEST_NG: u8 = 0x04;

#[derive(Debug)]
enum HashAlgorithm {
    Sha1,
    Md4,
    Md5,
    Ripemd160,
    Sha256,
    Sha384,
    Sha512,
    Sha224,
    Sm3_256,
}

impl HashAlgorithm {
    fn from_str(algo: &str) -> Option<Self> {
        match algo.to_lowercase().as_str() {
            "sha1" => Some(HashAlgorithm::Sha1),
            "md4" => Some(HashAlgorithm::Md4),
            "md5" => Some(HashAlgorithm::Md5),
            "ripemd160" => Some(HashAlgorithm::Ripemd160),
            "sha256" => Some(HashAlgorithm::Sha256),
            "sha384" => Some(HashAlgorithm::Sha384),
            "sha512" => Some(HashAlgorithm::Sha512),
            "sha224" => Some(HashAlgorithm::Sha224),
            "sm3_256" => Some(HashAlgorithm::Sm3_256),
            _ => None,
        }
    }

    fn nid(&self) -> Nid {
        match self {
            HashAlgorithm::Sha1 => Nid::SHA1,
            HashAlgorithm::Md4 => Nid::MD4,
            HashAlgorithm::Md5 => Nid::MD5,
            HashAlgorithm::Ripemd160 => Nid::RIPEMD160,
            HashAlgorithm::Sha224 => Nid::SHA224,
            HashAlgorithm::Sha256 => Nid::SHA256,
            HashAlgorithm::Sha384 => Nid::SHA384,
            HashAlgorithm::Sha512 => Nid::SHA512,
            HashAlgorithm::Sm3_256 => Nid::SM3,
        }
    }

    fn ima_xattr_type(&self) -> u8 {
        match self {
            HashAlgorithm::Sha1 => 0,
            HashAlgorithm::Md4 => 1,
            HashAlgorithm::Md5 => 2,
            HashAlgorithm::Ripemd160 => 3,
            HashAlgorithm::Sha256 => 4,
            HashAlgorithm::Sha384 => 5,
            HashAlgorithm::Sha512 => 6,
            HashAlgorithm::Sha224 => 7,
            HashAlgorithm::Sm3_256 => 8,
        }
    }
}

fn main() {
    let file = "README.md";
    let hash_algo = "sha512";

    match hash_ima(file, hash_algo) {
        Ok(_) => println!("Successfully hashed IMA"),
        Err(e) => eprintln!("Error hashing IMA: {:?}", e),
    }
}

fn hash_ima(file: &str, hash_algo: &str) -> io::Result<()> {
    let mut hash = vec![0u8; MAX_DIGEST_SIZE + 2]; //64 +2 byte xattr header
    let hash_md = HashAlgorithm::from_str(hash_algo)
        .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;
    hash[0] = IMA_XATTR_DIGEST_NG;  // 0x04
    hash[1] = hash_md.ima_xattr_type(); // 0x06
    let offset = 2;

    // Calc Hash
    let len = calc_hash(file, &hash_md, &mut hash[offset..])?;
    let len = len + offset;

    // Print hash
    println!("hash({}={}): {:?}", hash_algo, hash_md.ima_xattr_type(), &hash[..len]);

    // Set extended attribute
    set_xattr(file, "user.imafake", &hash[..len])
}

fn calc_hash(file: &str, hash_algo: &HashAlgorithm, hash: &mut [u8]) -> io::Result<usize> {
    let mut file = fs::File::open(file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let md = match MessageDigest::from_nid(hash_algo.nid()) {
        Some(md) => md,
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm")),
    };

    let mut hasher = Hasher::new(md)?;
    hasher.update(&buffer)?;
    let hash_result = hasher.finish()?;
    let len = hash_result.len();
    hash[..len].copy_from_slice(&hash_result);

    Ok(len)
}

fn set_xattr(file: &str, name: &str, value: &[u8]) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    let file_cstr = CString::new(Path::new(file).as_os_str().as_bytes())?;
    let name_cstr = CString::new(name)?;

    unsafe {
        let ret = libc::setxattr(
            file_cstr.as_ptr(),
            name_cstr.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
