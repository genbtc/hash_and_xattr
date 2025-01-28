use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::fs;
use std::io::{self, Read};
//use std::os::unix::fs::MetadataExt;
use libc;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

//default _was_ sha256 https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L71
const DEFAULT_HASH_ALGO: &'static str = "sha512";
//Derived from https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L77-L78
const MAX_DIGEST_SIZE: usize = 64; // Adjust based on the maximum hash size
const MAX_SIGNATURE_SIZE: usize = 512; // Adjust based on the maximum signature size
//Derived from enum evm_ima_xattr_type @  https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L92-L99
const IMA_XATTR_DIGEST: u8 = 0x01;
const EVM_IMA_XATTR_DIGSIG: u8 = 0x03;
const IMA_XATTR_DIGEST_NG: u8 = 0x04;
const DIGSIG_VERSION_2: u8 = 0x02;


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
        }
    }
}

fn main() {
    let targetfile = "README.md"; // Replace with the actual file path
    let hash_algo = "sha512"; // Replace with the desired hash algorithm (TODO: or default DEFAULT_HASH_ALGO)
    let key_path = "/home/genr8eofl/signing_key.priv"; // Replace with the actual key file path

    match sign_ima(targetfile, hash_algo, key_path) {
        Ok(_) => println!("Successfully signed IMA"),
        Err(e) => eprintln!("Error signing IMA: {:?}", e),
    }
}

fn sign_ima(file: &str, hash_algo: &str, key_path: &str) -> io::Result<()> {
    let hash_algo = HashAlgorithm::from_str(hash_algo)
        .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;
    let mut hash = vec![0u8; MAX_DIGEST_SIZE + 2]; // +2 byte xattr header (0406)

    if hash_algo.ima_xattr_type() > 1 {
        hash[0] = IMA_XATTR_DIGEST_NG;
        hash[1] = hash_algo.ima_xattr_type();
    } else {
        hash[0] = IMA_XATTR_DIGEST;
    }

    let offset = if hash_algo.ima_xattr_type() > 1 { 2 } else { 1 };
    
    //Calc hash
    let len = calc_hash(file, &hash_algo, &mut hash[offset..])?;
    let len = len + offset;
    if len > MAX_DIGEST_SIZE + 2 {
        println!("Error!: length {} is > MAX_DIGEST_SIZE {}", len, MAX_DIGEST_SIZE );
    }

    // Print hash
    println!("hash({:?}): {:?}", hash_algo, &hash[..len]);

    // Sign the hash
    let signature = sign_hash(&hash_algo, &hash[offset..len], key_path)?;

    // Prepare header of xattr
    let mut xattr_value = vec![EVM_IMA_XATTR_DIGSIG, DIGSIG_VERSION_2, hash[1] ];
    //TODO: INSERT REAL HEADER FORMAT HERE: like https://github.com/linux-integrity/ima-evm-utils/blob/next/src/libimaevm.c#L724
    //      03 + 0206 + keyID + ??
    // signature_v2_hdr @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L194
    //keyid ab6f2050 (from /etc/keys/signing_key.priv)
    xattr_value.extend_from_slice(&signature);

    // Print signature
    println!("sig({:?}): {:?}", hash_algo, &signature[..MAX_SIGNATURE_SIZE]);

    // Set extended attribute
    set_xattr(file, "user.imasign", &xattr_value)
}

fn calc_hash(file: &str, hash_algo: &HashAlgorithm, hash: &mut [u8]) -> io::Result<usize> {
    let mut file = fs::File::open(file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let md = MessageDigest::from_nid(hash_algo.nid())
        .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;

    let mut hasher = Hasher::new(md)?;
    hasher.update(&buffer)?;
    let hash_result = hasher.finish()?;
    let len = hash_result.len();
    hash[..len].copy_from_slice(&hash_result);

    Ok(len)
}

fn sign_hash(hash_algo: &HashAlgorithm, hash: &[u8], key_path: &str) -> io::Result<Vec<u8>> {
    let private_key = fs::read(key_path)?;
    let pkey = PKey::private_key_from_pem(&private_key)?;

    let md = MessageDigest::from_nid(hash_algo.nid())
        .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;

    let mut signer = Signer::new(md, &pkey)?;
    signer.update(hash)?;
    let signature = signer.sign_to_vec()?;
    
    Ok(signature)
}

fn set_xattr(file: &str, name: &str, value: &[u8]) -> io::Result<()> {
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
