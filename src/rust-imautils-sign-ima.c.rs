use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_DIGEST_SIZE: usize = 64; // Adjust based on the maximum hash size
const MAX_SIGNATURE_SIZE: usize = 256; // Adjust based on the maximum signature size
const IMA_XATTR_DIGEST: u8 = 0x01;
const IMA_XATTR_DIGEST_NG: u8 = 0x04;
const EVM_IMA_XATTR_DIGSIG: u8 = 0x03;

fn main() {
    let file = "/root/tpm2.dat"; // Replace with the actual file path
    let hash_algo = "sha512"; // Replace with the desired hash algorithm
    let key_path = "/etc/keys/signing_key.priv"; // Replace with the actual key file path

    match sign_ima(file, hash_algo, key_path) {
        Ok(_) => println!("Successfully signed IMA"),
        Err(e) => eprintln!("Error signing IMA: {:?}", e),
    }
}

fn sign_ima(file: &str, hash_algo: &str, key_path: &str) -> io::Result<()> {
    let mut hash = vec![0u8; MAX_DIGEST_SIZE + 2]; // +2 byte xattr header
    let algo = get_hash_algo(hash_algo)?;

    if algo > Nid::SHA1.as_raw() as u8 {
        hash[0] = IMA_XATTR_DIGEST_NG;
        hash[1] = algo;
    } else {
        hash[0] = IMA_XATTR_DIGEST;
    }

    let offset = if algo > Nid::SHA1.as_raw() as u8 { 2 } else { 1 };
    // Calculate hash
    let len = calc_hash(file, hash_algo, &mut hash[offset..])?;
    let len = len + offset;

    // Print hash
    println!("hash({}): {:?}", hash_algo, &hash[..len]);

    // Sign hash
    let signature = sign_hash(hash_algo, &hash[offset..len], key_path)?;

    // Set extended attribute
    let mut xattr_value = vec![EVM_IMA_XATTR_DIGSIG];
    xattr_value.extend_from_slice(&signature);

    set_xattr(file, "security.ima", &xattr_value)
}

fn get_hash_algo(algo: &str) -> Result<u8, io::Error> {
    match algo {
        "sha1" => Ok(Nid::SHA1.as_raw() as u8),
        "sha256" => Ok(Nid::SHA256.as_raw() as u8),
        "sha512" => Ok(Nid::SHA512.as_raw() as u8),
        // Add more algorithms as needed
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unknown hash algorithm")),
    }
}

fn calc_hash(file: &str, hash_algo: &str, hash: &mut [u8]) -> io::Result<usize> {
    let mut file = fs::File::open(file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let md = match MessageDigest::from_nid(Nid::from_raw(get_hash_algo(hash_algo)? as i32)) {
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

fn sign_hash(hash_algo: &str, hash: &[u8], key_path: &str) -> io::Result<Vec<u8>> {
    let private_key = fs::read(key_path)?;
    let pkey = PKey::private_key_from_pem(&private_key)?;

    let md = match MessageDigest::from_nid(Nid::from_raw(get_hash_algo(hash_algo)? as i32)) {
        Some(md) => md,
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm")),
    };

    let mut signer = Signer::new(md, &pkey)?;
    signer.update(hash)?;
    let signature = signer.sign_to_vec()?;
    
    Ok(signature)
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
