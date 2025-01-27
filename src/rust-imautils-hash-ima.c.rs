use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::x509::X509;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_DIGEST_SIZE: usize = 64;
const IMA_XATTR_DIGEST_NG: u8 = 0x04;

fn main() {
    let file = "/tmp/testfile";
    let hash_algo = "sha512";

    match hash_ima(file, hash_algo) {
        Ok(_) => println!("Successfully hashed IMA"),
        Err(e) => eprintln!("Error hashing IMA: {:?}", e),
    }
}

fn hash_ima(file: &str, hash_algo: &str) -> io::Result<()> {
    let mut hash = vec![0u8; MAX_DIGEST_SIZE + 2]; //64 +2 byte xattr header
    hash[0] = IMA_XATTR_DIGEST_NG;  // 0x04
    hash[1] = get_hash_algo(hash_algo)?; // 0x06
    let offset = 2;

    // Hash
    let len = calc_hash(file, hash_algo, &mut hash[offset..])?;
    let len = len + offset;

    // Print hash
    println!("hash({}): {:?}", hash_algo, &hash[..len]);

    // Set extended attribute
    set_xattr(file, "user.imafake", &hash[..len])
}

fn get_hash_algo(algo: &str) -> Result<u8, io::Error> {
    match algo {
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
