//mod set_ima_xattr.rs
use std::path::Path;
use std::io::{Result,Error,ErrorKind};
use xattr;

// Public function 1: Takes `&Path` and `&str`
pub fn set_ima_xattr_path_str(file_path: &Path, hash: &str) -> Result<()> {
    let hash_bytes = hash.as_bytes(); // Convert `&str` to `&[u8]`
    set_ima_xattr_internal(file_path, hash_bytes)
}

// Public function 2: Takes `&str` and `&Vec<u8>`
pub fn set_ima_xattr_str_vec(file_name: &str, data: &[u8]) -> Result<()> {
    let file_path = Path::new(file_name); // Convert `&str` to `Path`
    set_ima_xattr_internal(file_path, data)
}

// Internal function that contains the shared logic for setting xattr
fn set_ima_xattr_internal(file_path: &Path, data: &[u8]) -> Result<()> {
    let file_name = file_path.to_str().ok_or_else(|| {
        Error::new(ErrorKind::InvalidInput, "Invalid file path")
    })?;

    let xattr_name = "system.ima"; // Needs elevated permissions

    // Try to set the extended attribute - system.ima - (first)
    if let Err(e) = set_xattr_str_vec(file_name, xattr_name, data) {
        eprintln!("Failed to set xattr for {:?} with {}: {}",
                  file_path, xattr_name, e);
        // If setting "system.ima" fails, try to set the fallback "user.ima"
        let fallback_xattr_name = "user.ima";   //Does not need permissions
        if let Err(fallback_error) = set_xattr_str_vec(file_name, fallback_xattr_name, data) {
            eprintln!("Failed to set fallback xattr for {:?} with {}: {}",
                      file_path, fallback_xattr_name, fallback_error);
            return Err(fallback_error);  // Return the error directly
        }
        // If fallback succeeds, print success and return early
        println!("Fallback extended attribute set for {:?} with {}",
                  file_path, fallback_xattr_name);
        return Ok(());
    }
    // If setting "system.ima" succeeds, print success and return early
    println!("Extended attribute set for {:?} with {}", file_path, xattr_name);
    Ok(())
}

// function 1: Takes `&Path` and `&str`
#[allow(dead_code)]
fn set_xattr_path_str<P: AsRef<Path>>(file_path: P, xattr_name: &str, hash: &str) -> Result<()> {
    let hash_bytes = hash.as_bytes(); // Convert `&str` to `&[u8]`
    set_xattr_internal(file_path, xattr_name, hash_bytes)
}

// function 2: Takes `&str` and `&Vec<u8>`
fn set_xattr_str_vec(file_name: &str, xattr_name: &str, hash: &[u8]) -> Result<()> {
    let file_path = Path::new(file_name); // Convert `&str` to `Path`
    set_xattr_internal(file_path, xattr_name, hash)
}

// Main Internal function that contains the shared logic for setting xattr
fn set_xattr_internal<P: AsRef<Path>>(file_path: P, xattr_name: &str, hash: &[u8]) -> Result<()> {
    // Set the extended attribute using the hash bytes
    xattr::set(file_path, xattr_name, hash)  // Using the `xattr` crate to set the xattr
}
