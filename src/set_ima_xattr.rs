use std::path::Path;
use std::io::{Result,Error,ErrorKind};
use xattr;

#[allow(dead_code)]
// Public function 0: Takes `&Path` and `&[u8]`
pub fn set_ima_xattr_path_vec(file_path: &Path, data: &[u8]) -> Result<()> {
    set_ima_xattr_internal(file_path, data)
}
// Public function 1: Takes `&Path` and `&str`
#[allow(dead_code)]
pub fn set_ima_xattr_path_str(file_path: &Path, hash: &str) -> Result<()> {
    let hash_bytes = hash.as_bytes(); // Convert `&str` to `&[u8]`
    set_ima_xattr_internal(file_path, hash_bytes)
}
// Public function 2: Takes `&str` and `&Vec<u8>` or `&[u8]`
pub fn set_ima_xattr_str_vec(file_name: &str, data: &[u8]) -> Result<()> {
    let file_path = Path::new(file_name); // Convert `&str` to `Path`
    set_ima_xattr_internal(file_path, data)
}

// Internal function that contains the shared logic for setting xattr
//TODO: Refactor to take (security., user.) 
fn set_ima_xattr_internal(file_path: &Path, data: &[u8]) -> Result<()> {
    let file_name = file_path.to_str().ok_or_else(|| {
        Error::new(ErrorKind::InvalidInput, "Invalid file path!")
    })?;

    let xattr_name = "security.ima"; // Needs elevated permissions

    // Try to set the extended attribute - security. - (first)
    if let Err(e) = set_xattr_str_vec(file_name, xattr_name, data) {
        eprintln!("Failed to write {} secure xattr set for {:?}: {}",
                  xattr_name, file_path, e);
        // If setting "security." fails, try to set the fallback "user."
        let fallback_xattr_name = "user.ima";   //Does not need permissions
        if let Err(fallback_error) = set_xattr_str_vec(file_name, fallback_xattr_name, data) {
            eprintln!("Failed to write {} fallback user xattr set for {:?}: {}",
                      fallback_xattr_name, file_path, fallback_error);
            return Err(fallback_error);  // Return the error directly
        }
        // If fallback succeeds, print success and return early
        println!("Wrote {} fallback user extended attribute set for {:?}",
                  fallback_xattr_name, file_path);
        return Ok(());
    }
    // If setting "security." succeeds, print success and return early
    println!("Wrote {} secure extended attribute set for: {:?}", xattr_name, file_path);
    Ok(())
}

// Main function: Takes `&str` and `&Vec<u8>` or `&[u8]`
fn set_xattr_str_vec(file_name: &str, xattr_name: &str, data: &[u8]) -> Result<()> {
    let file_path = Path::new(file_name); // Convert `&str` to `Path`
    set_xattr_internal(file_path, xattr_name, data)
}

// Main Internal function that contains the shared logic for setting xattr
fn set_xattr_internal<P: AsRef<Path>>(file_path: P, xattr_name: &str, data: &[u8]) -> Result<()> {
    // Set the extended attribute using the data bytes
    xattr::set(file_path, xattr_name, data)  // Using the `xattr` crate to set the xattr
}
