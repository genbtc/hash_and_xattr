//mod set_ima_xattr.rs
use std::path::Path;
use std::io::Result;
use xattr;

pub fn set_ima_xattr(file_path: &Path, hash: &str) -> Result<()> {
    // Try to set the extended attribute - system.ima - (first)
    let xattr_name = "system.ima"; // Needs elevated permissions
    if let Err(e) = set_xattr(file_path, xattr_name, hash) {
        eprintln!("Failed to set xattr for {:?} with {}: {}",
                  file_path, xattr_name, e);
        // Attempt to set the xattr - user.ima - (if system.ima fails)
        let fallback_xattr_name = "user.ima";   //Does not need permissions
        if let Err(fallback_error) = set_xattr(file_path, fallback_xattr_name, hash) {
            eprintln!("Failed to set fallback xattr for {:?} with {}: {}",
                      file_path, fallback_xattr_name, fallback_error);
        } else {
            println!("Fallback extended attribute set for {:?} with {}",
                      file_path, fallback_xattr_name);
        }
    } else {
        println!("Extended attribute set for {:?} with {}", file_path, xattr_name);
    }

    Ok(())
}

fn set_xattr<P: AsRef<Path>>(path: P, xattr_name: &str, hash: &str) -> Result<()> {
    xattr::set(path, xattr_name, hash.as_bytes())?;
    Ok(())
}
