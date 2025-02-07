use std::fs::File;
use std::io::{Read, Result};
use std::path::Path;
use openssl::sha::Sha512;

// Shared helper function to hash the file
fn hash_file_internal<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new(); // Only SHA512
    let mut buffer = Vec::new();

    // Read the file in chunks to avoid loading it all into memory at once
    while let Ok(bytes_read) = file.read_to_end(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer);
        buffer.clear();
    }

    // Return the final hash as a Vec<u8>
    Ok(hasher.finish().to_vec())
}

// Function to return the hash as a String
#[allow(dead_code)]
pub fn hash_file_str<P: AsRef<Path>>(path: P) -> Result<String> {
    let hash = hash_file_internal(path)?; // Use the shared logic
    Ok(hash.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

// Function to return the hash as a Vec<u8>
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    hash_file_internal(path) // Use the shared logic
}
