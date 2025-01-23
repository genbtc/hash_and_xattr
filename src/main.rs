//hash_and_xattr v0.1 - 2025 - copyright genr8eofl 
use std::{fs::File, io::{self, Read}, path::Path};
use sha2::{Sha512, Digest};
use walkdir::WalkDir;
use xattr::set;

fn hash_file<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();
    let mut buffer = Vec::new();
    
    // Read the file in chunks to avoid loading it all into memory at once
    while let Ok(bytes_read) = file.read_to_end(&mut buffer) {
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer);
        buffer.clear();
    }
    
    // Finalize the hash and convert it to hex
    Ok(format!("{:x}", hasher.finalize()))
}

fn set_xattr<P: AsRef<Path>>(path: P, hash: &str) -> io::Result<()> {
    let xattr_name = "system.ima";
    set(path, xattr_name, hash.as_bytes())?;
    Ok(())
}

fn process_directory<P: AsRef<Path>>(dir: P) -> io::Result<()> {
    // Walk the directory and process files
    for entry in WalkDir::new(dir) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let file_path = entry.path();
            println!("Hashing file: {:?}", file_path);
            
            // Hash the file
            match hash_file(file_path) {
                Ok(hash) => {
                    println!("Hash: {}", hash);
                    
                    // Set the extended attribute
                    if let Err(e) = set_xattr(file_path, &hash) {
                        eprintln!("Failed to set xattr for {:?}: {}", file_path, e);
                    } else {
                        println!("Extended attribute set for {:?}", file_path);
                    }
                }
                Err(e) => eprintln!("Failed to hash file {:?}: {}", file_path, e),
            }
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let dir = "./"; // Set the directory to scan, can be changed as needed
    process_directory(dir)
}
