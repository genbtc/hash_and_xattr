//hash_and_xattr v0.11 - 2025 (c) genr8eofl @ gmx
use std::{fs::File, io::{self, Read}, path::Path};
use sha2::{Sha512, Digest};
use walkdir::WalkDir;
use xattr::set;
use rayon::prelude::*;

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

fn set_xattr<P: AsRef<Path>>(path: P, xattr_name: &str, hash: &str) -> io::Result<()> {
    set(path, xattr_name, hash.as_bytes())?;
    Ok(())
}

fn process_directory<P: AsRef<Path>>(dir: P) -> io::Result<()> {
    // Walk the directory and collect all files into a vector
    let files: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .collect();

    // Process files in parallel using Rayon
    files.into_par_iter().for_each(|entry| {
        let file_path = entry.path();
        println!("IMAHash(Name): {:?}", file_path);
        
        // Hash the file
        match hash_file(file_path) {
            Ok(hash) => {
                println!("IMAHash(SHA512): {}", hash);
                
                // Set the extended attribute
//                    let xattr_name = "system.ima"; //needs permissions 
                let xattr_name = "user.ima"; //doesnt need permission
                if let Err(e) = set_xattr(file_path, xattr_name, &hash) {
                    eprintln!("Failed to set xattr for {:?}!!: {}", file_path, e);
                } else {
                    println!("Extended attribute set for {:?}", file_path);
                }
            }
            Err(e) => eprintln!("Failed to hash file {:?}!: {}", file_path, e),
        }
    });
    Ok(())
}

fn main() -> io::Result<()> {
    let dir = "./"; // Set the directory to scan, can be changed as needed. //TODO: read from Argv0, stdin, and -f file.txt
    process_directory(dir)
}
