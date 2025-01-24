//hash_and_xattr v0.13 - 2025 (c) genr8eofl @ gmx
use std::{env, fs::File, io::{self, Read,BufRead}, path::{Path,PathBuf}};
use sha2::{Sha512, Digest};
use walkdir::WalkDir;
use xattr::set;
use rayon::prelude::*;
use atty;

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

fn process_files(files: Vec<PathBuf>) -> io::Result<()> {
    // Process files in parallel using Rayon
    files.into_par_iter().for_each(|file_path| {
        println!("IMAHash(Name): {:?}", file_path);
        
        // Hash the file
        match hash_file(&file_path) {
            Ok(hash) => {
                println!("IMAHash(SHA512): {}", hash);
                
                // Set the extended attribute
//                    let xattr_name = "system.ima"; //needs permissions 
                let xattr_name = "user.ima"; //doesnt need permission
                if let Err(e) = set_xattr(&file_path, xattr_name, &hash) {
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

fn get_files_from_directory(dir: &str) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

fn get_files_from_stdin() -> Vec<PathBuf> {
    let stdin = io::stdin();
    let handle = stdin.lock();
    
    handle
        .lines()
        .filter_map(|line| line.ok())
        .map(|line| PathBuf::from(line))
        .collect()
}

fn main() -> io::Result<()> {
//    let dir = "./"; // Set the directory to scan, can be changed as needed. //TODO: and -f file.txt
    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    // Default directory, if no argument is passed
    let dir = if args.len() > 1 {
        &args[1]
    } else {
        "./" // Default to the current directory
    };

    // Determine if we should read from stdin or use a directory argument
    let files = if atty::is(atty::Stream::Stdin) {
        // If stdin is empty, use directory argument if provided
        println!("IMAHash(Dir): {}", dir);
        get_files_from_directory(dir)
    } else {
        // Read from stdin (piped input)
        println!("IMAHash(stdin):");
        get_files_from_stdin()
    };
    // Process the files (hash and set xattr)
    process_files(files)
}
