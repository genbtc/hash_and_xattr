//hash_and_xattr v0.14 - 2025 (c) genr8eofl @ gmx
//pathwalkr.rs v0.2.6 - attach to main project
//Update v0.2.7. Writes hash directly to system.ima
use std::{env, fs::File, io::{Read,BufRead,stdin,BufReader}, path::{Path,PathBuf}};
use std::io::{Error,ErrorKind,Result};
use openssl::sha::Sha512;
use walkdir::WalkDir;
use rayon::prelude::*;
use xattr;
use atty;

fn hash_file<P: AsRef<Path>>(path: P) -> Result<String> {
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
    Ok(hasher.finish().to_vec().iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

fn set_xattr<P: AsRef<Path>>(path: P, xattr_name: &str, hash: &str) -> Result<()> {
    xattr::set(path, xattr_name, hash.as_bytes())?;
    Ok(())
}

fn process_files(files: Vec<PathBuf>) -> Result<()> {
    // Collect all errors in a vector to handle them after parallel processing
    let errors: Vec<_> = files.into_par_iter().filter_map(|file_path| {
        println!("IMAHash(Name): {:?}", file_path);
        match hash_file(&file_path) {
            Ok(hash) => {
                // Try to set the extended attribute and return any error
                if let Err(e) = set_ima_xattr(&file_path, &hash) {
                    Some(e) // Collect xattr error
                } else {
                    println!("IMAHash(SHA512): {}", hash);
                    None // No error
                }
            }
            Err(e) => Some(e), // Return hash error
        }
    }).collect();
    if errors.is_empty() {
        Ok(()) // All files processed without errors
    } else {
        Err(Error::new(ErrorKind::Other, "Some files failed to process"))
    }
}

fn set_ima_xattr(file_path: &Path, hash: &str) -> Result<()> {
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

//Option 1 - Dir
fn get_files_from_directory(dir: &str) -> Result<Vec<PathBuf>> {
    Ok(
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .collect()
    )
}
//Option 2 - Stdin
fn get_files_from_stdin() -> Result<Vec<PathBuf>> {
    let stdin = stdin();
    let handle = stdin.lock();
    Ok(
    handle.lines()
        .filter_map(|line| line.ok())
        .map(|line| PathBuf::from(line))
        .collect()
    )
}
//Option 3 - File
fn get_files_from_file(file_path: &str) -> Result<Vec<PathBuf>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    // Read each line, strip any surrounding whitespace, and convert it to PathBuf
    let files: Vec<PathBuf> = reader.lines()
        .filter_map(|line| line.ok())            // Filter out any lines that can't be read
        .map(|line| PathBuf::from(line.trim()))  // Trim whitespace and convert to PathBuf
        .collect();
    Ok(files)
}

fn main() -> Result<()> {
    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    // Default directory, if no argument is passed
    let dir = if args.len() > 1 {
        &args[1]
    } else {
        "./" // Set default to the current directory
    };

    // Determine which method to use based on the number of arguments or input type
    let files = if args.len() > 2 {
        // If a third argument is passed, treat it as a file path
        let file_path = &args[2];
        println!("Read filenames from file: {}", file_path);
        get_files_from_file(file_path)?
    } else if atty::is(atty::Stream::Stdin) {
        // If stdin is empty, use directory argument if provided
        println!("Dir: {}", dir);
        get_files_from_directory(dir)?
    } else {
        // Read from stdin (piped input)
        println!("(from stdin):");
        get_files_from_stdin()?
    };

    // Process the files (hash and set xattr)
    process_files(files)
}
