//hash_and_xattr v0.14 - 2025 (c) genr8eofl @ gmx
//pathwalkr.rs v0.2.6 - attach to main project
//Update v0.2.7. Writes hash directly to security.ima
//Latest version: v0.2.9 - Feb 1, 2025
use std::{env, fs::File, io::{BufRead,stdin,BufReader}, path::PathBuf};
//use std::io::{Error,ErrorKind,Result};
use std::io::Result;
use walkdir::WalkDir;
//use rayon::prelude::*;
use atty;
//Local mods
//use crate::format_hex;
//use crate::hash_file;
//use crate::set_ima_xattr;                                                                                                                                                                                                                                              

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
    Ok(handle.lines()
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
    Ok(reader.lines()
        .filter_map(|line| line.ok())            // Filter out any lines that can't be read
        .map(|line| PathBuf::from(line.trim()))  // Trim whitespace and convert to PathBuf
        .collect()
    )
}

pub fn pathwalk() -> Result<Vec<PathBuf>> {
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
        get_files_from_file(file_path)
    } else if atty::is(atty::Stream::Stdin) {
        // If stdin is empty, use directory argument if provided
        println!("Dir: {}", dir);
        get_files_from_directory(dir)
    } else {
        // Read from stdin (piped input)
        println!("(from stdin):");
        get_files_from_stdin()
    };
    files
    // Simple SHA-512 Hash the files (hash set to xattr)
    //hash_files(files)
}

/*
#[allow(dead_code)]
fn main() -> Result<Vec<PathBuf>> {
    hash_files(pathwalk()?)
}

pub fn hash_files(files: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    // Collect all errors in a vector to handle them after parallel processing
    let errors: Vec<_> = files.clone().into_par_iter().filter_map(|file_path| {
        println!("IMAHash(Name): {:?}", file_path);
        match hash_file::hash_file(&file_path) {
            Ok(hash) => {
                // Try to set the extended attribute and return any error
                if let Err(e) = set_ima_xattr::set_ima_xattr_str_vec(&file_path.to_str()?, &hash) {
                    Some(e) // Collect xattr error
                } else { //TODO: If verbose
                    println!("IMAHash(SHA512): {}", format_hex::format_hex(&hash));
                    None // No error
                }
            }
            Err(e) => Some(e), // Return hash error
        }
    }).collect();
    if errors.is_empty() {
        Ok(files) // All files processed without errors
    } else {
        Err(Error::new(ErrorKind::Other, "Some files failed to process!\n"))
    }
}
*/
