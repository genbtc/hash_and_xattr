//hash_and_xattr v0.14 - 2025 (c) genr8eofl @ gmx
//pathwalkr.rs v0.2.6 - attach to main project
//Update v0.2.7. Writes hash directly to system.ima
//Latest version: v0.2.8 - Feb 1, 2025
use std::{env, fs::File, io::{BufRead,stdin,BufReader}, path::PathBuf};
use std::io::{Error,ErrorKind,Result};
use walkdir::WalkDir;
use rayon::prelude::*;
use atty;
//Local mods
mod hash_file;
mod set_ima_xattr;

fn ima_process_files(files: Vec<PathBuf>) -> Result<()> {
    // Collect all errors in a vector to handle them after parallel processing
    let errors: Vec<_> = files.into_par_iter().filter_map(|file_path| {
        println!("IMAHash(Name): {:?}", file_path);
        match crate::hash_file::hash_file(&file_path) {
            Ok(hash) => {
                // Try to set the extended attribute and return any error
                if let Err(e) = crate::set_ima_xattr::set_ima_xattr(&file_path, &hash) {
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
        Err(Error::new(ErrorKind::Other, "Some files failed to process!\n"))
    }
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

    // IMA Process the files (hash and set xattr)
    ima_process_files(files)
}
