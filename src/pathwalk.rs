//hash_and_xattr - pathwalkr.rs v0.3.5
//v0.2.6 - Feb 1, 2025
//v0.3.3 - Filters directories out
use std::{env, fs::File, io::{BufRead,stdin,BufReader}, path::PathBuf};
use std::io::Result;
use walkdir::WalkDir;
use atty;

//Option 1 - Dir
fn get_files_from_directory(dir: &str) -> Result<Vec<PathBuf>> {
    Ok(
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| !path.is_dir()) // Exclude directories
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
        .filter(|path| !path.is_dir()) // Exclude directories
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
        .filter(|path| !path.is_dir()) // Exclude directories
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
        println!("Dir: {}", dir);   //NOTE: Non-recursive.
        get_files_from_directory(dir)
    } else {
        // Read from stdin (piped input)
        println!("(from stdin):");
        get_files_from_stdin()
    };
    files
}
