use std::fs::File;
use std::path::Path;
use std::io::Result;
use openssl::sha::Sha512;
use std::io::Read;

pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<String> {
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
