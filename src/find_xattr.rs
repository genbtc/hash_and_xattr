use xattr;
use std::io::{self};
use std::path::Path;
use crate::format_hex;

fn log_error(message: &str, path: &str) {
    eprintln!("{}: {}", message, path);
}

fn is_directory(path: &str) -> bool {
    Path::new(path).is_dir()
}

//Check Does the xattr exist?
pub fn llistxattr(path: &str, xattr_name: &str) -> Result<Option<String>, io::Error> {
    if is_directory(path) {
        return Ok(None);    //skip directories now
    }
    // Get the list of xattrs associated with the file at the specified path
    let xattrs = xattr::list(path)?;

    // Search for the specified xattr directly in the list
    for xattr in xattrs {
        if xattr == xattr_name {
            // Fetch the value of the xattr
            match xattr::get(path, xattr_name) {
                Ok(value) => {
                    // Try to convert the xattr value to a String
                   if let Some(v) = &value {
                        let hexstr = format_hex::format_hex(v);
                        //println!(IMAHash(SHA512): {}", hexstr); //TODO: Debug
                        return Ok(Some(hexstr));
                    }
                }
                Err(_) => return Ok(None), // Return None if the xattr value cannot be fetched
            }
        }
    }
    Ok(None) // Return None if the xattr wasn't found
}

#[allow(dead_code)]
fn main() {
    let path = "testA";
    let attr = "user.ima";
    match llistxattr(path,attr) {
        Ok(Some(xattr)) => println!("Found xattr: {}", xattr),
        Ok(None) => println!("xattr not found"),
        Err(_err) => log_error("Failed to read xattrs", path),
    }
}
