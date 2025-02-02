use xattr::{get,list};
use std::io::{self};

fn log_error(message: &str, path: &str) {
    eprintln!("{}: {}", message, path);
}

pub fn llistxattr(path: &str, xattr_name: &str) -> Result<Option<String>, io::Error> {
    // Get the list of xattrs associated with the file at the specified path
    let xattrs = list(path)?;

    // Search for the specified xattr directly in the list
    for xattr in xattrs {
        if xattr == xattr_name {
            // Fetch the value of the xattr
            match get(path, xattr_name) {
                Ok(value) => {
                    // Try to convert the xattr value to a String
                    if let Ok(value_str) = String::from_utf8(value.expect("unexpected string conversion error")) {
                        return Ok(Some(value_str)); // Return the value as a String if it's valid UTF-8
                    } else {
                        return Ok(None); // Return None if the value is not valid UTF-8
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
