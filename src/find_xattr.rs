use xattr::{get, list};
use std::ffi::CString;
use std::io::{self, Write};

fn log_error(message: &str, path: &str) {
    eprintln!("{}: {}", message, path);
}

fn find_xattr(xattrs: Vec<String>, xattr_name: &str) -> Option<String> {
    for xattr in xattrs {
        if xattr == xattr_name {
            return Some(xattr);
        }
    }
    None
}

pub fn llistxattr(path: &str, xattr_name: &str) -> Result<Option<String>, io::Error> {
    // Get the list of xattrs associated with the file at the specified path
    let xattrs = list(path)?;
    // Check if the xattr we're looking for is in the list
    match find_xattr(xattrs, xattr_name) {
        Some(xattr) => Ok(Some(xattr)),
        None => Ok(None),
    }
}

#[allow(dead_code)]
fn main() {
    let path = "testA";
    let attr = "user.ima"
    match llistxattr(path) {
        Ok(Some(xattr)) => println!("Found xattr: {}", xattr),
        Ok(None) => println!("xattr not found"),
        Err(err) => log_error("Failed to read xattrs", path),
    }
}
