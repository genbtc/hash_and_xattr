use openssl::x509::X509;
use std::fs::File;
use std::io::{Read,Result,Error,ErrorKind};
//Local mod works with --bin keyid, and main.rs
use crate::format_hex;

pub fn extract_keyid_from_x509_pem(pem_path: &str) -> Result<Vec<u8>> {
    // Load the PEM file
    let mut file = File::open(pem_path).expect("Failed to open PEM file");
    let mut pem_contents = String::new();
    file.read_to_string(&mut pem_contents).expect("Failed to read PEM file");

    // Parse the certificate
    let cert = X509::from_pem(pem_contents.as_bytes()).expect("Failed to parse X509 certificate");

    // Extract the last 4 bytes of the Subject Key Identifier (SKI)
    if let Some(ski) = cert.subject_key_id() {
        let ski_bytes = ski.as_slice();
        let keyid_bytes = ski_bytes[ski_bytes.len() - 4..].to_vec();
        println!("Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));
        Ok(keyid_bytes)
    } else {
        Err(Error::new(ErrorKind::NotFound, "X509v3 Subject Key Identifier not found"))
    }
}

// This is an example of how to call the function
//#[allow(dead_code)]
/*
fn main() {
    let pem_path = "/home/genr8eofl/signing_key.crt";
    let _ = extract_keyid_from_x509_pem(pem_path);
}
*/
