use openssl::x509::X509;
use std::fs::File;
use std::io::Read;

fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":")
}

pub fn extract_keyid_from_x509_pem(pem_path: &str) {
    // Load the PEM file
    let mut file = File::open(pem_path).expect("Failed to open PEM file");
    let mut pem_contents = String::new();
    file.read_to_string(&mut pem_contents).expect("Failed to read PEM file");

    // Parse the certificate
    let cert = X509::from_pem(pem_contents.as_bytes()).expect("Failed to parse X509 certificate");

    // Convert the certificate to text and Print it
    let cert_text_bytes = cert.to_text().expect("Failed to convert certificate to text");
    let cert_text = String::from_utf8(cert_text_bytes).expect("Failed to convert bytes to string");
    println!("Certificate:\n{}", cert_text);

    // Extract and print the last 4 bytes of the Subject Key Identifier (SKI)
    if let Some(ski) = cert.subject_key_id() {
        let ski_bytes = ski.as_slice();
        println!("Full SKI: {}", format_hex(&ski_bytes));
        let keyid_bytes = &ski_bytes[ski_bytes.len() - 4..];
        let keyid = u32::from_be_bytes([keyid_bytes[0], keyid_bytes[1], keyid_bytes[2], keyid_bytes[3]]);
        println!("Key ID (from SKI): {:08X}", keyid);
    } else {
        println!("X509v3 Subject Key Identifier not found");
    }
}

// This is an example of how to call the function
fn main() {
    extract_keyid_from_x509_pem("/home/genr8eofl/signing_key.pem");
}
