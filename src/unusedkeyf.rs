use openssl::pkey::{PKey,Public,Private};
use openssl::sha::{sha1,Sha1};
use std::fs::{File};                                                                                                                                  
use std::io::Read;

#[allow(dead_code)]
fn calc_keyid_v2(pkey: &PKey<openssl::pkey::Public>) -> Result<u32, Box<dyn std::error::Error>> {
    // Convert the PKey to DER format
    let der_bytes = pkey.public_key_to_der()?;
    // Compute the SHA1 hash of the DER-encoded public key
    let hash = sha1(&der_bytes);
    // Extract the first 4 bytes of the hash
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));
    // Convert the bytes to a 32-bit unsigned integer
    let keyid = u32::from_be_bytes(keyid_bytes);

    Ok(keyid)
}

#[allow(dead_code)]
fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>, Box<dyn std::error::Error>> {
    // Open the PEM file
    let mut file = File::open(path)?;
    // Read the contents into a vector of bytes
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)?;
    // Load the private key from the PEM contents
    Ok(PKey::private_key_from_pem(&pem)?)
}

#[allow(dead_code)]
fn load_public_key<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Public>, Box<dyn std::error::Error>> {
    // Open the PEM file
    let mut file = File::open(path)?;
    // Read the contents into a vector of bytes
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)?;
    // Load the public key from the PEM contents
    Ok(PKey::public_key_from_pem(&pem)?)
}
