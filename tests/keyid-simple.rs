use openssl::rsa::Rsa;
use openssl::sha::Sha1;
use std::fs::File;
use std::io::Read;

#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the RSA private key from the PEM file.
    let mut file = File::open("test_private_key.pem")?;
    let mut pem_data = Vec::new();
    file.read_to_end(&mut pem_data)?;
    
    // Parse the RSA private key.
    let rsa = Rsa::private_key_from_pem(&pem_data)?;
    
    // Get the DER-encoded public key in PKCS#1 format.
    // This returns only the modulus and exponent (without any OID structure).
//    let key_der = rsa.public_key_to_der()?;   //has 24 byte OID header
    let key_der = rsa.public_key_to_der_pkcs1()?;
    println!("DER Public Key (PKCS#1) len({}): {}", key_der.len(), hex::encode(&key_der));

    // Compute the SHA-1 hash of the DER bytes.
    let mut hasher = Sha1::new();
    hasher.update(&key_der);
//    hasher.update(&key_der[24..]);    //old way
    let hash = hasher.finish();
    println!("SHA-1 Hash: {}", hex::encode(&hash));

    // Extract the last 4 bytes of the SHA-1 hash (as is common for an X509v3 Subject Key Identifier).
    let keyid_bytes: [u8; 4] = hash[16..].try_into()?;
    println!("Found! Key ID (X509v3 S.K.I.): {}", hex::encode(&keyid_bytes));

    Ok(())
}
