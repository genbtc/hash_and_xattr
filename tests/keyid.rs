use openssl::rsa::Rsa;
use openssl::sha::Sha1;
use std::fs::File;
use std::io::Read;
use hash_and_xattr::format_hex;
use yasna;
//YASNA implementation:
#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the RSA private key from PEM file
    let mut file = File::open("test_private_key.pem").expect("Failed to open PEM file");
    let mut pem_data = Vec::new();
    file.read_to_end(&mut pem_data).expect("Failed to read PEM file");

    // RSA Pkey load init
    let rsa = Rsa::private_key_from_pem(&pem_data).expect("Failed to parse RSA private key");

    // Convert modulus (n) and exponent (e) to byte arrays
    // Encode the RSA key as a DER SEQUENCE (Modulus + Exponent) - ASN.1 INTEGER (bigint)
    let key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bigint_bytes(&rsa.n().to_vec(), true); // Modulus (n)
            writer.next().write_bigint_bytes(&rsa.e().to_vec(), true); // Exponent (e)
        });
    });
    println!("DER Public Key (PKCS#1) len({}) dump:\n{}", key_der.len(), format_hex::format_hex(&key_der));

    // Compute SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(&key_der);
    let hash = hasher.finish();
    println!("Full SHA-1 Hash: {}", format_hex::format_hex(&hash));
    println!("Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&hash[16..]));

    Ok(())
}
