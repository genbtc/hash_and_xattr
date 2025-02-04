use openssl::x509::{X509, X509Builder};
use openssl::pkey::{PKey,Public,Private};
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::sha::sha1;
use std::convert::TryInto;
use std::path::Path;
use std::fs::{File};
use std::io::Read;
//use std::io::{Error,ErrorKind};
use hash_and_xattr::format_hex;

fn generate_self_signed_cert(private_key: PKey<Private>, public_key:PKey<Public>) -> Result<X509, Box<dyn std::error::Error>> {
    // Create a new X509 builder
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_pubkey(&public_key)?;

    // Sign the certificate with the private key
    builder.sign(&private_key, MessageDigest::sha512())?;

    // Build the certificate
    let cert = builder.build();
    
    //Check for Subject Key ID.
    if let Some(key_id) = cert.subject_key_id() {
        let key_id_bytes = key_id.as_slice(); // Convert to byte slice
        let key_id_hex: String = key_id_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        println!("FOUND X509 Subject Key Identifier: {}", key_id_hex);
    } else {
        println!("X509 Subject Key Identifier NOT found in the certificate!.");
    }

    Ok(cert)
}


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

fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>, Box<dyn std::error::Error>> {
    // Open the PEM file
    let mut file = File::open(path)?;
    // Read the contents into a vector of bytes
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)?;
    // Load the private key from the PEM contents
    Ok(PKey::private_key_from_pem(&pem)?)
}

fn load_public_key<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Public>, Box<dyn std::error::Error>> {
    // Open the PEM file
    let mut file = File::open(path)?;
    // Read the contents into a vector of bytes
    let mut pem = Vec::new();
    file.read_to_end(&mut pem)?;
    // Load the public key from the PEM contents
    Ok(PKey::public_key_from_pem(&pem)?)
}

#[test]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_path = "test_private_key.pem";
    let public_key_path = "test_public_key.pem";
    // Load the private key
    let private_key = load_private_key(private_key_path)?;
    // Now you can use `private_key` as needed
    println!("Private key successfully loaded: {}", private_key_path);
    // Load the public key
    let public_key = load_public_key(public_key_path)?;
    // Now you can use `public_key` as needed
    println!("Public key successfully loaded: {}", public_key_path);

    //Hash Priv Der Bytes
    let priv_der_bytes = private_key.private_key_to_der()?;
    let hash = sha1(&priv_der_bytes);   //710da1b3
//    println!("priv_der_hash: {}", format_hex::format_hex(&hash));
    // Extract the first 4 bytes of the hash
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("1Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    //Hash Pub Pem
    let pub_pem = public_key.public_key_to_pem()?;
    let hash = sha1(&pub_pem);  //9b4948b0
//    println!("pub_pem_hash: {:?}", hash);
    // Extract the first 4 bytes of the hash
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("2Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Extract the public key from the private key
    let public_key_pem = private_key.public_key_to_pem()?;
    let hash = sha1(&public_key_pem);   //9b4948b0
//    println!("priv_pub_pem_hash: {:?}", hash);
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("3Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    //Hash Pub Der Bytes
    let pub_der_bytes = public_key.public_key_to_der()?;
    let hash = sha1(&pub_der_bytes);    //a621f3b5
//    println!("pub_der_hash: {:?}", hash);
    // Extract the first 4 bytes of the hash
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("4Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Convert the PEM-encoded public key into a PKey<Public>
    let public_key = PKey::public_key_from_pem(&public_key_pem)?;
    // Convert the PEM-Pub-Key into a DER
    let pub_der_bytes = public_key.public_key_to_der()?;
    let hash = sha1(&pub_der_bytes);    //a621f3b5
//    println!("pub_der_hash: {:?}", hash);
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("5Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Calculate the key ID
    let _key_id = calc_keyid_v2(&public_key)?;   //a621f3b5

    // Parse the PEM data into an RSA public key
    let rsa = Rsa::public_key_from_pem(&pub_pem)?;
    // Convert the RSA public key into a PKey
    let _pkey = PKey::from_rsa(rsa)?;

    // Generate a self-signed certificate
    let _cert = generate_self_signed_cert(private_key, public_key.clone())?;
    Ok(())
}
