use openssl::x509::{X509, X509Builder};
use openssl::pkey::{PKey,Public,Private};
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use openssl::sha::{sha1,Sha1};
use openssl::bn::BigNum;
use std::convert::TryInto;
use std::path::Path;
use std::fs::{File};
use std::io::Read;
//use std::io::{Error,ErrorKind};
use hash_and_xattr::format_hex;
use yasna::Tag;
use yasna::{self, DERWriter};
use yasna::models::ObjectIdentifier;
use num_bigint::BigUint;

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

    //Hash Priv Pem Bytes
    let priv_pem_bytes = private_key.private_key_to_pem_pkcs8()?;
    let hash = sha1(&priv_pem_bytes);   //710da1b3
//    println!("priv_der_hash: {}", format_hex::format_hex(&hash));
    // Extract the first 4 bytes of the hash
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("0Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

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
    let private_public_key_pem = private_key.public_key_to_pem()?;
    let hash = sha1(&private_public_key_pem);   //9b4948b0
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
    let public_key = PKey::public_key_from_pem(&private_public_key_pem)?;
    // Convert the PEM-Pub-Key into a DER
    let pkey_der_bytes = public_key.public_key_to_der()?;
    let hash = sha1(&pkey_der_bytes);    //a621f3b5
//    println!("pub_der_hash: {:?}", hash);
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("5Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Calculate the 6key ID
    let _key_id = calc_keyid_v2(&public_key)?;   //a621f3b5

    // Parse the PEM data into an RSA public key
    let rsa = Rsa::public_key_from_pem(&pub_pem)?;
    // Convert the RSA public key into a PKey
    let pkey = PKey::from_rsa(rsa)?;
    // Get the public key in DER format
    let der_bytes = pkey.public_key_to_der().expect("Failed to serialize public key");

    // Hash the DER-encoded public key using SHA-1
    let mut hasher = Sha1::new();
    hasher.update(&der_bytes);
    let hashed_pubkey = hasher.finish();
    println!("RSA Public Key Hash (SHA-1): {:x?}", hashed_pubkey);

    //last resort
    let mut file = File::open("test_private_key.pem").expect("Failed to open PEM file");
    let mut pem_data = Vec::new();
    file.read_to_end(&mut pem_data).expect("Failed to read PEM file");

    // Load the RSA private key from the PEM file
    let rsa = Rsa::private_key_from_pem(&pem_data).expect("Failed to parse RSA private key");
    // Convert the RSA private key into a public key wrapped in PKey
    let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");
    // Extract the public key in DER format (equivalent to i2d_PUBKEY in C)
    let der_bytes = pkey.public_key_to_der().expect("Failed to convert public key to DER");
    // Compute SHA-1 hash of the DER-encoded public key
    let mut hasher = Sha1::new();
    hasher.update(&der_bytes);
    let hash = hasher.finish();
    // Print the SHA-1 hash in hexadecimal format
    println!("SHA-1 hash of public key:    {:x?}", hash);

//YASNA implementation. 
    // Read the RSA private key from PEM file
    let mut file = File::open("test_private_key.pem").expect("Failed to open PEM file");
    let mut pem_data = Vec::new();
    file.read_to_end(&mut pem_data).expect("Failed to read PEM file");

    let rsa = Rsa::private_key_from_pem(&pem_data).expect("Failed to parse RSA private key");

    // Convert modulus (n) and exponent (e) to byte arrays
    let mut n_bytes = rsa.n().to_vec();
    let mut e_bytes = rsa.e().to_vec();

    // Encode the RSA key as a DER SEQUENCE (Modulus + Exponent) - ASN.1 INTEGER 
    let key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bigint_bytes(&n_bytes,true); // Modulus (n)
            writer.next().write_bigint_bytes(&e_bytes,true); // Exponent (e)
        });
    });
    println!("DER Public Key (PKCS#1) len({}): {}", key_der.len(), format_hex::format_hex(&key_der));
    // Compute SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(&key_der);
    let hash = hasher.finish();
    println!("SHA-1 Hash: {:x?}", hash);
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("6Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Construct the full DER encoding of the public key
    let der_bytes = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // ✅ Correctly wrap in BIGINT (02), not OCTET STRING (04)
            writer.next().write_bigint_bytes(&pem_data,true); // 0 padding bits
        });
    });
    println!("DER Public Key (PKCS#1) len({}): {}", der_bytes.len(), format_hex::format_hex(&der_bytes[20..]));

    // Compute SHA-1 hash
    let mut hasher = Sha1::new();
    hasher.update(&der_bytes);
    let hash = hasher.finish();
    println!("SHA-1 Hash: {:x?}", hash);
    let keyid_bytes: [u8; 4] = hash[hash.len()-4..].try_into()?;
    println!("7Key ID (X509v3 S.K.I.): {}", format_hex::format_hex(&keyid_bytes));

    // Generate a self-signed certificate
    let _cert = generate_self_signed_cert(private_key, public_key.clone())?;
    Ok(())
}
