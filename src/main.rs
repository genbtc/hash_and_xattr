use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::fs;
use std::io::{self};
use std::path::Path;

mod keyid;
use crate::keyid::extract_keyid_from_x509_pem;
#[allow(non_snake_case)]
mod IMAhashAlgorithm;
use crate::IMAhashAlgorithm::HashAlgorithm;

//Default _was_ sha256 https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L71
const DEFAULT_HASH_ALGO: &'static str = "sha512";
//Derived from https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L77-L78
const MAX_DIGEST_SIZE: u8 = 64; // Adjust based on the maximum hash size
const MAX_SIGNATURE_SIZE: u16 = 512; // Adjust based on the maximum signature size
//Derived from enum evm_ima_xattr_type @  https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L92-L99
const IMA_XATTR_DIGEST: u8 = 0x01;
const EVM_IMA_XATTR_DIGSIG: u8 = 0x03;
const IMA_XATTR_DIGEST_NG: u8 = 0x04;
const DIGSIG_VERSION_2: u8 = 0x02;

fn main() {
    let targetfile = "testA"; // TODO: Replace with the actual target file path to hash
    let hash_algo = HashAlgorithm::from_str(DEFAULT_HASH_ALGO).expect("Invalid hash algorithm");    //SHA512
    let key_path = "/home/genr8eofl/signing_key.priv"; // TODO: Replace with the actual key file path

    match sign_ima(targetfile, hash_algo, key_path) {
        Ok(_) => println!("Successfully signed IMA"),
        Err(e) => eprintln!("Error signing IMA: {:?}", e),
    }
}

//format matches sha512sum (hex output), only uppercase
fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join("")
}

fn sign_ima(file: &str, hash_algo: HashAlgorithm, key_path: &str) -> io::Result<()> {
    //Calc hash
    let md = MessageDigest::from_nid(hash_algo.nid())      //HashAlgo to MessageDigest
        .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;
    let calc_hash = calc_hash(file, md)?;
    let len = calc_hash.len();
    if len < MAX_DIGEST_SIZE.into() {
        println!{"hash len is smaller than expected MAX_DIGEST_SIZE {}", MAX_DIGEST_SIZE};
    }

    // Print hash
    println!("hash({:?}): {}", hash_algo, format_hex(&calc_hash));

    // Start IMA Header (0406)
    let mut ima_hash_header: Vec<u8> = vec![];
    if hash_algo.ima_xattr_type() > 1 {
        ima_hash_header.push(IMA_XATTR_DIGEST_NG);
        ima_hash_header.push(hash_algo.ima_xattr_type());
    } else {
        ima_hash_header.push(IMA_XATTR_DIGEST);
    }
    let _offset = if hash_algo.ima_xattr_type() > 1 { 2 } else { 1 };

    // Prepare header of xattr
    let mut ima_hash_packet = vec![];
    ima_hash_packet.extend_from_slice(&ima_hash_header);
    ima_hash_packet.extend_from_slice(&calc_hash);

    let mut ima_sign_header: Vec<u8> = vec![DIGSIG_VERSION_2, hash_algo.ima_xattr_type()];
    //REAL HEADER FORMAT @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/libimaevm.c#L724
    //      03 + 0206 + keyID + MaxSize (0200?) + sig
    //       1 + 2 + 4 + 2 =  +9
    // signature_v2_hdr @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L194
    //keyid ab6f2050 (from /etc/keys/signing_key.priv)
    //call crate::keyid::extract_keyid_from_x509_pem;
    let keyid_result = extract_keyid_from_x509_pem("/home/genr8eofl/signing_key.crt");
    // Extend digsig_header with key_id vector
    match keyid_result {
        Ok(keyid_bytes) => {
            println!("Key ID (X509v3 S.K.I.): {:?}", format_hex(&keyid_bytes));
            ima_sign_header.extend_from_slice(&keyid_bytes);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }

    // Sign file. read original file.
    let ffile = fs::read(file)?;
    let hash_sign = sign_hash(md, &ffile, key_path)?;
    println!("signature: {}", format_hex(&hash_sign));
    let slen = hash_sign.len();
    if slen < (MAX_SIGNATURE_SIZE).into() {
        println!{"signature len is smaller than expected MAX_SIGNATURE_SIZE {}", MAX_SIGNATURE_SIZE};
    }

    // Append max sig size (0x0200)
    ima_sign_header.extend_from_slice(&MAX_SIGNATURE_SIZE.to_be_bytes());
    // Print ima_sign_header
    println!("ima_sign_header: {}", format_hex(&ima_sign_header));

    //Append Signature
    let mut signature: Vec<u8> = vec![EVM_IMA_XATTR_DIGSIG]; // +9 byte xattr header
    signature.extend_from_slice(&ima_sign_header);
    signature.extend_from_slice(&hash_sign);
    // Print final xattr
    println!("final xattr signature ({:?}bytes): {}", signature.len() - 1, format_hex(&signature));

    // Set extended attribute
    set_xattr(file, "system.ima", &signature)?;
    set_xattr(file, "user.system.ima", &signature)
}

fn calc_hash(file: &str, md: MessageDigest) -> io::Result<Vec<u8>> {
    let file = fs::read(file)?;

    let mut hasher = Hasher::new(md)?;
    hasher.update(&file)?;
    let hash_result = hasher.finish()?;
    // Convert DigestBytes to Vec<u8>
    let hash_vec = hash_result.to_vec();
    
    Ok(hash_vec)
}

fn sign_hash(md: MessageDigest, hash: &[u8], key_path: &str) -> io::Result<Vec<u8>> {
    let private_key = fs::read(key_path)?;
    let pkey = PKey::private_key_from_pem(&private_key)?;

    //(DEBUG) PKey { algorithm: "RSA" }
    //println!("(DEBUG) {:?}", pkey);
    //(DEBUG) EVP_PKEY_get1_RSA: Rsa, EVP_PKEY_bits: 4096, EVP_PKEY_id: Id(6), EVP_PKEY_size: 512
    //println!("(DEBUG) EVP_PKEY_get1_RSA: {:?}, EVP_PKEY_bits: {:?}, EVP_PKEY_id: {:?}, EVP_PKEY_size: {:?}"
    //                             , &pkey.rsa().unwrap(), &pkey.bits(), &pkey.id(), &pkey.size());

    let mut signer = Signer::new(md, &pkey)?;
    // Sign the data
    signer.update(hash)?;
    println!{"signer(len): {:?}", signer.len().unwrap()};
    let signature = signer.sign_to_vec()?;

    Ok(signature)
}

use xattr::set;

fn set_xattr(file: &str, attr_name: &str, value: &[u8]) -> io::Result<()> {
    let file_path = Path::new(file);
    // Use the xattr crate's set function
    set(file_path, attr_name, value).map_err(
        |err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}
