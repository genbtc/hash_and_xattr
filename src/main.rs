use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use std::fs;
use std::io::{self};
use std::path::Path;
//Local mods (lib.rs)
mod keyid;
use crate::keyid::extract_keyid_from_x509_pem;
use hash_and_xattr::IMAhashAlgorithm::HashAlgorithm;
use hash_and_xattr::format_hex::format_hex;
use hash_and_xattr::hash_file::hash_file;

//#const PRIVATE_KEY_PATH: &'static str ="/etc/keys/signing_key.priv"; // TODO: Replace with the actual key file path
//const PUBLIC_CERT_PATH: &'static str ="/etc/keys/signing_key.pem"; // TODO: ^^
const PRIVATE_KEY_PATH: &'static str ="/home/genr8eofl/signing_key.priv"; // TODO: Replace with the actual key file path
const PUBLIC_CERT_PATH: &'static str ="/home/genr8eofl/signing_key.crt"; // TODO: ^^
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

    match sign_ima(targetfile, hash_algo, PRIVATE_KEY_PATH) {
        Ok(_) => println!("Successfully signed IMA"),
        Err(e) => eprintln!("Error signing IMA: {:?}", e),
    }
}

fn sign_ima(file: &str, hash_algo: HashAlgorithm, key_path: &str) -> io::Result<()> {
    //Calc hash
//    let calc_hash = hash_file(file, md)?;
    let calc_hash = hash_file(file)?;
    let len = calc_hash.len();
    if len < MAX_DIGEST_SIZE.into() {
        println!{"Hash len is smaller than expected MAX_DIGEST_SIZE {}", MAX_DIGEST_SIZE};
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
    let keyid_result = extract_keyid_from_x509_pem(PUBLIC_CERT_PATH)?;
    ima_sign_header.extend_from_slice(&keyid_result);


    // Sign file. read original file.
    let md = MessageDigest::from_nid(hash_algo.nid())      //HashAlgo to MessageDigest
            .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Invalid hash algorithm"))?;
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
    println!("Signature ({:?}bytes): {}", signature.len() - 1, format_hex(&signature));

    // Set extended attribute, security.ima
    let sys = set_xattr(file, "security.ima", &signature);
    match sys {
        Ok(c) => {
            println!("Wrote security.ima {:?}byte signature", signature.len() - 1);
            Ok(c)
        }
        Err(e) => {
            eprintln!("Error writing security.ima: {}", e);
            println!("Wrote user.ima {:?}byte signature instead", signature.len() - 1);
            set_xattr(file, "user.ima", &signature)
        }
    }
}

fn sign_hash(md: MessageDigest, hash: &[u8], key_path: &str) -> io::Result<Vec<u8>> {
    let private_key = fs::read(key_path)?;
    let pkey = PKey::private_key_from_pem(&private_key)?;

    let mut signer = Signer::new(md, &pkey)?;
    // Sign the data - 64byte hash -> 512byte sig
    signer.update(hash)?;
    let signature = signer.sign_to_vec()?;

    Ok(signature)
}

fn set_xattr(file: &str, attr_name: &str, value: &[u8]) -> io::Result<()> {
    let file_path = Path::new(file);
    // Use the xattr crate's set function
    xattr::set(file_path, attr_name, value).map_err(
        |err| io::Error::new(io::ErrorKind::Other, err.to_string()))
}
