// hash_and_xattr v0.3.5 - by genr8eofl @2025 - LICENSE: AGPL3
// Signs files with an IMA signature and verifies them
#[allow(unused_imports)]
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer,Verifier};
use std::fs::{self};
use std::io::{self,Error,ErrorKind};
#[cfg(not(test))]
use std::path::{Path, PathBuf};
//use std::path::Path;
//Local mods (lib.rs)
use hash_and_xattr::IMAhashAlgorithm::*;
use hash_and_xattr::format_hex::format_hex;
#[allow(unused_imports)]
use hash_and_xattr::keyid;
#[allow(unused_imports)]
use hash_and_xattr::hash_file;
use hash_and_xattr::set_ima_xattr;
use hash_and_xattr::find_xattr;
#[cfg(not(test))]
use hash_and_xattr::pathwalk;
#[allow(unused_imports)]
use hash_and_xattr::keyutils;

#[cfg(test)]
const TEST_PRIVATE_KEY_PATH: &'static str ="test_private_key.pem";
#[cfg(test)]
const _TEST_PUBLIC_KEY_PATH: &'static str ="test_public_key.pem";

//const SYS_PRIVATE_KEY_PATH: &'static str ="/etc/keys/signing_key.priv"; // TODO: Replace with the system key file path
//const SYS_PUBLIC_CERT_PATH: &'static str ="/etc/keys/signing_key.pem"; // TODO: Switch keys if privs allow?
#[cfg(not(test))]
const PRIVATE_KEY_PATH: &'static str ="/home/genr8eofl/signing_key.priv"; // TODO: Replace with the default key file path
#[cfg(not(test))]
const _PUBLIC_CERT_PATH: &'static str ="/home/genr8eofl/signing_key.crt"; // TODO: ^^

fn sign_ima(pkey: &PKey<openssl::pkey::Private>, file: &str, hash_algo: HashAlgorithm, keyid: &[u8]) -> io::Result<()> {
    let hash_type = hash_algo.ima_xattr_type();
    let md = MessageDigest::from_nid(hash_algo.nid()) //HashAlgo to MessageDigest
            .ok_or(Error::new(ErrorKind::InvalidInput, "Invalid hash algorithm"))?;
    //let calc_hash = calc_ima_hash(file, &hash_algo); //TODO: use hash later

// Start IMA_Signed Header(v2)
    //REAL HEADER FORMAT @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/libimaevm.c#L724
    // this 03 = EVM_IMA_XATTR_DIGSIG, pre-pended afterwards. //TODO: why?
    //      ^^ + 0206 + keyID(u32) + MaxSize=Hex(0200) + signature = 520b
    //       1 +  2   +     4      +     2      =   +9 + 512 = 521bytes
    // signature_v2_hdr @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L194
    let mut ima_sign_header: Vec<u8> = vec![DIGSIG_VERSION_2, hash_type];   //0206
    ima_sign_header.extend_from_slice(&keyid);    //keyid ab6f2050 (from /etc/keys/signing_key.priv)

    // security.ima - Check for existence of xattr
    let xattr_name = "security.ima";
    match find_xattr::llistxattr(file, xattr_name) {
        Ok(Some(xattr)) => { //TODO: Don't always skip, or add force ?
            //Verify
            let freadfile = fs::read(file)?;
            match verify_signature(pkey, md, &freadfile, &xattr) {
                Ok(success) => {
                  if success { 
                    return Ok(());
                    /*println!("Success, Hash Matches! Write Skipped!");*/
                  } else { 
                    println!("SIGNFAIL: Verification Mismatch! @ {}", file);
                }},
                Err(err) => eprintln!("Error in Signature Verification! {}", err),
            }
            //return Err(Error::new(ErrorKind::AlreadyExists, "security.ima xattr Already Exists, Skipped!"));
        },
        Ok(None) => {},
        Err(err) => eprintln!("Error reading xattrs!: {}", err),
    }

    // IMA Sign the original file (openssl SHA512 + openssl RSA)
    let freadfile = fs::read(file)?;
    let ima_sig = sign_bytes(pkey, md, &freadfile)?;
    let ima_sig_len: [u8; 2] = (ima_sig.len() as u16).to_be_bytes();
    //println!("signature({}b): {}", ima_sig_len, format_hex(&ima_sig));  //DebugPrint
    if ima_sig_len != MAX_SIGNATURE_SIZE.to_be_bytes() {
        eprintln!{"signature length {:?} differs from expected MAX_SIGNATURE_SIZE {}",
                   ima_sig_len, MAX_SIGNATURE_SIZE};
    }
    // Append sig length to header
    ima_sign_header.extend_from_slice(&ima_sig_len);  //(size 0x0200)

    // Finalize Signature
    let mut signature: Vec<u8> = vec![EVM_IMA_XATTR_DIGSIG];    //0x03
    signature.extend_from_slice(&ima_sign_header); //  +8 byte IMA header
    signature.extend_from_slice(&ima_sig);         //+512 byte signature
    //Total = 521 bytes = OK

    // Set extended attribute, security.ima, fallback to user.ima
    // Try to set the extended attribute and return any error
    if let Err(e) = set_ima_xattr::set_ima_xattr_str_vec(&file, &signature) {
        Err(e) // Collect xattr error
    } else {
        // Print final xattr
        println!("Wrote sig ({:?}bytes): {}", signature.len(), format_hex(&signature));
        Ok(()) // No error
    }
}

fn sign_bytes(pkey: &PKey<openssl::pkey::Private>, md: MessageDigest, data: &[u8]) -> io::Result<Vec<u8>> {
//    let pkey = keyutils::load_private_key(Path::new(key_path)).expect("unexpected Error, Cannot load private key");
    let mut signer = Signer::new(md, &pkey)?;
    signer.update(data)?;
//    Ok(signer.sign_to_vec()?)   //ErrorStack
    Ok(signer.sign_to_vec().expect("unexpected Error, Signer output of signature failed"))
}
fn verify_signature(pkey: &PKey<openssl::pkey::Private>, md: MessageDigest, filedata: &[u8], xattr: &str) -> io::Result<bool> {
//    let pkey = keyutils::load_private_key(Path::new(key_path)).expect("unexpected Error, Cannot load private key");
    // Read signature from extended attribute
    let signature = hex::decode(xattr)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Hex decode error in signature"))?;
//    println!("Vsignature: {:?}", signature);//DebugPrint

    // Hash the file data
    let mut verifier = Verifier::new(md, &pkey)
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to init verifier"))?;
    verifier.update(filedata)
        .map_err(|_| Error::new(ErrorKind::Other, "Failed to hash data"))?;

    // Verify signature (skip +9 IMA header) //TODO: properly, check hashalgo, KeyID, length 
    verifier.verify(&signature[9..])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Signature verification failed"))
}

fn run_sign_ima(pkey: &PKey<openssl::pkey::Private>, targetfile: &str, hash_algo: HashAlgorithm, keyid: &[u8]) -> io::Result<()> {
    match sign_ima(pkey, targetfile, hash_algo, &keyid) {
        Ok(_) => { println!("SIGNATURE(OK): \"{}\"",targetfile); return Ok(()); }
        Err(e) => { eprintln!("imafix2: Error signing IMA: {:?} - {:?}", e.kind(), e.to_string()); return Err(e); }
    }
}

#[test]
//Verify_sig_hash_pub
fn test_a() -> io::Result<()> {
    use std::io::Write;
    use std::fs::File;
    use std::path::Path;
    //AutoGenerate RSA Public/Private Test Key in harness (depends on key existing)
    //generate_rsa_keypair(); (Crate can't be found during test mode over here)

    // Create a new empty test file for writing
    let test_filename = "testA.txt";
    let mut file = File::create(test_filename)?;
    // Write the ASCII character "A" to the test file
    file.write_all(&['A' as u8])?;
    // Followed by a Line Feed (0x0a)
    file.write_all(b"\n")?;
    // Explicitly flush the file to ensure all data is written to disk
    file.flush()?;
    
    // Extract keyID from private key (once per program) - Option 1
    let pkey = keyutils::load_private_key(Path::new(TEST_PRIVATE_KEY_PATH)).expect("unexpected Error, Cannot load test private key");
    let keyid = keyutils::calc_keyid_v2(&pkey.rsa()?).expect("unexpected Error, Cannot Calculate KeyID from privkey").to_vec();
    // Extract keyID from PUBLIC Cert (once per program) - Option 2
//    let keyid = extract_keyid_from_x509_pem(TEST_PUBLIC_CERT_PATH)?;
//    let keyid = vec!{0;4}; //blank define it - Option 3
//    let keyid: Vec<u8> = vec![0xAB, 0x6F, 0x20, 0x50]; //hardcoded - Option 4
    // IMA Sign the file, expect a Valid 3af28 Signature out.
    //TODO: Verify (or force)
    let _ = run_sign_ima(&pkey, test_filename, HashAlgorithm::from_str(DEFAULT_HASH_ALGO).expect("unexpected Error, Invalid hash algorithm"), &keyid);
    //not ready to pass itself as return since it errors out on repeated user.ima writes to the same file.
    Ok(())
}

//TODO: Remove my key.
#[cfg(not(test))]
fn main() -> Result<(), Error> {
    use rayon::prelude::*;  //parallel processing
    // Call pathwalk to get the files , handle the result
    let files: Result<Vec<PathBuf>, Error> = pathwalk::pathwalk();
    // Extract keyID from pub certificate. (once per program) // Method 2
    //let keyid = keyid::extract_keyid_from_x509_pem(PUBLIC_CERT_PATH)?;
    let pkey = keyutils::load_private_key(Path::new(PRIVATE_KEY_PATH)).expect("unexpected Error, Cannot load private key");
    let keyid = keyutils::calc_keyid_v2(&pkey.rsa()?).expect("unexpected Error, Cannot calculate keyid from private key"); // Method 1

    // Match result process files
    match files {
        Ok(files) => {
            // Iterate over each file and call function
            //for file in files {
            // PARALLEL PROCESSING WITH RAYON:
            files.par_iter().for_each(|file| {
                let filename = file.to_str().expect("unexpected Error, in filename to str");
                println!(/*"Filename: */"{:?}", filename);
                let _ = run_sign_ima(
                    &pkey,
                    filename,
                    HashAlgorithm::from_str(DEFAULT_HASH_ALGO).expect("unexpected Error, Invalid hash algorithm"),
                    &keyid);
            });
            Ok(()) // Return Ok(()) when everything is processed successfully
        },
        Err(e) => {
            // Handle error in case pathwalk fails
            eprintln!("BUG! imafix2(): Total Error during pathwalk: {}", e);
            Err(e) // Return the error to propagate it
        }
    }
}

/* //XATTR-USER (less PERMISSIONS)
#[allow(dead_code)] //TODO: use function later
fn xattr_user() -> Result<()> { 
    // user.ima - Search if xattr existing already and bail out to save time.
    let xattr_name = "user.ima"; // The xattr name you're searching for
    match find_xattr::llistxattr(file, xattr_name) {
        Ok(Some(_xattr)) => { 
            //println!("Skip existing Xattr {}: {:?}", xattr_name, xattr); //(full data)
            //println!("Skip existing Xattr: {}", xattr_name);  //TODO: DebugPrint
            return Err(Error::new(ErrorKind::AlreadyExists, "user.ima xattr Already Exists, Skipped!"));
        },
        Ok(None) => {}, //println!("xattr {} not found", xattr_name), //FIXME: Excessive printout
        Err(err) => eprintln!("Error reading xattrs: {}", err),
    }
}
*/
/*
#[allow(dead_code)] //TODO: use function later
fn calc_ima_hash(file: &str, hash_algo: &HashAlgorithm) -> io::Result<Vec<u8>> {
    let hash_type = hash_algo.ima_xattr_type();
    //Calc hash
    let calc_hash = hash_file::hash_file(file)?; //hardcoded Sha512. //TODO: hash_type
    if calc_hash.len() < MAX_DIGEST_SIZE.into() {
        println!{"Hash len is smaller than expected MAX_DIGEST_SIZE {}", MAX_DIGEST_SIZE};
    }
    // Print hash
    println!("Hash({:?}): {}", hash_algo, format_hex(&calc_hash));

// Start IMA_Hash Header
    let mut ima_hash_header: Vec<u8> = vec![];
    //hash_v2 (0406) vs hash_v1 (01)
    if hash_type > 1 {
        ima_hash_header.push(IMA_XATTR_DIGEST_NG);
        ima_hash_header.push(hash_type);
    } else {
        ima_hash_header.push(IMA_XATTR_DIGEST);
    }
    let _offset = if hash_type > 1 { 2 } else { 1 };

    // Finalize IMA_Hash header and Calc_Hash
    ima_hash_header.extend_from_slice(&calc_hash);
    Ok(calc_hash)
}
//^Turns out none of this is needed for this sign function itself
//^but we need hashing later for the previous algo and also verifying. (TODO)
*/
