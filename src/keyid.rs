use openssl::x509::X509;                                                                                                                              
use std::fs::File;                                                                                                                                    
use std::io::Read;                                                                                                                                    

fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":")
}
                                                                                                                                                      
pub fn extract_keyid_from_x509_pem() {                                                                                                                                           
    // Load the private key from the file                                                                                                             
    let mut file = File::open("/home/genr8eofl/signing_key.priv").expect("Failed to open private key file");                                          
    let mut private_key_contents = String::new();                                                                                                     
    file.read_to_string(&mut private_key_contents).expect("Failed to read private key file");                                                         
                                                                                                                                                      
    // Load the certificate from the private key file to extract the public key                                                                       
    let cert = X509::from_pem(private_key_contents.as_bytes()).expect("Failed to parse X509 certificate");                                            
                                                                                                                                                      
    // Extract the Subject Key Identifier (SKI)                                                                                                       
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
