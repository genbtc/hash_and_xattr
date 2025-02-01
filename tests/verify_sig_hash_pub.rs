#[cfg(test)]
mod tests {
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use openssl::error::ErrorStack;

//format matches sha512sum (hex output)
fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join("")
}

fn verify_signature(message: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
    println!("signature: {}", format_hex(&signature));

    // Load the public key (PEM format) - from existing key derived from derive_pubkey_from_privkey
    let rsa = Rsa::public_key_from_pem(include_bytes!("/home/genr8eofl/derived_public_key.pem"))?; //compile time
    let pkey = PKey::from_rsa(rsa)?;

    // Create the verifier
    let mut verifier = Verifier::new(MessageDigest::sha512(), &pkey)?;
    // Provide message to verifier
    verifier.update(message)?;
    // Verify the signature
    let is_valid = verifier.verify(&signature)?;

    Ok(is_valid)
}

#[test]
fn verify_sig_hash_pub() {
    // Example message (the original data) and the known good sig  we are expecting
    let message = b"A\x0a";
    let sig_hex = "3af28d0bd4298b6ee60257360c8f00ee19ea605a37b7f86de8667af4550d5b94166bea96c6d5b592741645b9a318687774706eaf5edddc05102c6683a2a959ebd4c56e7243a5d18d63948ccc75414ea633c33a7125dbd2ca75fe529d987a83081b859cd83eb443458bafbe88b2ca54e6f27ebf62c72609fe9da9994f51e8a83d8411eb5e74d60e2e6ff10ca6218f25eaafba21809bc93c378d5103ef660ad0ed7f24433e15a4c3831c33f60661ea249d6c03ab671c457872de9e88ddce487e9fadbed7660129e1f221a780acb3084b8075ba51b6096ca0a66c3a201b21ec38318944620200705f4273164311291520a5c10dff368451fb48956697bcdda801a3765a0ac2b9f535e9b1a3ae365e3ad20d6972e441e594576d36ec9fb1ed0d373304c6cefc3c5ec3c66900605a6128add1840094aa9d3415aa35db9f401daf69a6ad3729aefc4304297274b170c3a88656c86886dc691b53e51d35b7f7725b208d18cb51a391b1972ba12967ed9b6d6cc6c356a776f77b59dd3f94aeec67d709367d7344e557bb34e7524602494d47715e58895b340eb15abe49d22cb5beb315a1cacc350f1750fa0f8478abbdbc685a18acacb925a1572c0616e3ee8775480fb0bc5eeee7f397c4d70be5268929e59f6f1e68b5c66881e49f1b6d62cf4e2623859a82c65f3fecd18505d056ccec00bc463c08ec031bcb6fdcb03f960652088bb5";
    let sig_vec = hex::decode(sig_hex).expect("Invalid hex signature");

    // Verify the MESSAGE
    println!("message: {}", format_hex(message));
    match verify_signature(message, &sig_vec) {
        Ok(true) => println!("OK, Message Signature valid!"),
        Ok(false) => println!("Message Signature is INVALID!!!"),
        Err(e) => eprintln!("Error verifying Message signature: {}", e),
    }
    
    //Example hash
    let message_hex = "7A296FAB5364B34CE3E0476D55BF291BD41AA085E5ECF2A96883E593AA1836FED22F7242AF48D54AF18F55C8D1DEF13EC9314C926666A0BA63F7663500090565";
    let message_vec = hex::decode(message_hex).expect("Invalid hex message");
    let signature_hex = "020B68AAC9662249DFC99338B1D9A2E16C1D4E50BD37596230B8279CB6E27D6E4F0F209D48F21839FB36CE0FF4761B4C197226BDEB3D89C2947D72A299F8A9278F62DB5C548C23139C727292E577904B572D265E3A2050B4AEF1D23F027C69EDD19759914D44565FEBA687436A637EC3CEA796560898682C7F976ED94030DBB29100132C3C4D59AB42EEAB5C031F7B008E7BC062511A27BCA4D77D3C9B9E144CAE1EB4ED5F68530E93F3E623D0D9E45D8A9A2AF9C0F1D2C5EAFF8080504451B57B747BE28D295079DFB5A8FB8391C57E0A62673518856F828B5F838C8081913C9C5EC5FC755DD677503CBF94BB2655C1562A6282C5D4268D5028FFF5457BA7983B0E723F74EC045F22E77292E15350252B9E178393A528E411C3A8C5315DE5B93D975B0F562DC66637F0278BF5AE6AAD79EA34594A5EE32FF599F903BB757C656AB22F2FD93EFE5FB58CBDC9A6DD3E3E81659D9F9DB25C33EA505946990DB1212ADECB12778861AC1A681C20C15D727D9E1B3ECED8DC11D6598B37F53A9E94C22306274D0EF3A296B1670CDC5988A1045C1009A83E03A139FBF6CD6438D6CD497AF0E27302FA01C320023200569ACEC4398553DBB642DCD288ACBB40AE2C66F5C8E81458EE9A83CDE08C3F3739DED3601D6C7DE3F21E33B3E73B808E676B7E3832F613FD6AEF7F14005AD7F38D092CB0CAACD0602A242947360A00514EA8DD20";
    let signature_vec = hex::decode(signature_hex).expect("Invalid hex signature");

    // Verify the Signature
    println!("message: {}", format_hex(&message_vec));     
    match verify_signature(&message_vec, &signature_vec) {
        Ok(true) => println!("OK, Hash Signature valid!"),
        Ok(false) => println!("Hash Signature is INVALID!!!"),
        Err(e) => eprintln!("Error verifying hash signature: {}", e),
    }
//    let signature_hex = "12d50734a95ee4d961d572d237bcd0fecf2099f8baa507f6586ab12e618442a6017dec56807ab8f8966f5178ff237160cbce37a11af37e31b4f297ed1f6073f12b3dd358c51882e29f1f30d7efc32bc7e2cac86ba6b48e8137481493b25b3d6d7deedd4fdc0a83731167a4e1398b3149e0be131775aed49d21daa944db38bdf45b742ef88c32f4c3296ada9db42080fad0d5696795d901df20764a49ae667bddd374074f5411a39128d8a4837a459cf491585751beb1cdacbd1ec1c5e9871f7801428e284fbe6e070ef9050a17ed277c13624338453dc3e9c1975dccaadd3bb837fa0e093478a6c0a0cd8591da10a2af25750a6a7a0f246a533ce91ace76298d2e43097d048d2227a3f0ebf985f2ccc1b6af30921703841fd946b1315721b7cb2079baa9a4782867674ec0c86c48fc1346bd4e7e1094b30c51f2224a94a35a3fbe9ca08cff94b017d3a85845203bc17743d4a67e390d466ac65f54af0507d07075332f3aa278f9d8e75f9233d18baf7c43b5cb52bfe0059eb61fd87ec52d9794f7b9784facbd0eec0eb9eca82a1d9fb35e7bb93e0e7de218b942344d75271fd0e5f3ba3defe812580777223f2fe65b443272c8e29fd75e4b6d877e059e9a8ba45228dbfedda79b12cd6a409602197d4da881bbeb446863336639ee3d4d61f5d39cb14763313970dc9dbfb51c908cedf8588a4d9eecf4ebe62f420838e4b68881";
}
}
