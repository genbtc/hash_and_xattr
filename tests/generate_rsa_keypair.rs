use openssl::rsa::Rsa;
use std::fs::File;
use std::io::Write;
use std::error::Error;

#[test]
pub fn generate_rsa_keypair() -> Result<(),Box<dyn Error>> {
    // Generate an RSA keypair (4096 bits)
    let rsa = Rsa::generate(4096)?;

    // Private key
    let private_key_pem = rsa.private_key_to_pem()?;
    let priv_file = "test_private_key.pem";
    let mut private_key_file = File::create(priv_file)?;
    private_key_file.write_all(&private_key_pem)?;

    // Public key
    let public_key_pem = rsa.public_key_to_pem()?;
    let pub_file = "test_public_key.pem";
    let mut public_key_file = File::create(pub_file)?;
    public_key_file.write_all(&public_key_pem)?;

    println!("RSA keypair generated and saved as PEM files: {}, {}", pub_file, priv_file);
    Ok(())
}

/*
fn main()  {
    generate_rsa_keypair().expect("error generating RSA Keys!")
}
*/
