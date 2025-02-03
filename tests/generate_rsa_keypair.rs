use openssl::rsa::Rsa;
use std::fs::File;
use std::io::Write;
use std::error::Error;

pub fn generate_rsa_keys() -> Result<(),Box<dyn Error>> {
    // Generate an RSA keypair (4096 bits)
    let rsa = Rsa::generate(4096)?;

    // Private key
    let private_key_pem = rsa.private_key_to_pem()?;
    let mut private_key_file = File::create("./test_private_key.pem")?;
    private_key_file.write_all(&private_key_pem)?;

    // Public key
    let public_key_pem = rsa.public_key_to_pem()?;
    let mut public_key_file = File::create("./test_public_key.pem")?;
    public_key_file.write_all(&public_key_pem)?;

    println!("RSA keypair generated and saved as PEM files: test_public_key.pem, test_private_key.pem");
    Ok(())
}

#[test]
fn main()  {
    generate_rsa_keys().expect("error generating RSA Keys!")
}
