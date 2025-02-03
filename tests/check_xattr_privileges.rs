use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use xattr;

fn check_xattr_privileges(file_path: &PathBuf, namespace: &str) -> bool {
    let xattr_name = format!("{}.test", namespace);
    let data = b"test_value";

    match xattr::set(file_path, &xattr_name, data) {
        Ok(_) => {
            println!("✔ Successfully set {} namespace attribute.", namespace);
            true
        }
        Err(err) => {
            println!("✘ Failed to set {} namespace attribute: {}", namespace, err);
            false
        }
    }
}

pub fn print_xattr_privileges() -> io::Result<()> {
    // Create the file in the current directory
    let file_name = "xattr_test_file";
    let file_path = PathBuf::from(file_name);

    let mut file = File::create(&file_path)?;
    writeln!(file, "Temporary file for xattr testing")?;

    println!("Testing xattr privileges on: {:?}", file_path);

    let has_user_priv = check_xattr_privileges(&file_path, "user");
    let has_security_priv = check_xattr_privileges(&file_path, "security");
    let has_trusted_priv = check_xattr_privileges(&file_path, "trusted");

    println!("\nPrivilege Summary:");
    println!("User namespace:     {}", if has_user_priv { "✅ Yes" } else { "❌ No" });
    println!("Security namespace: {}", if has_security_priv { "✅ Yes" } else { "❌ No" });
    println!("Trusted namespace:  {}", if has_trusted_priv { "✅ Yes" } else { "❌ No" });

    Ok(())
}

#[test]
fn output() -> io::Result<()> {
    print_xattr_privileges()
}
