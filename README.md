# hash and xattr, v0.3.5
# IMA Signs files, compatible with IMA.
Open a directory, scan for a list of files, hash them with SHA512, 

Load a private key to sign the signature and save it alongside the file,

to the linux filesystem xattrs, as security.ima - or as fallback - user.ima.

Also supports taking list of files by -f files.txt, or piped to stdin, or dir ./

## New IMA Rust Program - Feb 2025

## Project Dir Structure:
src/
```
main.rs		-	main() IMA sign files (like imafix2)
lib.rs		-	Lib.Rs Crate Module declarations (these files)
pathwalk.rs	-	Directory Traversal, STDIN support, input -f Filelist.txt of files
find_xattr.rs	-	llistxattr wrapper to list/get xattrs
set_ima_xattr.rs -	logic to set IMA xattr security.ima/user.ima
IMAhashAlgorithm.rs -   equivalent of imaevm.h from ima-evm-utils, struct defs
keyid.rs	-	Extract Subject Key ID from X509 Cert (for IMA header)
keyutils.rs	-	Calculate Subject Key ID from RSA Private Key (same as above but diff)
hash_file.rs	-	SHA-512 hash wrapper function
format_hex.rs	-	tiny Utility function to convert u8 bytes to ascii hex string
```
## Tests (dev):
tests/
```
generate_rsa_keypair.rs	-   Generate random public/private RSA keypair
verify_sig_hash_pub.rs	-   Verify known sig based on known key known text
check_xattr_privileges.rs - check permissions user or security,trusted
keyid.rs                -   Extract KeyID
keyid-simple.rs         -   Calculate KeyID
```
## Rust Dependencies:
Cargo.toml
```
[dependencies]
xattr = "*"      # interacting with extended attributes
openssl = "*"    # private/public crypto key signing
hex = "*"        # for hex decode/encode
atty = "*"       # Add atty to check if stdin is connected (pathwalk)
walkdir = "*"    # Directory traversal
rayon = "*"      # parallel processing iter
yasna = "*'      # ASN.1 Encoding
```
