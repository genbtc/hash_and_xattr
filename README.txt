Content-Type: text/x-zim-wiki
Wiki-Format: zim 0.6
Creation-Date: 2025-02-02T17:34:24-05:00

# hash_and_xattr v0.2
open a directory, scan for a list of files, hash them with SHA512, write a private key signed signature 
to the linux filesystem xattrs as security.ima or fallback as user.ima.

## New Rust Program - Feb 2025

## Dir Structure;
'''
src/
main.rs		-	main() IMA sign files (like imafix2)
find_xattr.rs	-	llistxattr wrapper to list/get xattrs
pathwalk.rs	-	Directory Traversal, STDIN support, input -f Filelist.txt of files
set_ima_xattr.rs - 	shared logic for setting security.ima/user.ima xattr
IMAhashAlgorithm.rs - equivalent of imaevm.h from ima-evm-utils, struct defs
lib.rs		-	Lib.Rs Crate Module declarations (these files)
keyid.rs		-	Extract Subject Key ID from X509 Cert (for IMA header)
hash_file.rs	-	SHA-512 hash function
format_hex.rs	-	Utility function to convert u8 bytes to ascii hex string
'''

## Dependencies:
'''
[dependencies]
xattr = "*"      # interacting with extended attributes
openssl = "*"  # private/public crypto key signing
hex = "*"        # for hex decode/encode
atty = "*"        # Add atty to check if stdin is connected (pathwalk)
rayon = "*"      # parallel processing iter
walkdir = "*"    # Directory traversal
'''
