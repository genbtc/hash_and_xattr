// Lib.rs -v0.31
// This exposes each file to the rest of the project
pub mod format_hex;
#[allow(non_snake_case)]
pub mod IMAhashAlgorithm;
pub mod hash_file;
pub mod set_ima_xattr;
pub mod pathwalk;
pub mod find_xattr;
pub mod keyid;
pub mod keyutils;
// #Usage:
//use hash_and_xattr::IMAhashAlgorithm::HashAlgorithm;                                                                                                                                                                                                                            
//use hash_and_xattr::format_hex::format_hex;
//use hash_and_xattr::hash_file::hash_file;
//use hash_and_xattr::set_ima_xattr::set_ima_xattr;
//use hash_and_xattr::pathwalk::pathwalk;
//use hash_and_xattr::find_xattr::find_xattr;
//use hash_and_xattr::keyid::keyid;
//use hash_and_xattr::keyutils::keyutils;
