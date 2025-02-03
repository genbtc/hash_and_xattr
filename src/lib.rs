// Lib.rs -v0.2
// This exposes format_hex to the rest of the project
pub mod format_hex;
// This exposes IMAhashAlgorithm to the rest of the project
#[allow(non_snake_case)]
pub mod IMAhashAlgorithm;
// This exposes hash_file to the rest of the project
pub mod hash_file;
// This exposes set_ima_xattr to the rest of the project
pub mod set_ima_xattr;
// This exposes pathwalk to the rest of the project
pub mod pathwalk;
// This exposes find_xattr to the rest of the project
pub mod find_xattr;
// This exposes keyid to the rest of the project
pub mod keyid;
//hash_file
//#Usage:
//use hash_and_xattr::IMAhashAlgorithm::HashAlgorithm;                                                                                                                                                                                                                            
//use hash_and_xattr::format_hex::format_hex;
//use hash_and_xattr::hash_file::hash_file;
//use hash_and_xattr::set_ima_xattr::set_ima_xattr;
//use hash_and_xattr::pathwalk::pathwalk;
//use hash_and_xattr::find_xattr::find_xattr;
