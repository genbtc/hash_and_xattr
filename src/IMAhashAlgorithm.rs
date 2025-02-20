//IMAhashAlgorithm.rs - v0.2
//Derived from implementation of enum pkey_hash_algo at https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L167-L175
use openssl::nid::Nid;
//public constants
//Default used to be sha256 @ https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L71
pub const DEFAULT_HASH_ALGO: &'static str = "sha512";
//Derived from https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L77-L78
pub const MAX_DIGEST_SIZE: u8 = 64; // Adjust based on the maximum hash size (SHA-512)
pub const MAX_SIGNATURE_SIZE: u16 = 512; // Adjust based on the maximum signature size (RSA-4096)
//Derived from enum evm_ima_xattr_type @  https://github.com/linux-integrity/ima-evm-utils/blob/next/src/imaevm.h#L92-L99
//enum evm_ima_xattr_type {
pub const IMA_XATTR_DIGEST: u8 = 0x01;
pub const EVM_IMA_XATTR_DIGSIG: u8 = 0x03;
pub const IMA_XATTR_DIGEST_NG: u8 = 0x04;
// };
pub const DIGSIG_VERSION_2: u8 = 0x02; // (from enum digsig_version @ #L144)

#[derive(Debug)]
struct HashAlgorithmData {
    name: &'static str,
    nid: Nid,
    ima_xattr_type: u8,
}

#[derive(Debug)]
pub enum HashAlgorithm {
    Sha1,
    Md4,
    Md5,
    Ripemd160,
    Sha256,
    Sha384,
    Sha512,
    Sha224,
}

impl HashAlgorithm {
    fn data(&self) -> HashAlgorithmData {
        match self {
            HashAlgorithm::Sha1 => HashAlgorithmData {
                name: "sha1",
                nid: Nid::SHA1,
                ima_xattr_type: 0x00,
            },
            HashAlgorithm::Md4 => HashAlgorithmData {
                name: "md4",
                nid: Nid::MD4,
                ima_xattr_type: 0x01,
            },
            HashAlgorithm::Md5 => HashAlgorithmData {
                name: "md5",
                nid: Nid::MD5,
                ima_xattr_type: 0x02,
            },
            HashAlgorithm::Ripemd160 => HashAlgorithmData {
                name: "ripemd160",
                nid: Nid::RIPEMD160,
                ima_xattr_type: 0x03,
            },
            HashAlgorithm::Sha256 => HashAlgorithmData {
                name: "sha256",
                nid: Nid::SHA256,
                ima_xattr_type: 0x04,
            },
            HashAlgorithm::Sha384 => HashAlgorithmData {
                name: "sha384",
                nid: Nid::SHA384,
                ima_xattr_type: 0x05,
            },
            HashAlgorithm::Sha512 => HashAlgorithmData {
                name: "sha512",
                nid: Nid::SHA512,
                ima_xattr_type: 0x06,
            },
            HashAlgorithm::Sha224 => HashAlgorithmData {
                name: "sha224",
                nid: Nid::SHA224,
                ima_xattr_type: 0x07,
            },
        }
    }
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        self.data().name
    }

    pub fn nid(&self) -> Nid {
        self.data().nid
    }

    pub fn ima_xattr_type(&self) -> u8 {
        self.data().ima_xattr_type
    }

    pub fn from_str(algo: &str) -> Option<Self> {
        match algo.to_lowercase().as_str() {
            "sha1" => Some(HashAlgorithm::Sha1),
            "md4" => Some(HashAlgorithm::Md4),
            "md5" => Some(HashAlgorithm::Md5),
            "ripemd160" => Some(HashAlgorithm::Ripemd160),
            "sha256" => Some(HashAlgorithm::Sha256),
            "sha384" => Some(HashAlgorithm::Sha384),
            "sha512" => Some(HashAlgorithm::Sha512),
            "sha224" => Some(HashAlgorithm::Sha224),
            _ => None,
        }
    }
}
