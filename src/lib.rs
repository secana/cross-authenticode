//! Cross platform library for verifying Authenticode signed files.
//!
//! This library can be used to verify the Authenticode signature of a PE file on both Windows and
//! Linux.
//!
//! # Example
//! ```rust
//! use cross_authenticode::{AuthenticodeInfo, ToHex, Algorithm};
//! use std::fs::File;
//! use std::path::PathBuf;
//!
//! let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
//! let pe_file = std::fs::read(pe_path).unwrap();
//!
//! let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();
//!
//! // Check thumbprints of the first two certificates
//! assert_eq!(ai.certificates[0].sha1.to_hex(), "f55115d2439ce0a7529ffaaea654be2c71dce955");
//! assert_eq!(ai.certificates[1].sha1.to_hex(), "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d");
//!
//! // Check the Authenticode algorithm
//! assert_eq!(ai.digest.algorithm, Algorithm::Sha256);
//!
//! // Verify the the Authenticode signature
//! assert!(ai.verify().unwrap());
//!
//! // Verify the Authenticode signature manually
//! assert_eq!(ai.authenticode_sha256().unwrap(), ai.digest.hash);
//! ```

mod algorithm;
mod authenticode_certificate;
mod authenticode_info;
mod error;
mod hex_ex;
mod pe_file;
mod spc_indirect_data;
mod win_certificate;

pub use algorithm::Algorithm;
pub use authenticode_info::{AuthenticodeInfo, DigestInfo};
pub use hex_ex::ToHex;
