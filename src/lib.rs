//! Cross platform library for verifying Authenticode signed files.
//!
//! This library can be used to verify the Authenticode signature of a PE file on both Windows and
//! Linux.
//!
//! # Example
//! ```rust
//! use cross_authenticode::AuthenticodeInfo;
//! use std::fs::File;
//! use std::path::PathBuf;
//!
//! let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
//! let pe_file = std::fs::read(pe_path).unwrap();
//!
//! let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();
//!
//! // Check thumbprints of the first two certificates
//! assert_eq!(ai.certificates[0].sha1, "f55115d2439ce0a7529ffaaea654be2c71dce955");
//! assert_eq!(ai.certificates[1].sha1, "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d");
//! ```

mod authenticode_certificate;
mod authenticode_info;
mod error;
mod win_certificate;

pub use authenticode_info::AuthenticodeInfo;
