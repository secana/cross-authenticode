use crate::algorithm::Algorithm;
use crate::error::OptionExt;
use crate::pe_file::PeFile;
use crate::spc_indirect_data::{SPC_INDIRECT_DATA_OBJID, SpcIndirectDataContent};
use crate::win_certificate::WinCertificate;
use crate::{authenticode_certificate::AuthenticodeCertificate, error::AuthenticodeError};
use cms::cert::x509::spki::ObjectIdentifier;
use cms::{
    cert::{
        CertificateChoices,
        x509::der::{Decode, SliceReader},
    },
    content_info::ContentInfo,
    signed_data::SignedData,
};
use object::read::pe::{PeFile32, PeFile64};
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// Information about the digest of the PE file.
/// The information includes the algorithm used and the hash,
/// which are taken from the PE file itself.
///
#[derive(Debug)]
pub struct DigestInfo {
    /// The algorithm used for the Authenticode hash.
    pub algorithm: Algorithm,
    /// The hash of the Authenticode signature.
    ///
    /// ATTENTION: The hash can be wrong and has to be verified by comparing it to the computed hash
    /// of the Authenticode signature.
    pub hash: Vec<u8>,
}

/// Contains information about the Authenticode signature of a PE file.
pub struct AuthenticodeInfo<'a> {
    /// List of certificates with additional information found in the PE file.
    pub certificates: Vec<AuthenticodeCertificate>,
    /// Information about the digest of the Authenticode signature file.
    pub digest: DigestInfo,

    pe: Box<dyn PeFile + 'a>,
}

impl AuthenticodeInfo<'_> {
    fn create(data: &[u8]) -> Result<AuthenticodeInfo, AuthenticodeError> {
        let pe: Box<dyn PeFile> = match PeFile64::parse(data) {
            Ok(pe) => Box::new(pe),
            Err(_) => Box::new(PeFile32::parse(data)?),
        };
        let content_info = Self::content_info(&pe.win_certificate()?)?;
        let signed_data = Self::signed_data(&content_info)?;
        let authenticode_certificates = Self::certificates(&signed_data)?;
        let digest_info = Self::digest_info(&content_info, &signed_data)?;

        Ok(AuthenticodeInfo {
            certificates: authenticode_certificates,
            digest: digest_info,
            pe,
        })
    }

    /// Verifies the Authenticode signature by comparing the hash of the PE file with the hash
    /// found in the Authenticode signature.
    ///
    /// Supports SHA1 and SHA256 algorithms, for all other algorithms, use the `authenticode_hash`
    /// function to compute the hash and compare it manually with the `DigestInfo.hash`.
    pub fn verify(&self) -> Result<bool, AuthenticodeError> {
        match &self.digest.algorithm {
            Algorithm::Sha1 => Ok(self.authenticode_sha1()? == self.digest.hash),
            Algorithm::Sha256 => Ok(self.authenticode_sha256()? == self.digest.hash),
            alg => Err(AuthenticodeError::InvalidHashAlgorithmWithName(
                alg.to_string(),
            )),
        }
    }

    /// Returns the SHA1 hash of the Authenticode signature computed from the PE file.
    pub fn authenticode_sha1(&self) -> Result<Vec<u8>, AuthenticodeError> {
        self.authenticode_hash::<Sha1>()
    }

    /// Returns the SHA256 hash of the Authenticode signature computed from the PE file.
    pub fn authenticode_sha256(&self) -> Result<Vec<u8>, AuthenticodeError> {
        self.authenticode_hash::<Sha256>()
    }

    /// Returns the hash of the Authenticode signature computed from the PE file.
    ///
    /// This function is generic and can be used with any hashing algorithm that implements the
    /// `Digest` trait.
    ///
    /// # Example
    /// ```rust
    /// use sha2::Sha512;
    /// use cross_authenticode::AuthenticodeInfo;
    /// use std::fs::File;
    /// use std::path::PathBuf;
    ///
    /// let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
    /// let pe_file = std::fs::read(pe_path).unwrap();
    ///
    /// let authenticode_info = AuthenticodeInfo::try_from(&pe_file).unwrap();
    /// let hash = authenticode_info.authenticode_hash::<Sha512>().unwrap();
    /// ```
    pub fn authenticode_hash<D: Digest>(&self) -> Result<Vec<u8>, AuthenticodeError> {
        let mut digest = D::new();
        let offsets = self.pe.offsets()?;

        // Hash from beginning to checksum.
        let bytes = self.pe.data().get(..offsets.checksum).err_slice()?;
        digest.update(bytes);

        // Hash from checksum to the security data directory.
        let bytes = self
            .pe
            .data()
            .get(offsets.after_checksum..offsets.security_dir)
            .err_slice()?;
        digest.update(bytes);

        // Hash from the security data directory to the end of the header.
        let bytes = self
            .pe
            .data()
            .get(offsets.after_security_dir..offsets.after_header)
            .err_slice()?;
        digest.update(bytes);

        // Track offset as sections are hashed. This is used to hash data
        // after the sections.
        let mut sum_of_bytes_hashed = offsets.after_header;

        // First sort the sections.
        let mut sections = (1..=offsets.num_sections)
            .map(|i| self.pe.section_data_range(i))
            .collect::<Result<Vec<_>, AuthenticodeError>>()?;
        sections.sort_unstable_by_key(|r| r.start);

        // Then hash each section's data.
        for section_range in sections {
            let bytes = self.pe.data().get(section_range).err_slice()?;

            digest.update(bytes);
            sum_of_bytes_hashed = sum_of_bytes_hashed.checked_add(bytes.len()).err_pe_oor()?;
        }

        let mut extra_hash_len = self
            .pe
            .data()
            .len()
            .checked_sub(sum_of_bytes_hashed)
            .err_pe_oor()?;

        // The certificate table is not included in the hash.
        if let Some(security_data_dir) = offsets.certificate_table_range {
            let size = security_data_dir
                .end
                .checked_sub(security_data_dir.start)
                .err_pe_oor()?;
            extra_hash_len = extra_hash_len.checked_sub(size).err_pe_oor()?;
        }

        digest.update(
            self.pe
                .data()
                .get(
                    sum_of_bytes_hashed
                        ..sum_of_bytes_hashed
                            .checked_add(extra_hash_len)
                            .err_pe_oor()?,
                )
                .err_slice()?,
        );

        Ok(digest.finalize().to_vec())
    }

    fn digest_info(
        content_info: &ContentInfo,
        signed_data: &SignedData,
    ) -> Result<DigestInfo, AuthenticodeError> {
        if content_info.content_type != ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2") {
            return Err(AuthenticodeError::InvalidContentType(
                content_info.content_type.to_string(),
            ));
        }

        if signed_data.encap_content_info.econtent_type != SPC_INDIRECT_DATA_OBJID {
            return Err(AuthenticodeError::InvalidEncapsulatedContentType(
                signed_data.encap_content_info.econtent_type.to_string(),
            ));
        }

        let indirect_data = signed_data
            .clone()
            .encap_content_info
            .econtent
            .ok_or(AuthenticodeError::NoEncapsulatedContent)?
            .decode_as::<SpcIndirectDataContent>()?;

        let hash = indirect_data.message_digest.digest.as_bytes();

        Ok(DigestInfo {
            algorithm: Algorithm::try_from(hash)?,
            hash: hash.to_vec(),
        })
    }

    fn signed_data(content_info: &ContentInfo) -> Result<SignedData, AuthenticodeError> {
        let signed_data = content_info.content.decode_as::<SignedData>()?;
        Ok(signed_data)
    }

    fn content_info(win_certificate: &WinCertificate) -> Result<ContentInfo, AuthenticodeError> {
        let mut reader = SliceReader::new(win_certificate.certificate)?;
        let content_info = ContentInfo::decode(&mut reader)?;
        Ok(content_info)
    }

    fn certificates(
        signed_data: &SignedData,
    ) -> Result<Vec<AuthenticodeCertificate>, AuthenticodeError> {
        let authenticode_certificates = signed_data
            .certificates
            .as_ref()
            .ok_or(AuthenticodeError::NoCertificates)?
            .0
            .iter()
            .filter_map(|cert| match cert {
                CertificateChoices::Certificate(cert) => Some(cert),
                _ => None,
            })
            .map(|cert| AuthenticodeCertificate::try_from(cert.to_owned()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(authenticode_certificates)
    }
}

/// Tries to create an `AuthenticodeInfo` struct from a slice of bytes.
impl<'a> TryFrom<&'a [u8]> for AuthenticodeInfo<'a> {
    type Error = AuthenticodeError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        Self::create(data)
    }
}

/// Tries to create an `AuthenticodeInfo` struct from a vector of bytes.
impl<'a> TryFrom<&'a Vec<u8>> for AuthenticodeInfo<'a> {
    type Error = AuthenticodeError;

    fn try_from(data: &'a Vec<u8>) -> Result<Self, Self::Error> {
        Self::create(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ToHex;
    use std::path::PathBuf;

    #[test]
    fn sha1_thumbprints_signed_64() {
        let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha1.to_hex(),
            "f55115d2439ce0a7529ffaaea654be2c71dce955"
        );
        assert_eq!(
            ai.certificates[1].sha1.to_hex(),
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d"
        );
        assert_eq!(ai.digest.algorithm, Algorithm::Sha256);
        assert!(ai.verify().unwrap());
    }

    #[test]
    fn sha256_thumbprints_signed_64() {
        let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha256.to_hex(),
            "9267a08c9fc07b6ab194dc4df3121b264e825330a39ffc42cdb0942f5115eb97"
        );
        assert_eq!(
            ai.certificates[1].sha256.to_hex(),
            "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
        );
        assert_eq!(ai.digest.algorithm, Algorithm::Sha256);
        assert!(ai.verify().unwrap());
    }

    #[test]
    fn sha1_thumbprints_signed_32() {
        let pe_path = PathBuf::from("test-pe/test-signed-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha1.to_hex(),
            "aeb9b61e47d91c42fff213992b7810a3d562fb12"
        );
        assert_eq!(
            ai.certificates[1].sha1.to_hex(),
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d"
        );
        assert_eq!(ai.digest.algorithm, Algorithm::Sha256);
        assert!(ai.verify().unwrap());
    }

    #[test]
    fn sha256_thumbprints_signed_32() {
        let pe_path = PathBuf::from("test-pe/test-signed-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha256.to_hex(),
            "bb91b9f1a11556a6556a804d0b5c984c3d1281a04dc918ab7b0a90d8b0747fde"
        );
        assert_eq!(
            ai.certificates[1].sha256.to_hex(),
            "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
        );
        assert_eq!(ai.digest.algorithm, Algorithm::Sha256);
        assert!(ai.verify().unwrap());
    }

    #[test]
    fn no_cert_unsigned_32() {
        let pe_path = PathBuf::from("test-pe/test-unsigned-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(error, AuthenticodeError::NoWinCertificate);
    }

    #[test]
    fn no_cert_unsigned_64() {
        let pe_path = PathBuf::from("test-pe/test-unsigned-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(error, AuthenticodeError::NoWinCertificate);
    }

    #[test]
    fn not_a_pe_file() {
        let pe_path = PathBuf::from("test-pe/test-no-pe.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(
            error,
            AuthenticodeError::ParsePe("Invalid DOS header size or alignment".to_string())
        );
    }
}
