use crate::{error::AuthenticodeError, win_certificate::WinCertificate};
use object::{
    LittleEndian,
    pe::IMAGE_DIRECTORY_ENTRY_SECURITY,
    pod,
    read::pe::{ImageNtHeaders, PeFile, PeFile32, PeFile64},
};

trait CommonPeFile {
    fn data(&self) -> &[u8];
    fn data_dir(&self, dir: usize) -> Option<&object::pe::ImageDataDirectory>;

    fn checksum_offset(&self) -> Result<usize, AuthenticodeError>;

    fn offset(&self, bytes: &[u8]) -> Result<usize, AuthenticodeError>;
}

impl<'a, I> CommonPeFile for PeFile<'a, I>
where
    I: ImageNtHeaders,
{
    fn data(&self) -> &[u8] {
        self.data()
    }

    fn data_dir(&self, dir: usize) -> Option<&object::pe::ImageDataDirectory> {
        self.data_directory(dir)
    }

    fn checksum_offset(&self) -> Result<usize, AuthenticodeError> {
        let oh = self.nt_headers().optional_header();
        let oh_bytes = pod::bytes_of(oh);
        let oh_offset = self.offset(&oh_bytes)?;
        let check_sum_offset = oh_offset
            .checked_add(0x40)
            .ok_or(AuthenticodeError::ParsePe(
                "Failed to compute offset of checksum".to_string(),
            ))?;
        Ok(check_sum_offset)
    }

    fn offset(&self, bytes: &[u8]) -> Result<usize, AuthenticodeError> {
        let base = self.data().as_ptr() as usize;
        let start = bytes.as_ptr() as usize;

        start.checked_sub(base).ok_or(AuthenticodeError::ParsePe(
            "Failed to compute offset from PE file".to_string(),
        ))
    }
}

pub(crate) struct PeInfo<'a> {
    pub win_certificate: WinCertificate<'a>,
    pub checksum_offset: usize,
}

impl<'a> PeInfo<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, AuthenticodeError> {
        let pe: Box<dyn CommonPeFile> = match PeFile64::parse(data) {
            Ok(pe) => Box::new(pe),
            Err(_) => Box::new(PeFile32::parse(data)?),
        };

        let security_dir = pe
            .data_dir(IMAGE_DIRECTORY_ENTRY_SECURITY)
            .ok_or(AuthenticodeError::NoWinCertificate)?;

        let win_certificate =
            WinCertificate::new(data, security_dir.virtual_address.get(LittleEndian))?;

        let checksum_offset = pe.checksum_offset()?;

        Ok(PeInfo {
            win_certificate,
            checksum_offset,
        })
    }
}
