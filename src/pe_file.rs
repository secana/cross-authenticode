use crate::{
    error::{AuthenticodeError, OptionExt},
    win_certificate::WinCertificate,
};
use object::{
    LittleEndian, SectionIndex,
    pe::{IMAGE_DIRECTORY_ENTRY_SECURITY, ImageDataDirectory},
    pod,
    read::pe::{ImageNtHeaders, ImageOptionalHeader},
};
use std::{mem, ops::Range};

pub(crate) trait PeFile {
    fn data(&self) -> &[u8];

    fn offsets(&self) -> Result<AuthenicodeInput, AuthenticodeError>;

    fn offset(&self, bytes: &[u8]) -> Result<usize, AuthenticodeError>;

    fn win_certificate(&self) -> Result<WinCertificate<'_>, AuthenticodeError>;

    fn section_data_range(&self, index: usize) -> Result<Range<usize>, AuthenticodeError>;
}

impl<I> PeFile for object::read::pe::PeFile<'_, I>
where
    I: ImageNtHeaders,
{
    fn data(&self) -> &[u8] {
        self.data()
    }

    fn offsets(&self) -> Result<AuthenicodeInput, AuthenticodeError> {
        // Offset of the checksum field in the optional header.
        let oh = self.nt_headers().optional_header();
        let oh_bytes = pod::bytes_of(oh);
        let oh_offset = self.offset(oh_bytes)?;
        let checksum = oh_offset
            .checked_add(0x40)
            .ok_or(AuthenticodeError::ParsePe(
                "Failed to compute offset of checksum".to_string(),
            ))?;
        let after_checksum =
            checksum
                .checked_add(mem::size_of::<u32>())
                .ok_or(AuthenticodeError::ParsePe(
                    "Failed to compute offset after checksum".to_string(),
                ))?;

        // Offset of the security data directory.
        let data_dirs_offset =
            oh_offset
                .checked_add(oh_bytes.len())
                .ok_or(AuthenticodeError::ParsePe(
                    "Failed to compute offset of data directories".to_string(),
                ))?;
        let security_dir = data_dirs_offset
            .checked_add(
                mem::size_of::<ImageDataDirectory>()
                    .checked_mul(IMAGE_DIRECTORY_ENTRY_SECURITY)
                    .ok_or(AuthenticodeError::ParsePe(
                        "Failed to compute offset of security directory".to_string(),
                    ))?,
            )
            .ok_or(AuthenticodeError::ParsePe(
                "Failed to compute offset of security directory".to_string(),
            ))?;
        let sec_dir_size = mem::size_of::<ImageDataDirectory>();
        let after_security_dir =
            security_dir
                .checked_add(sec_dir_size)
                .ok_or(AuthenticodeError::ParsePe(
                    "Failed to compute offset after security directory".to_string(),
                ))?;

        // Offset of the data directory after the security directory.
        let after_header: usize = (self.nt_headers().optional_header().size_of_headers())
            .try_into()
            .map_err(|_| {
                AuthenticodeError::ParsePe("Failed to compute offset of after header".to_string())
            })?;

        let num_sections = self.section_table().len();

        let certificate_table_range =
            if let Some(dir) = self.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY) {
                let start = dir.virtual_address.get(LittleEndian) as usize;
                let size = dir.size.get(LittleEndian) as usize;
                let end = start.checked_add(size).err_pe_oor()?;
                Some(start..end)
            } else {
                None
            };

        Ok(AuthenicodeInput {
            checksum,
            after_checksum,
            security_dir,
            after_security_dir,
            after_header,
            num_sections,
            certificate_table_range,
        })
    }

    fn offset(&self, bytes: &[u8]) -> Result<usize, AuthenticodeError> {
        let base = self.data().as_ptr() as usize;
        let start = bytes.as_ptr() as usize;

        start.checked_sub(base).ok_or(AuthenticodeError::ParsePe(
            "Failed to compute offset from PE file".to_string(),
        ))
    }

    fn win_certificate(&self) -> Result<WinCertificate<'_>, AuthenticodeError> {
        let security_dir = self
            .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
            .ok_or(AuthenticodeError::NoWinCertificate)?;

        WinCertificate::new(self.data(), security_dir.virtual_address.get(LittleEndian))
    }

    fn section_data_range(&self, index: usize) -> Result<Range<usize>, AuthenticodeError> {
        let section = self.section_table().section(SectionIndex(index))?;
        let start = section.pointer_to_raw_data.get(LittleEndian) as usize;
        let size = section.size_of_raw_data.get(LittleEndian) as usize;
        let end = start.checked_add(size).err_pe_oor()?;
        Ok(start..end)
    }
}

pub struct AuthenicodeInput {
    pub checksum: usize,
    pub after_checksum: usize,
    pub security_dir: usize,
    pub after_security_dir: usize,
    pub after_header: usize,
    pub num_sections: usize,
    pub certificate_table_range: Option<Range<usize>>,
}
