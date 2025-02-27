#![allow(dead_code)]
use crate::error::AuthenticodeError;

#[derive(Debug)]
pub(crate) struct WinCertificate<'a> {
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
    pub certificate: &'a [u8],
}

impl<'a> WinCertificate<'a> {
    pub fn new(data: &'a [u8], offset: u32) -> Result<Self, AuthenticodeError> {
        let offset = offset as usize;
        let length = u32::from_le_bytes(data[offset..offset + 4].try_into()?);
        let revision = u16::from_le_bytes(data[offset + 4..offset + 6].try_into()?);
        let certificate_type = u16::from_le_bytes(data[offset + 6..offset + 8].try_into()?);
        let certificate = &data[offset + 8..(offset + length as usize)];

        Ok(Self {
            length,
            revision,
            certificate_type,
            certificate,
        })
    }
}
