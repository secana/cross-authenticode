/// Extension trait to convert byte slices and byte vectors to hex strings.
pub trait ToHex {
    /// Converts the byte slice or vector to a hex string in lowercase.
    fn to_hex(&self) -> String;
    /// Converts the byte slice or vector to a hex string in lowercase.
    fn to_lower_hex(&self) -> String;
    /// Converts the byte slice or vector to a hex string in uppercase.
    fn to_upper_hex(&self) -> String;
}

impl ToHex for &[u8] {
    fn to_hex(&self) -> String {
        self.to_lower_hex()
    }
    fn to_lower_hex(&self) -> String {
        use std::fmt::Write;
        self.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02x}");
            output
        })
    }
    fn to_upper_hex(&self) -> String {
        use std::fmt::Write;
        self.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02X}");
            output
        })
    }
}

impl ToHex for Vec<u8> {
    fn to_hex(&self) -> String {
        self.to_lower_hex()
    }

    fn to_lower_hex(&self) -> String {
        self.as_slice().to_lower_hex()
    }

    fn to_upper_hex(&self) -> String {
        self.as_slice().to_upper_hex()
    }
}
