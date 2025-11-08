use std::fmt;

pub const WINERROR_FILE_NOT_FOUND: u32 = 2;
pub const WINERROR_NO_SUCH_LOGON_SESSION: u32 = 1312;

#[derive(Debug)]
pub enum WinError {
    String(String),
    WinApiError(WinApiError)
}

impl From<WinApiError> for WinError {
    fn from(e: WinApiError) -> Self {
        return Self::WinApiError(e);
    }
}

impl From<String> for WinError {
    fn from(e: String) -> Self {
        return Self::String(e);
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::String(s) => s.fmt(f),
            Self::WinApiError(wae) => wae.fmt(f)
        }
    }
}

#[derive(Debug)]
pub struct WinApiError {
    pub error: u32,
    pub source: String,
}

impl fmt::Display for WinApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Windows error in {} : {} (0x{:x})",
            self.source, self.error, self.error
        )
    }
}
