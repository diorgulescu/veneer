use std::error::Error;
use std::fmt;

/// Standard boxed error result alias used across all modules.
pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[cfg(windows)]
pub type PlatformError = windows::core::Error;

#[cfg(not(windows))]
pub type PlatformError = std::io::Error;

/// Domain error type for user-space Windows 11 personalization operations.
#[derive(Debug)]
pub enum PersonalizeError {
    InvalidInput(String),
    UnsupportedPlatform(&'static str),
    Io {
        context: String,
        source: std::io::Error,
    },
    Registry {
        operation: &'static str,
        subkey: String,
        value_name: Option<String>,
        source: PlatformError,
    },
    UnexpectedRegistryType {
        subkey: String,
        value_name: String,
        expected: &'static str,
        actual: u32,
    },
    UnexpectedRegistrySize {
        subkey: String,
        value_name: String,
        expected: usize,
        actual: usize,
    },
    Win32 {
        operation: &'static str,
        detail: String,
        source: Option<PlatformError>,
    },
}

impl fmt::Display for PersonalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::UnsupportedPlatform(op) => {
                write!(f, "operation '{op}' requires a Windows 11 target")
            }
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Registry {
                operation,
                subkey,
                value_name: Some(val),
                source,
            } => write!(
                f,
                "registry {operation} failed on HKCU\\{subkey} [{val}]: {source}"
            ),
            Self::Registry {
                operation,
                subkey,
                value_name: None,
                source,
            } => write!(f, "registry {operation} failed on HKCU\\{subkey}: {source}"),
            Self::UnexpectedRegistryType {
                subkey,
                value_name,
                expected,
                actual,
            } => write!(
                f,
                "unexpected registry value type at HKCU\\{subkey} [{value_name}]: expected {expected}, got type id {actual}"
            ),
            Self::UnexpectedRegistrySize {
                subkey,
                value_name,
                expected,
                actual,
            } => write!(
                f,
                "unexpected registry value size at HKCU\\{subkey} [{value_name}]: expected {expected} bytes, got {actual} bytes"
            ),
            Self::Win32 {
                operation,
                detail,
                source: Some(src),
            } => write!(f, "win32 operation '{operation}' failed ({detail}): {src}"),
            Self::Win32 {
                operation,
                detail,
                source: None,
            } => write!(f, "win32 operation '{operation}' failed: {detail}"),
        }
    }
}

impl Error for PersonalizeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Registry { source, .. } => Some(source),
            Self::Win32 {
                source: Some(src), ..
            } => Some(src),
            _ => None,
        }
    }
}
