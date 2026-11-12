use std::error::Error;
#[cfg(windows)]
use std::mem::size_of;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA};
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, REG_DWORD, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
};
#[cfg(windows)]
pub use windows::Win32::System::Registry::{KEY_QUERY_VALUE, KEY_SET_VALUE};

use crate::error::PersonalizeError;

pub const PERSONALIZE_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
pub const DWM_SUBKEY: &str = r"Software\Microsoft\Windows\DWM";
pub const DESKTOP_SUBKEY: &str = r"Control Panel\Desktop";

pub const APPS_USE_LIGHT_THEME: &str = "AppsUseLightTheme";
pub const SYSTEM_USES_LIGHT_THEME: &str = "SystemUsesLightTheme";
pub const ACCENT_COLOR_VALUE: &str = "AccentColor";
pub const COLOR_PREVALENCE_VALUE: &str = "ColorPrevalence";
pub const WALLPAPER_VALUE: &str = "Wallpaper";

/// Minimal SAM access flags for user-space registry reads/writes when targeting non-Windows hosts.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegSamFlags(pub u32);

#[cfg(not(windows))]
pub const KEY_QUERY_VALUE: RegSamFlags = RegSamFlags(0x0001);
#[cfg(not(windows))]
pub const KEY_SET_VALUE: RegSamFlags = RegSamFlags(0x0002);

#[cfg(windows)]
pub type SamFlags = REG_SAM_FLAGS;
#[cfg(not(windows))]
pub type SamFlags = RegSamFlags;

/// Windows 11 theme polarity (`0` = Dark, `1` = Light).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    Dark,
    Light,
}

impl ThemeMode {
    #[inline]
    pub const fn as_dword(self) -> u32 {
        match self {
            Self::Dark => 0,
            Self::Light => 1,
        }
    }

    #[inline]
    pub const fn from_dword(val: u32) -> Self {
        if val == 0 {
            Self::Dark
        } else {
            Self::Light
        }
    }
}

/// Encodes a Rust UTF-8 string into a NUL-terminated UTF-16 buffer suitable for `PCWSTR`.
/// Rejects embedded NUL characters to prevent silent string truncation across the Win32 FFI boundary.
pub(crate) fn encode_wide_nul(input: &str) -> Result<Vec<u16>, PersonalizeError> {
    if input.contains('\0') {
        return Err(PersonalizeError::InvalidInput(
            "string contains an interior NUL character".to_owned(),
        ));
    }
    Ok(input.encode_utf16().chain(std::iter::once(0)).collect())
}

/// RAII wrapper around an opened `HKEY` strictly rooted under `HKEY_CURRENT_USER`.
///
/// Guarantees deterministic handle cleanup via `RegCloseKey` on drop and never exposes
/// access to `HKEY_LOCAL_MACHINE` or elevated registry hives.
pub struct HkcuKey {
    #[cfg(windows)]
    handle: HKEY,
    #[cfg(windows)]
    subkey: String,
    #[cfg(not(windows))]
    _private: (),
}

impl HkcuKey {
    /// Opens an existing subkey strictly under `HKEY_CURRENT_USER` with minimal `sam_desired` rights.
    #[cfg(windows)]
    pub fn open(subkey: &str, sam_desired: SamFlags) -> Result<Self, Box<dyn Error>> {
        if subkey.is_empty() {
            return Err(Box::new(PersonalizeError::InvalidInput(
                "registry subkey path must not be empty".to_owned(),
            )));
        }

        let wide_subkey = encode_wide_nul(subkey)?;
        let mut handle = HKEY::default();

        // SAFETY:
        // - `HKEY_CURRENT_USER` is a predefined pseudo-handle valid for the lifetime of the process.
        // - `wide_subkey` is NUL-terminated and outlives the `RegOpenKeyExW` call.
        // - `handle` is a valid stack-allocated out-pointer initialized to `HKEY::default()`.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(wide_subkey.as_ptr()),
                0,
                sam_desired,
                std::ptr::from_mut(&mut handle),
            )
        };

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegOpenKeyExW",
            subkey: subkey.to_owned(),
            value_name: None,
            source,
        })?;

        Ok(Self {
            handle,
            subkey: subkey.to_owned(),
        })
    }

    #[cfg(not(windows))]
    pub fn open(subkey: &str, _sam_desired: SamFlags) -> Result<Self, Box<dyn Error>> {
        if subkey.is_empty() {
            return Err(Box::new(PersonalizeError::InvalidInput(
                "registry subkey path must not be empty".to_owned(),
            )));
        }
        let _ = encode_wide_nul(subkey)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegOpenKeyExW",
        )))
    }

    /// Writes a 32-bit `REG_DWORD` value under this `HKEY_CURRENT_USER` key via `RegSetValueExW`.
    #[cfg(windows)]
    pub fn set_dword(&self, value_name: &str, data: u32) -> Result<(), Box<dyn Error>> {
        let wide_name = encode_wide_nul(value_name)?;
        let bytes = data.to_le_bytes();

        // SAFETY:
        // - `self.handle` is a valid open `HKEY` with `KEY_SET_VALUE` access.
        // - `wide_name` is a valid NUL-terminated UTF-16 buffer outliving the call.
        // - `bytes` is a 4-byte stack array matching `REG_DWORD` little-endian layout.
        let status = unsafe {
            RegSetValueExW(
                self.handle,
                PCWSTR(wide_name.as_ptr()),
                0,
                REG_DWORD,
                Some(bytes.as_slice()),
            )
        };

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegSetValueExW",
            subkey: self.subkey.clone(),
            value_name: Some(value_name.to_owned()),
            source,
        })?;

        Ok(())
    }

    #[cfg(not(windows))]
    pub fn set_dword(&self, value_name: &str, _data: u32) -> Result<(), Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegSetValueExW",
        )))
    }

    /// Writes a NUL-terminated `REG_SZ` string value under this `HKEY_CURRENT_USER` key via `RegSetValueExW`.
    #[cfg(windows)]
    pub fn set_string(&self, value_name: &str, data: &str) -> Result<(), Box<dyn Error>> {
        let wide_name = encode_wide_nul(value_name)?;
        let wide_data = encode_wide_nul(data)?;
        let byte_len = wide_data
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| PersonalizeError::InvalidInput("string payload too large".to_owned()))?;
        let _cb_data = u32::try_from(byte_len).map_err(|_| {
            PersonalizeError::InvalidInput("string payload exceeds u32 byte limit".to_owned())
        })?;

        // SAFETY:
        // - `wide_data` is contiguous `u16` memory; reinterpreting as `u8` of length `wide_data.len() * 2`
        //   is sound because `u8` has alignment 1 and `u16` has no padding bytes.
        // - `byte_len` fits within `u32::MAX` (verified above).
        // - Both `wide_name` and `wide_data` outlive `RegSetValueExW`.
        let byte_slice =
            unsafe { std::slice::from_raw_parts(wide_data.as_ptr().cast::<u8>(), byte_len) };

        let status = unsafe {
            RegSetValueExW(
                self.handle,
                PCWSTR(wide_name.as_ptr()),
                0,
                REG_SZ,
                Some(byte_slice),
            )
        };

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegSetValueExW",
            subkey: self.subkey.clone(),
            value_name: Some(value_name.to_owned()),
            source,
        })?;

        Ok(())
    }

    #[cfg(not(windows))]
    pub fn set_string(&self, value_name: &str, data: &str) -> Result<(), Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        let _ = encode_wide_nul(data)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegSetValueExW",
        )))
    }

    /// Deletes a value under this `HKEY_CURRENT_USER` key via `RegDeleteValueW`, succeeding
    /// as a no-op if the value is already absent (`ERROR_FILE_NOT_FOUND`).
    #[cfg(windows)]
    pub fn delete_value_if_exists(&self, value_name: &str) -> Result<(), Box<dyn Error>> {
        let wide_name = encode_wide_nul(value_name)?;

        // SAFETY:
        // - `self.handle` is a valid open `HKEY` with `KEY_SET_VALUE` access.
        // - `wide_name` is a NUL-terminated UTF-16 buffer outliving `RegDeleteValueW`.
        let status = unsafe { RegDeleteValueW(self.handle, PCWSTR(wide_name.as_ptr())) };

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegDeleteValueW",
            subkey: self.subkey.clone(),
            value_name: Some(value_name.to_owned()),
            source,
        })?;

        Ok(())
    }

    #[cfg(not(windows))]
    pub fn delete_value_if_exists(&self, value_name: &str) -> Result<(), Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegDeleteValueW",
        )))
    }

    /// Queries an optional 32-bit `REG_DWORD` value via `RegQueryValueExW`, returning `Ok(None)`
    /// if the value has not been initialized yet (`ERROR_FILE_NOT_FOUND`).
    #[cfg(windows)]
    pub fn query_dword_optional(&self, value_name: &str) -> Result<Option<u32>, Box<dyn Error>> {
        let wide_name = encode_wide_nul(value_name)?;
        let mut buf = [0u8; size_of::<u32>()];
        let mut cb_data = buf.len() as u32;
        let mut value_type = REG_VALUE_TYPE::default();

        // SAFETY:
        // - `self.handle` is a valid open `HKEY` with `KEY_QUERY_VALUE` access.
        // - `wide_name` is NUL-terminated and outlives the call.
        // - `buf` provides `cb_data` (4) writable bytes, matching `cb_data` passed in/out.
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(std::ptr::from_mut(&mut value_type)),
                Some(buf.as_mut_ptr()),
                Some(std::ptr::from_mut(&mut cb_data)),
            )
        };

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegQueryValueExW",
            subkey: self.subkey.clone(),
            value_name: Some(value_name.to_owned()),
            source,
        })?;

        if value_type != REG_DWORD {
            return Err(Box::new(PersonalizeError::UnexpectedRegistryType {
                subkey: self.subkey.clone(),
                value_name: value_name.to_owned(),
                expected: "REG_DWORD",
                actual: value_type.0,
            }));
        }

        if cb_data as usize != size_of::<u32>() {
            return Err(Box::new(PersonalizeError::UnexpectedRegistrySize {
                subkey: self.subkey.clone(),
                value_name: value_name.to_owned(),
                expected: size_of::<u32>(),
                actual: cb_data as usize,
            }));
        }

        Ok(Some(u32::from_le_bytes(buf)))
    }

    #[cfg(not(windows))]
    pub fn query_dword_optional(&self, value_name: &str) -> Result<Option<u32>, Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegQueryValueExW",
        )))
    }

    /// Queries a required 32-bit `REG_DWORD` value from this `HKEY_CURRENT_USER` key via `RegQueryValueExW`.
    #[cfg(windows)]
    pub fn query_dword(&self, value_name: &str) -> Result<u32, Box<dyn Error>> {
        self.query_dword_optional(value_name)?.ok_or_else(|| {
            Box::new(PersonalizeError::Registry {
                operation: "RegQueryValueExW",
                subkey: self.subkey.clone(),
                value_name: Some(value_name.to_owned()),
                source: windows::core::Error::from(ERROR_FILE_NOT_FOUND),
            }) as Box<dyn Error>
        })
    }

    #[cfg(not(windows))]
    pub fn query_dword(&self, value_name: &str) -> Result<u32, Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegQueryValueExW",
        )))
    }

    /// Queries an optional `REG_SZ` or `REG_EXPAND_SZ` string value via two-pass `RegQueryValueExW`,
    /// returning `Ok(None)` if the value does not exist (`ERROR_FILE_NOT_FOUND`).
    #[cfg(windows)]
    pub fn query_string_optional(
        &self,
        value_name: &str,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let wide_name = encode_wide_nul(value_name)?;
        let mut cb_data: u32 = 0;
        let mut value_type = REG_VALUE_TYPE::default();

        // Pass 1: Determine required buffer size in bytes.
        // SAFETY: Passing `None` for `lpdata` instructs `RegQueryValueExW` to only populate `cb_data`.
        let status = unsafe {
            RegQueryValueExW(
                self.handle,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(std::ptr::from_mut(&mut value_type)),
                None,
                Some(std::ptr::from_mut(&mut cb_data)),
            )
        };

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }

        status.ok().map_err(|source| PersonalizeError::Registry {
            operation: "RegQueryValueExW(size)",
            subkey: self.subkey.clone(),
            value_name: Some(value_name.to_owned()),
            source,
        })?;

        if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
            return Err(Box::new(PersonalizeError::UnexpectedRegistryType {
                subkey: self.subkey.clone(),
                value_name: value_name.to_owned(),
                expected: "REG_SZ | REG_EXPAND_SZ",
                actual: value_type.0,
            }));
        }

        if cb_data == 0 {
            return Ok(Some(String::new()));
        }

        // Retry loop guards against concurrent value growth between size query and data read.
        for _ in 0..3 {
            let u16_len = (cb_data as usize).div_ceil(size_of::<u16>());
            let mut wide_buf = vec![0u16; u16_len];
            let mut alloc_bytes = (u16_len * size_of::<u16>()) as u32;

            // SAFETY:
            // - `wide_buf` has capacity and initialized length for `alloc_bytes` bytes with 2-byte alignment.
            // - `RegQueryValueExW` writes at most `alloc_bytes` bytes into `wide_buf`.
            let read_status = unsafe {
                RegQueryValueExW(
                    self.handle,
                    PCWSTR(wide_name.as_ptr()),
                    None,
                    Some(std::ptr::from_mut(&mut value_type)),
                    Some(wide_buf.as_mut_ptr().cast::<u8>()),
                    Some(std::ptr::from_mut(&mut alloc_bytes)),
                )
            };

            if read_status == ERROR_MORE_DATA {
                cb_data = alloc_bytes;
                continue;
            }

            read_status
                .ok()
                .map_err(|source| PersonalizeError::Registry {
                    operation: "RegQueryValueExW(data)",
                    subkey: self.subkey.clone(),
                    value_name: Some(value_name.to_owned()),
                    source,
                })?;

            let actual_u16 = (alloc_bytes as usize) / size_of::<u16>();
            wide_buf.truncate(actual_u16);
            while wide_buf.last() == Some(&0) {
                wide_buf.pop();
            }

            let decoded = String::from_utf16(&wide_buf).map_err(|e| -> Box<dyn Error> {
                Box::new(PersonalizeError::InvalidInput(format!(
                    "invalid UTF-16 data in HKCU\\{} [{}]: {e}",
                    self.subkey, value_name
                )))
            })?;
            return Ok(Some(decoded));
        }

        Err(Box::new(PersonalizeError::InvalidInput(format!(
            "concurrent modification prevented reading HKCU\\{} [{}]",
            self.subkey, value_name
        ))))
    }

    #[cfg(not(windows))]
    pub fn query_string_optional(
        &self,
        value_name: &str,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegQueryValueExW",
        )))
    }

    /// Queries a required `REG_SZ` or `REG_EXPAND_SZ` string value via `RegQueryValueExW`.
    #[cfg(windows)]
    pub fn query_string(&self, value_name: &str) -> Result<String, Box<dyn Error>> {
        self.query_string_optional(value_name)?.ok_or_else(|| {
            Box::new(PersonalizeError::Registry {
                operation: "RegQueryValueExW",
                subkey: self.subkey.clone(),
                value_name: Some(value_name.to_owned()),
                source: windows::core::Error::from(ERROR_FILE_NOT_FOUND),
            }) as Box<dyn Error>
        })
    }

    #[cfg(not(windows))]
    pub fn query_string(&self, value_name: &str) -> Result<String, Box<dyn Error>> {
        let _ = encode_wide_nul(value_name)?;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "RegQueryValueExW",
        )))
    }
}

#[cfg(windows)]
impl Drop for HkcuKey {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `self.handle` was obtained from a successful `RegOpenKeyExW` call
            // and is exclusively owned by `Self`, so it is closed exactly once.
            unsafe {
                let _ = RegCloseKey(self.handle);
            }
        }
    }
}

/// Sets `AppsUseLightTheme` and `SystemUsesLightTheme` (`0` = Dark, `1` = Light)
/// under `HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`.
pub fn set_theme_mode(mode: ThemeMode) -> Result<(), Box<dyn Error>> {
    let key = HkcuKey::open(PERSONALIZE_SUBKEY, KEY_SET_VALUE)?;
    let flag = mode.as_dword();
    key.set_dword(APPS_USE_LIGHT_THEME, flag)?;
    key.set_dword(SYSTEM_USES_LIGHT_THEME, flag)?;
    Ok(())
}

/// Queries `(AppsUseLightTheme, SystemUsesLightTheme)` from `HKCU\...\Themes\Personalize`.
pub fn get_theme_mode() -> Result<(ThemeMode, ThemeMode), Box<dyn Error>> {
    let key = HkcuKey::open(PERSONALIZE_SUBKEY, KEY_QUERY_VALUE)?;
    let apps = ThemeMode::from_dword(key.query_dword(APPS_USE_LIGHT_THEME)?);
    let system = ThemeMode::from_dword(key.query_dword(SYSTEM_USES_LIGHT_THEME)?);
    Ok((apps, system))
}

/// Sets `AccentColor` (`DWORD` in `AABBGGRR` format) and `ColorPrevalence` (`DWORD` `0` or `1`)
/// under `HKCU\Software\Microsoft\Windows\DWM`.
pub fn set_accent_color(accent_abgr: u32, color_prevalence: bool) -> Result<(), Box<dyn Error>> {
    let key = HkcuKey::open(DWM_SUBKEY, KEY_SET_VALUE)?;
    let prevalence_dword = u32::from(color_prevalence);
    key.set_dword(ACCENT_COLOR_VALUE, accent_abgr)?;
    key.set_dword(COLOR_PREVALENCE_VALUE, prevalence_dword)?;
    Ok(())
}

/// Sets only `ColorPrevalence` (`0` or `1`) under `HKCU\Software\Microsoft\Windows\DWM`.
pub fn set_color_prevalence(color_prevalence: bool) -> Result<(), Box<dyn Error>> {
    let key = HkcuKey::open(DWM_SUBKEY, KEY_SET_VALUE)?;
    key.set_dword(COLOR_PREVALENCE_VALUE, u32::from(color_prevalence))
}

/// Queries `(AccentColor [AABBGGRR], ColorPrevalence)` from `HKCU\Software\Microsoft\Windows\DWM`.
pub fn get_accent_color() -> Result<(u32, bool), Box<dyn Error>> {
    let key = HkcuKey::open(DWM_SUBKEY, KEY_QUERY_VALUE)?;
    let abgr = key.query_dword_optional(ACCENT_COLOR_VALUE)?.unwrap_or(0);
    let prevalence = key
        .query_dword_optional(COLOR_PREVALENCE_VALUE)?
        .unwrap_or(0)
        != 0;
    Ok((abgr, prevalence))
}

/// Queries the current desktop wallpaper path from `HKCU\Control Panel\Desktop\Wallpaper`.
pub fn get_wallpaper_path() -> Result<String, Box<dyn Error>> {
    let key = HkcuKey::open(DESKTOP_SUBKEY, KEY_QUERY_VALUE)?;
    Ok(key
        .query_string_optional(WALLPAPER_VALUE)?
        .unwrap_or_default())
}

/// Converts standard RGBA components into Windows DWM `AABBGGRR` DWORD layout.
#[inline]
pub const fn rgba_to_abgr(r: u8, g: u8, b: u8, a: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((g as u32) << 8) | (r as u32)
}

/// Formats a Windows DWM `AABBGGRR` DWORD into `#RRGGBB` web hex notation.
#[inline]
pub fn abgr_to_rgb_hex(abgr: u32) -> String {
    let r = (abgr & 0xFF) as u8;
    let g = ((abgr >> 8) & 0xFF) as u8;
    let b = ((abgr >> 16) & 0xFF) as u8;
    format!("#{r:02X}{g:02X}{b:02X}")
}

/// Parses a user-supplied color specification into DWM `AABBGGRR` DWORD format:
/// - `#RRGGBB` or `RRGGBB` (6 hex chars): standard RGB converted to opaque `0xFFBBGGRR`.
/// - `0xAABBGGRR` (8 hex chars prefixed with `0x`/`0X`): raw DWM `AABBGGRR` DWORD.
pub fn parse_accent_color(input: &str) -> Result<u32, Box<dyn Error>> {
    let trimmed = input.trim();

    if let Some(raw_abgr) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if raw_abgr.len() != 8 {
            return Err(Box::new(PersonalizeError::InvalidInput(format!(
                "raw AABBGGRR literal '{trimmed}' must contain exactly 8 hex digits (e.g., 0xFFD47800)"
            ))));
        }
        let val = u32::from_str_radix(raw_abgr, 16).map_err(|_| {
            PersonalizeError::InvalidInput(format!(
                "invalid hex digits in raw AABBGGRR literal '{trimmed}'"
            ))
        })?;
        return Ok(val);
    }

    let hex_rgb = trimmed.strip_prefix('#').unwrap_or(trimmed);
    if hex_rgb.len() != 6 {
        return Err(Box::new(PersonalizeError::InvalidInput(format!(
            "color '{trimmed}' must be '#RRGGBB' (6 hex digits) or '0xAABBGGRR' (8 hex digits)"
        ))));
    }

    let rgb = u32::from_str_radix(hex_rgb, 16).map_err(|_| {
        PersonalizeError::InvalidInput(format!("invalid hex color literal '{trimmed}'"))
    })?;

    let r = ((rgb >> 16) & 0xFF) as u8;
    let g = ((rgb >> 8) & 0xFF) as u8;
    let b = (rgb & 0xFF) as u8;

    Ok(rgba_to_abgr(r, g, b, 0xFF))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_windows_blue_rgb_to_dwm_abgr() {
        // Windows Blue #0078D4 -> R=0x00, G=0x78, B=0xD4, A=0xFF -> 0xFFD47800
        let abgr = parse_accent_color("#0078D4").expect("valid RGB hex");
        assert_eq!(abgr, 0xFF_D4_78_00);
        assert_eq!(abgr_to_rgb_hex(abgr), "#0078D4");
    }

    #[test]
    fn parses_raw_aabbggrr_dword() {
        let abgr = parse_accent_color("0x80D47800").expect("valid raw AABBGGRR");
        assert_eq!(abgr, 0x80_D4_78_00);
    }

    #[test]
    fn rejects_interior_nul_strings() {
        assert!(encode_wide_nul("ValidName").is_ok());
        assert!(encode_wide_nul("Bad\0Name").is_err());
    }

    #[test]
    fn theme_mode_dword_mapping() {
        assert_eq!(ThemeMode::Dark.as_dword(), 0);
        assert_eq!(ThemeMode::Light.as_dword(), 1);
        assert_eq!(ThemeMode::from_dword(0), ThemeMode::Dark);
        assert_eq!(ThemeMode::from_dword(1), ThemeMode::Light);
    }
}
