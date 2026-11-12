use std::error::Error;
#[cfg(windows)]
use std::ffi::c_void;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use windows::core::{w, PCWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{
    GetLastError, SetLastError, ERROR_SUCCESS, ERROR_TIMEOUT, LPARAM, WPARAM,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    SendMessageTimeoutW, SystemParametersInfoW, HWND_BROADCAST, SMTO_ABORTIFHUNG, SPIF_SENDCHANGE,
    SPIF_UPDATEINIFILE, SPI_SETDESKWALLPAPER, WM_SETTINGCHANGE,
};

use crate::error::PersonalizeError;

#[cfg(windows)]
const BROADCAST_TIMEOUT_MS: u32 = 150;

/// Broadcasts a single `WM_SETTINGCHANGE` topic to all top-level windows via `SendMessageTimeoutW`.
#[cfg(windows)]
fn broadcast_setting_change(
    topic: PCWSTR,
    topic_label: &'static str,
) -> Result<(), Box<dyn Error>> {
    let mut msg_result: usize = 0;

    // SAFETY:
    // - `SetLastError(ERROR_SUCCESS)` clears thread-local error state prior to FFI dispatch.
    // - `HWND_BROADCAST` is a documented Win32 pseudo-handle for top-level broadcast.
    // - `topic` points to a `'static` NUL-terminated UTF-16 string literal (`w!(...)`),
    //   so the `lParam` pointer remains valid for the entire synchronous broadcast.
    // - `msg_result` is a valid stack `usize` out-parameter.
    let lresult = unsafe {
        SetLastError(ERROR_SUCCESS);
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(topic.0 as isize),
            SMTO_ABORTIFHUNG,
            BROADCAST_TIMEOUT_MS,
            Some(std::ptr::from_mut(&mut msg_result)),
        )
    };

    if lresult.0 == 0 {
        // SAFETY: Reads thread-local Win32 error set by `SendMessageTimeoutW`.
        let win32_err = unsafe { GetLastError() };
        // On `HWND_BROADCAST` with a 150ms budget, an unresponsive background window can yield
        // `ERROR_TIMEOUT` even after responsive shell windows (`explorer.exe`) processed the event.
        if win32_err != ERROR_SUCCESS && win32_err != ERROR_TIMEOUT {
            return Err(Box::new(PersonalizeError::Win32 {
                operation: "SendMessageTimeoutW(WM_SETTINGCHANGE)",
                detail: format!("broadcast failed for topic '{topic_label}'"),
                source: Some(windows::core::Error::from(win32_err)),
            }));
        }
    }

    Ok(())
}

/// Notifies the Windows 11 shell (`explorer.exe`, DWM, and UWP/Win32 listeners) of theme and
/// immersive color changes by broadcasting `WM_SETTINGCHANGE` (`150ms` timeout) for:
/// - `L"ImmersiveColorSet"`
/// - `L"WindowsThemeElement"`
#[cfg(windows)]
pub fn notify_theme_change() -> Result<(), Box<dyn Error>> {
    broadcast_setting_change(w!("ImmersiveColorSet"), "ImmersiveColorSet")?;
    broadcast_setting_change(w!("WindowsThemeElement"), "WindowsThemeElement")?;
    Ok(())
}

#[cfg(not(windows))]
pub fn notify_theme_change() -> Result<(), Box<dyn Error>> {
    Err(Box::new(PersonalizeError::UnsupportedPlatform(
        "SendMessageTimeoutW(WM_SETTINGCHANGE)",
    )))
}

/// Strips the Win32 extended-length `\\?\` prefix for standard drive-letter paths (e.g., `\\?\C:\...`),
/// while leaving `\\?\UNC\...` network paths untouched.
pub(crate) fn strip_verbatim_drive_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        if stripped.as_bytes().get(1) == Some(&b':') {
            return stripped;
        }
    }
    s
}

/// Normalizes a local filesystem path into an absolute Win32 path without `\\?\` verbatim prefixes.
///
/// Win32 Shell APIs (`SystemParametersInfoW`, `Explorer.exe` `desktop.ini` parsers) fail silently
/// or lose persistence when passed extended-length `\\?\C:\...` paths.
pub(crate) fn normalize_win32_path(
    path: &Path,
    label: &'static str,
) -> std::result::Result<PathBuf, PersonalizeError> {
    if path.as_os_str().is_empty() {
        return Err(PersonalizeError::InvalidInput(format!(
            "{label} path must not be empty"
        )));
    }

    let cleaned_input = match path.to_str() {
        Some(s) => Path::new(strip_verbatim_drive_prefix(s)),
        None => path,
    };

    let abs_path = std::path::absolute(cleaned_input).map_err(|source| PersonalizeError::Io {
        context: format!(
            "failed to resolve absolute {label} path '{}'",
            path.display()
        ),
        source,
    })?;

    if let Some(s) = abs_path.to_str() {
        let stripped = strip_verbatim_drive_prefix(s);
        if stripped.len() != s.len() {
            return Ok(PathBuf::from(stripped));
        }
    }

    Ok(abs_path)
}

/// Encodes an OS path string into a NUL-terminated UTF-16 buffer, rejecting embedded NULs.
pub(crate) fn os_str_to_wide_nul(
    os_str: &OsStr,
    label: &'static str,
) -> std::result::Result<Vec<u16>, PersonalizeError> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = os_str.encode_wide().collect();
        if wide.contains(&0) {
            return Err(PersonalizeError::InvalidInput(format!(
                "{label} path contains an interior NUL character"
            )));
        }
        wide.push(0);
        Ok(wide)
    }

    #[cfg(not(windows))]
    {
        let utf8 = os_str.to_str().ok_or_else(|| {
            PersonalizeError::InvalidInput(format!("{label} path is not valid UTF-8"))
        })?;
        crate::registry::encode_wide_nul(utf8)
    }
}

/// Sets the desktop wallpaper in user-space via `SystemParametersInfoW` with
/// `SPI_SETDESKWALLPAPER`, `SPIF_UPDATEINIFILE`, and `SPIF_SENDCHANGE`.
pub fn set_wallpaper(path: &Path) -> Result<(), Box<dyn Error>> {
    let normalized = normalize_win32_path(path, "wallpaper")?;

    let metadata = std::fs::metadata(&normalized).map_err(|source| PersonalizeError::Io {
        context: format!(
            "wallpaper file '{}' is not accessible",
            normalized.display()
        ),
        source,
    })?;

    if !metadata.is_file() {
        return Err(Box::new(PersonalizeError::InvalidInput(format!(
            "wallpaper path '{}' is not a regular file",
            normalized.display()
        ))));
    }

    let wide_path = os_str_to_wide_nul(normalized.as_os_str(), "wallpaper")?;

    #[cfg(windows)]
    {
        // SAFETY:
        // - `wide_path` is a valid, NUL-terminated UTF-16 buffer for an existing local file path.
        // - `SPI_SETDESKWALLPAPER` treats `pvParam` as a read-only `PCWSTR` despite the C API
        //   declaring `PVOID` (`*mut c_void`) across all `SPI_*` actions.
        // - `wide_path` remains live on the stack until after `SystemParametersInfoW` returns.
        unsafe {
            SystemParametersInfoW(
                SPI_SETDESKWALLPAPER,
                0,
                Some(wide_path.as_ptr().cast_mut().cast::<c_void>()),
                SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
            )
        }
        .map_err(|source| PersonalizeError::Win32 {
            operation: "SystemParametersInfoW(SPI_SETDESKWALLPAPER)",
            detail: format!("failed setting wallpaper to '{}'", normalized.display()),
            source: Some(source),
        })?;

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = wide_path;
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "SystemParametersInfoW(SPI_SETDESKWALLPAPER)",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_win32_verbatim_drive_prefix() {
        assert_eq!(
            strip_verbatim_drive_prefix(r"\\?\C:\Users\StandardUser\Pictures\wall.jpg"),
            r"C:\Users\StandardUser\Pictures\wall.jpg"
        );
        assert_eq!(
            strip_verbatim_drive_prefix(r"\\?\UNC\Server\Share\wall.jpg"),
            r"\\?\UNC\Server\Share\wall.jpg"
        );
    }

    #[test]
    fn rejects_empty_wallpaper_path() {
        assert!(normalize_win32_path(Path::new(""), "wallpaper").is_err());
    }
}
