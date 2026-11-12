#[cfg(windows)]
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES,
    INVALID_FILE_ATTRIBUTES,
};
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNE_UPDATEITEM, SHCNF_FLUSH, SHCNF_PATHW,
};

use crate::error::{PersonalizeError, Result};
use crate::shell::{normalize_win32_path, os_str_to_wide_nul};

const DESKTOP_INI_FILENAME: &str = "desktop.ini";
static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Verifies that `target_dir` is genuinely writable by the current Medium-Integrity user.
///
/// On Windows NTFS, `FILE_ATTRIBUTE_READONLY` on a directory is an Explorer shell marker
/// (used to trigger `desktop.ini` parsing) rather than an ACL write lock. Probing file creation
/// directly validates the user's effective NTFS `FILE_ADD_FILE` DACL permission.
fn verify_directory_writable(target_dir: &Path) -> std::result::Result<(), PersonalizeError> {
    let pid = std::process::id();
    let seq = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe_path = target_dir.join(format!(".veneer_write_probe_{pid}_{seq}.tmp"));

    let probe_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
        .map_err(|source| PersonalizeError::Io {
            context: format!(
                "target directory '{}' is not writable by the current user",
                target_dir.display()
            ),
            source,
        })?;

    drop(probe_file);
    let _ = fs::remove_file(&probe_path);
    Ok(())
}

/// Builds the Windows Shell `desktop.ini` payload using standard Win32 CRLF line endings.
fn format_desktop_ini(
    abs_icon_path: &Path,
    icon_index: u32,
) -> std::result::Result<String, PersonalizeError> {
    let icon_str = abs_icon_path.to_str().ok_or_else(|| {
        PersonalizeError::InvalidInput(
            "icon file path must be valid Unicode for desktop.ini".to_owned(),
        )
    })?;

    if icon_str.contains(['\0', '\r', '\n']) {
        return Err(PersonalizeError::InvalidInput(
            "icon file path contains control characters invalid in desktop.ini".to_owned(),
        ));
    }

    Ok(format!(
        "[.ShellClassInfo]\r\nIconResource={icon_str},{icon_index}\r\n[ViewState]\r\nMode=\r\nVid=\r\nFolderType=Generic\r\n"
    ))
}

/// Customizes a folder's icon in user-space by writing `desktop.ini`, applying Win32 system/hidden
/// attributes, marking the folder read-only for Shell inspection, and flushing Explorer's icon cache.
pub fn set_folder_icon(target_dir: &Path, icon_path: &Path, icon_index: u32) -> Result<()> {
    let abs_target_dir = normalize_win32_path(target_dir, "target directory")?;
    let abs_icon_path = normalize_win32_path(icon_path, "icon file")?;

    let dir_meta = fs::metadata(&abs_target_dir).map_err(|source| PersonalizeError::Io {
        context: format!(
            "target directory '{}' is not accessible",
            abs_target_dir.display()
        ),
        source,
    })?;
    if !dir_meta.is_dir() {
        return Err(Box::new(PersonalizeError::InvalidInput(format!(
            "target path '{}' is not a directory",
            abs_target_dir.display()
        ))));
    }

    let icon_meta = fs::metadata(&abs_icon_path).map_err(|source| PersonalizeError::Io {
        context: format!("icon file '{}' is not accessible", abs_icon_path.display()),
        source,
    })?;
    if !icon_meta.is_file() {
        return Err(Box::new(PersonalizeError::InvalidInput(format!(
            "icon path '{}' is not a regular file",
            abs_icon_path.display()
        ))));
    }

    verify_directory_writable(&abs_target_dir)?;

    let desktop_ini_path = abs_target_dir.join(DESKTOP_INI_FILENAME);
    let ini_content = format_desktop_ini(&abs_icon_path, icon_index)?;

    let wide_target_dir = os_str_to_wide_nul(abs_target_dir.as_os_str(), "target directory")?;
    let wide_desktop_ini = os_str_to_wide_nul(desktop_ini_path.as_os_str(), "desktop.ini")?;

    #[cfg(windows)]
    if desktop_ini_path.exists() {
        // Clear existing HIDDEN | SYSTEM | READONLY flags prior to truncation; otherwise
        // Win32 `CreateFileW(CREATE_ALWAYS)` rejects overwriting hidden/system files with `ERROR_ACCESS_DENIED`.
        // SAFETY: `wide_desktop_ini` is a valid NUL-terminated UTF-16 path outliving the call.
        unsafe { SetFileAttributesW(PCWSTR(wide_desktop_ini.as_ptr()), FILE_ATTRIBUTE_NORMAL) }
            .map_err(|source| PersonalizeError::Win32 {
                operation: "SetFileAttributesW(FILE_ATTRIBUTE_NORMAL)",
                detail: format!(
                    "failed clearing attributes on existing '{}'",
                    desktop_ini_path.display()
                ),
                source: Some(source),
            })?;
    }

    fs::write(&desktop_ini_path, ini_content.as_bytes()).map_err(|source| {
        PersonalizeError::Io {
            context: format!("failed writing '{}'", desktop_ini_path.display()),
            source,
        }
    })?;

    #[cfg(windows)]
    {
        // 1. Mark `desktop.ini` as Hidden + System (`FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`).
        // SAFETY: `wide_desktop_ini` is NUL-terminated and outlives `SetFileAttributesW`.
        unsafe {
            SetFileAttributesW(
                PCWSTR(wide_desktop_ini.as_ptr()),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )
        }
        .map_err(|source| PersonalizeError::Win32 {
            operation: "SetFileAttributesW(desktop.ini)",
            detail: format!(
                "failed setting HIDDEN|SYSTEM attributes on '{}'",
                desktop_ini_path.display()
            ),
            source: Some(source),
        })?;

        // 2. Preserve existing folder attributes and set `FILE_ATTRIBUTE_READONLY` on `target_dir`
        //    (matching `PathMakeSystemFolderW` so Windows Explorer parses `desktop.ini`).
        // SAFETY: `wide_target_dir` is NUL-terminated and outlives both attribute calls.
        let current_dir_attrs = unsafe { GetFileAttributesW(PCWSTR(wide_target_dir.as_ptr())) };
        if current_dir_attrs == INVALID_FILE_ATTRIBUTES {
            return Err(Box::new(PersonalizeError::Win32 {
                operation: "GetFileAttributesW(target_dir)",
                detail: format!(
                    "failed reading attributes for '{}'",
                    abs_target_dir.display()
                ),
                source: Some(windows::core::Error::from_win32()),
            }));
        }

        let updated_dir_attrs =
            FILE_FLAGS_AND_ATTRIBUTES(current_dir_attrs & !FILE_ATTRIBUTE_NORMAL.0)
                | FILE_ATTRIBUTE_READONLY;

        unsafe { SetFileAttributesW(PCWSTR(wide_target_dir.as_ptr()), updated_dir_attrs) }
            .map_err(|source| PersonalizeError::Win32 {
                operation: "SetFileAttributesW(target_dir)",
                detail: format!(
                    "failed setting FILE_ATTRIBUTE_READONLY on '{}'",
                    abs_target_dir.display()
                ),
                source: Some(source),
            })?;

        // 3. Notify Explorer of the updated folder item and flush global Shell icon associations.
        // SAFETY:
        // - For `SHCNE_UPDATEITEM` with `SHCNF_PATHW`, `dwItem1` points to NUL-terminated UTF-16 `wide_target_dir`,
        //   and `SHCNF_FLUSH` guarantees synchronous completion before `wide_target_dir` drops.
        // - For `SHCNE_ASSOCCHANGED` with `SHCNF_FLUSH`, both item pointers are required to be `None` (`NULL`).
        unsafe {
            SHChangeNotify(
                SHCNE_UPDATEITEM,
                SHCNF_PATHW | SHCNF_FLUSH,
                Some(wide_target_dir.as_ptr().cast::<c_void>()),
                None,
            );
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, None, None);
        }

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = (wide_target_dir, wide_desktop_ini);
        let _ = fs::remove_file(&desktop_ini_path);
        Err(Box::new(PersonalizeError::UnsupportedPlatform(
            "SetFileAttributesW / SHChangeNotify",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_desktop_ini_format() {
        let icon = Path::new(r"C:\Users\Dragos\Icons\custom.ico");
        let content = format_desktop_ini(icon, 2).expect("valid desktop.ini content");
        let expected = concat!(
            "[.ShellClassInfo]\r\n",
            "IconResource=C:\\Users\\Dragos\\Icons\\custom.ico,2\r\n",
            "[ViewState]\r\n",
            "Mode=\r\n",
            "Vid=\r\n",
            "FolderType=Generic\r\n",
        );
        assert_eq!(content, expected);
    }

    #[test]
    fn rejects_newline_injection_in_icon_path() {
        let bad = Path::new("C:\\Icons\\bad\r\nInjected=1.ico");
        assert!(format_desktop_ini(bad, 0).is_err());
    }

    #[test]
    fn writability_probe_succeeds_and_cleans_up_in_temp_dir() {
        let temp_dir =
            std::env::temp_dir().join(format!("veneer_icon_test_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("create temp test dir");

        let res = verify_directory_writable(&temp_dir);
        assert!(res.is_ok());

        let remaining: Vec<_> = fs::read_dir(&temp_dir).expect("read temp dir").collect();
        assert!(
            remaining.is_empty(),
            "write probe must clean up its temp file"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
