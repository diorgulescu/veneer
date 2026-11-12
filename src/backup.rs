use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{PersonalizeError, Result};
use crate::registry::{
    HkcuKey, ACCENT_COLOR_VALUE, APPS_USE_LIGHT_THEME, COLOR_PREVALENCE_VALUE, DESKTOP_SUBKEY,
    DWM_SUBKEY, KEY_QUERY_VALUE, KEY_SET_VALUE, PERSONALIZE_SUBKEY, SYSTEM_USES_LIGHT_THEME,
    WALLPAPER_VALUE,
};
use crate::shell;

const BACKUP_DIR_NAME: &str = "win-personalize";
const BACKUP_FILE_NAME: &str = "state_backup.json";

/// Complete snapshot of user-space `HKEY_CURRENT_USER` personalization state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateBackup {
    pub apps_use_light_theme: u32,
    pub system_uses_light_theme: u32,
    pub accent_color: Option<u32>,
    pub color_prevalence: Option<u32>,
    pub wallpaper: String,
    #[serde(default)]
    pub captured_at_unix_secs: u64,
}

/// Resolves `%LOCALAPPDATA%\win-personalize\state_backup.json` strictly in standard user space.
pub fn state_backup_path() -> Result<PathBuf> {
    if let Some(local_appdata) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(local_appdata)
            .join(BACKUP_DIR_NAME)
            .join(BACKUP_FILE_NAME));
    }

    if let Some(userprofile) = env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(userprofile)
            .join("AppData")
            .join("Local")
            .join(BACKUP_DIR_NAME)
            .join(BACKUP_FILE_NAME));
    }

    Err(Box::new(PersonalizeError::InvalidInput(
        "LOCALAPPDATA environment variable is not set".to_owned(),
    )))
}

impl StateBackup {
    /// Reads the active `HKEY_CURRENT_USER` theme, DWM accent, and desktop wallpaper values.
    pub fn capture_from_hkcu() -> Result<Self> {
        let personalize_key = HkcuKey::open(PERSONALIZE_SUBKEY, KEY_QUERY_VALUE)?;
        let apps_use_light_theme = personalize_key
            .query_dword_optional(APPS_USE_LIGHT_THEME)?
            .unwrap_or(1);
        let system_uses_light_theme = personalize_key
            .query_dword_optional(SYSTEM_USES_LIGHT_THEME)?
            .unwrap_or(1);

        let dwm_key = HkcuKey::open(DWM_SUBKEY, KEY_QUERY_VALUE)?;
        let accent_color = dwm_key.query_dword_optional(ACCENT_COLOR_VALUE)?;
        let color_prevalence = dwm_key.query_dword_optional(COLOR_PREVALENCE_VALUE)?;

        let desktop_key = HkcuKey::open(DESKTOP_SUBKEY, KEY_QUERY_VALUE)?;
        let wallpaper = desktop_key
            .query_string_optional(WALLPAPER_VALUE)?
            .unwrap_or_default();

        let captured_at_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            apps_use_light_theme,
            system_uses_light_theme,
            accent_color,
            color_prevalence,
            wallpaper,
            captured_at_unix_secs,
        })
    }

    /// Atomically serializes and writes this snapshot to `path` via a sibling temporary file.
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| PersonalizeError::Io {
                context: format!("failed creating backup directory '{}'", parent.display()),
                source,
            })?;
        }

        let json_payload = serde_json::to_string_pretty(self)?;
        let tmp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));

        fs::write(&tmp_path, json_payload.as_bytes()).map_err(|source| PersonalizeError::Io {
            context: format!("failed writing temporary backup '{}'", tmp_path.display()),
            source,
        })?;

        if let Err(rename_err) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Box::new(PersonalizeError::Io {
                context: format!("failed committing state backup to '{}'", path.display()),
                source: rename_err,
            }));
        }

        Ok(())
    }

    /// Reads and deserializes a `StateBackup` snapshot from `path`.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|source| PersonalizeError::Io {
            context: format!(
                "failed reading state backup '{}' (run `backup` or apply a setting first)",
                path.display()
            ),
            source,
        })?;
        let state = serde_json::from_str(&raw)?;
        Ok(state)
    }

    /// Writes all backed-up values back to `HKEY_CURRENT_USER` (removing DWM values that did
    /// not exist prior to the snapshot) and refreshes the Windows shell.
    pub fn restore_to_hkcu(&self) -> Result<()> {
        let personalize_key = HkcuKey::open(PERSONALIZE_SUBKEY, KEY_SET_VALUE)?;
        personalize_key.set_dword(APPS_USE_LIGHT_THEME, self.apps_use_light_theme)?;
        personalize_key.set_dword(SYSTEM_USES_LIGHT_THEME, self.system_uses_light_theme)?;

        let dwm_key = HkcuKey::open(DWM_SUBKEY, KEY_SET_VALUE)?;
        match self.accent_color {
            Some(abgr) => dwm_key.set_dword(ACCENT_COLOR_VALUE, abgr)?,
            None => dwm_key.delete_value_if_exists(ACCENT_COLOR_VALUE)?,
        }
        match self.color_prevalence {
            Some(prevalence) => dwm_key.set_dword(COLOR_PREVALENCE_VALUE, prevalence)?,
            None => dwm_key.delete_value_if_exists(COLOR_PREVALENCE_VALUE)?,
        }

        let desktop_key = HkcuKey::open(DESKTOP_SUBKEY, KEY_SET_VALUE)?;
        desktop_key.set_string(WALLPAPER_VALUE, &self.wallpaper)?;

        if !self.wallpaper.is_empty() {
            let wall_path = Path::new(&self.wallpaper);
            if wall_path.is_file() {
                shell::set_wallpaper(wall_path)?;
            }
        }

        shell::notify_theme_change()?;
        Ok(())
    }
}

/// Snapshots current `HKEY_CURRENT_USER` personalization values to
/// `%LOCALAPPDATA%\win-personalize\state_backup.json` before applying mutations.
pub fn save_state_backup() -> Result<PathBuf> {
    let target_path = state_backup_path()?;
    let snapshot = StateBackup::capture_from_hkcu()?;
    snapshot.write_to_file(&target_path)?;
    Ok(target_path)
}

/// Reads `%LOCALAPPDATA%\win-personalize\state_backup.json`, writes the original registry values
/// back to `HKEY_CURRENT_USER`, and broadcasts `WM_SETTINGCHANGE` via `notify_theme_change()`.
pub fn restore_defaults() -> Result<PathBuf> {
    let source_path = state_backup_path()?;
    let snapshot = StateBackup::read_from_file(&source_path)?;
    snapshot.restore_to_hkcu()?;
    Ok(source_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_atomic_write_and_read_roundtrip() {
        let dir = env::temp_dir().join(format!("veneer_backup_test_{}", std::process::id()));
        let file_path = dir.join(BACKUP_FILE_NAME);

        let sample = StateBackup {
            apps_use_light_theme: 0,
            system_uses_light_theme: 0,
            accent_color: Some(0xFF_D4_78_00),
            color_prevalence: Some(1),
            wallpaper: r"C:\Windows\Web\Wallpaper\Windows\img19.jpg".to_owned(),
            captured_at_unix_secs: 1_762_814_400,
        };

        sample
            .write_to_file(&file_path)
            .expect("atomic write should succeed");
        let loaded =
            StateBackup::read_from_file(&file_path).expect("reading state_backup.json should work");

        assert_eq!(loaded, sample);
        let _ = fs::remove_dir_all(&dir);
    }
}
