use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::PersonalizeError;
use crate::registry::{self, ThemeMode};
use crate::shell;

const APP_DIR_NAME: &str = "veneer";
const DEFAULT_PROFILE_FILENAME: &str = "profile.json";

/// Serializable user-space personalization profile.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalizeProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<ThemeMode>,
    /// Accent color in `#RRGGBB` or `0xAABBGGRR` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    /// Whether DWM renders the accent color on title bars and window borders (`ColorPrevalence`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_prevalence: Option<bool>,
    /// Local path to the desktop wallpaper image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallpaper: Option<PathBuf>,
}

/// Resolves the default user-local profile path (`%APPDATA%\veneer\profile.json`).
/// Strictly avoids system-wide paths such as `%PROGRAMDATA%`.
pub fn default_profile_path() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(appdata) = env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(appdata)
            .join(APP_DIR_NAME)
            .join(DEFAULT_PROFILE_FILENAME));
    }

    if let Some(local_appdata) = env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(local_appdata)
            .join(APP_DIR_NAME)
            .join(DEFAULT_PROFILE_FILENAME));
    }

    if let Some(userprofile) = env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(userprofile)
            .join("AppData")
            .join("Roaming")
            .join(APP_DIR_NAME)
            .join(DEFAULT_PROFILE_FILENAME));
    }

    Err(Box::new(PersonalizeError::InvalidInput(
        "unable to resolve user-local AppData directory from environment".to_owned(),
    )))
}

impl PersonalizeProfile {
    /// Loads a personalization profile from a local JSON file.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let raw = fs::read_to_string(path).map_err(|source| PersonalizeError::Io {
            context: format!("failed reading profile '{}'", path.display()),
            source,
        })?;
        let profile = serde_json::from_str(&raw)?;
        Ok(profile)
    }

    /// Saves the personalization profile to a local JSON file, creating user-space parent directories if needed.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| PersonalizeError::Io {
                context: format!("failed creating directory '{}'", parent.display()),
                source,
            })?;
        }

        let payload = serde_json::to_string_pretty(self)?;
        fs::write(path, payload).map_err(|source| PersonalizeError::Io {
            context: format!("failed writing profile '{}'", path.display()),
            source,
        })?;
        Ok(())
    }

    /// Snapshots the active `HKEY_CURRENT_USER` personalization state into a `PersonalizeProfile`.
    pub fn capture_current() -> Result<Self, Box<dyn Error>> {
        let (_apps_theme, system_theme) = registry::get_theme_mode()?;
        let (abgr, prevalence) = registry::get_accent_color()?;
        let wallpaper_str = registry::get_wallpaper_path()?;

        let wallpaper = if wallpaper_str.is_empty() {
            None
        } else {
            Some(PathBuf::from(wallpaper_str))
        };

        Ok(Self {
            theme: Some(system_theme),
            accent_color: Some(format!("0x{abgr:08X}")),
            color_prevalence: Some(prevalence),
            wallpaper,
        })
    }

    /// Applies all populated fields in this profile to `HKEY_CURRENT_USER` and broadcasts shell updates.
    pub fn apply(&self) -> Result<(), Box<dyn Error>> {
        let mut needs_shell_notify = false;

        if let Some(mode) = self.theme {
            registry::set_theme_mode(mode)?;
            needs_shell_notify = true;
        }

        if let Some(ref color_str) = self.accent_color {
            let abgr = registry::parse_accent_color(color_str)?;
            let prevalence = match self.color_prevalence {
                Some(flag) => flag,
                None => registry::get_accent_color()
                    .map(|(_, prev)| prev)
                    .unwrap_or(false),
            };
            registry::set_accent_color(abgr, prevalence)?;
            needs_shell_notify = true;
        } else if let Some(prevalence) = self.color_prevalence {
            let (current_abgr, _) = registry::get_accent_color()?;
            registry::set_accent_color(current_abgr, prevalence)?;
            needs_shell_notify = true;
        }

        if needs_shell_notify {
            shell::notify_theme_change()?;
        }

        if let Some(ref wall_path) = self.wallpaper {
            shell::set_wallpaper(wall_path)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_profile_json() {
        let profile = PersonalizeProfile {
            theme: Some(ThemeMode::Dark),
            accent_color: Some("#0078D4".to_owned()),
            color_prevalence: Some(true),
            wallpaper: Some(PathBuf::from(r"C:\Users\Dragos\Pictures\bg.png")),
        };

        let serialized = serde_json::to_string_pretty(&profile).expect("serialize");
        let parsed: PersonalizeProfile = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(parsed, profile);
    }
}
