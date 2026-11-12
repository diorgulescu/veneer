use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;

use veneer::backup;
use veneer::error::{PersonalizeError, Result};
use veneer::icons;
use veneer::registry::{self, ThemeMode};
use veneer::shell;

/// Zero-privilege Windows 11 personalization CLI (Medium Integrity Level / HKCU & user paths only).
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Revert `HKEY_CURRENT_USER` personalization settings from `state_backup.json`
    #[arg(long, conflicts_with = "backup")]
    restore: bool,

    /// Manually snapshot current `HKEY_CURRENT_USER` personalization state to `%LOCALAPPDATA%`
    #[arg(long, conflicts_with = "restore")]
    backup: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Apply Windows 11 theme mode, DWM accent color, and broadcast shell changes
    Set {
        /// Theme polarity (`dark` or `light`)
        #[arg(long, value_enum)]
        mode: Option<ThemeMode>,

        /// Accent color in `#RRGGBB` hex (e.g. `#0078D4`) or `0xAABBGGRR` DWORD
        #[arg(long, value_name = "HEX_COLOR")]
        accent: Option<String>,

        /// Render accent color on title bars and window borders (`ColorPrevalence = 1`)
        #[arg(long)]
        accent_bars: bool,
    },

    /// Set the desktop wallpaper from a local image file
    Wallpaper {
        /// Path to a local wallpaper image (`.jpg`, `.png`, `.bmp`)
        #[arg(value_name = "IMAGE_PATH")]
        image_path: PathBuf,
    },

    /// Customize a folder's icon via `desktop.ini` and refresh Windows Explorer
    FolderIcon {
        /// Target folder path writable by the current user
        #[arg(long, value_name = "TARGET_DIR")]
        path: PathBuf,

        /// Path to the `.ico`, `.exe`, or `.dll` icon resource file
        #[arg(long, value_name = "ICO_PATH")]
        icon: PathBuf,

        /// Zero-based resource index inside the icon file
        #[arg(long, default_value_t = 0, value_name = "ICON_INDEX")]
        index: u32,
    },

    /// Manually snapshot current `HKEY_CURRENT_USER` personalization state to `%LOCALAPPDATA%`
    Backup,

    /// Revert `HKEY_CURRENT_USER` personalization settings from `state_backup.json`
    Restore,

    /// Display active `HKEY_CURRENT_USER` personalization state
    Status {
        /// Output active state as formatted JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct StatusReport {
    apps_theme: ThemeMode,
    system_theme: ThemeMode,
    accent_abgr: String,
    accent_rgb_hex: String,
    color_prevalence: bool,
    wallpaper: String,
}

fn handle_backup() -> Result<()> {
    let saved_path = backup::save_state_backup()?;
    println!("[backup] Snapshot saved to '{}'", saved_path.display());
    Ok(())
}

fn handle_restore() -> Result<()> {
    let restored_from = backup::restore_defaults()?;
    println!(
        "[restore] Restored personalization defaults from '{}'",
        restored_from.display()
    );
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.restore {
        return handle_restore();
    }
    if cli.backup {
        return handle_backup();
    }

    let Some(command) = cli.command else {
        return Err(Box::new(PersonalizeError::InvalidInput(
            "no subcommand or action flag specified".to_owned(),
        )));
    };

    match command {
        Commands::Set {
            mode,
            accent,
            accent_bars,
        } => {
            if mode.is_none() && accent.is_none() && !accent_bars {
                return Err(Box::new(PersonalizeError::InvalidInput(
                    "at least one of `--mode`, `--accent`, or `--accent-bars` must be provided"
                        .to_owned(),
                )));
            }

            // Validate color input prior to taking a state snapshot or writing registry keys.
            let parsed_abgr = match accent {
                Some(ref hex) => Some(registry::parse_accent_color(hex)?),
                None => None,
            };

            let backup_file = backup::save_state_backup()?;
            println!(
                "[backup] Saved pre-change state to '{}'",
                backup_file.display()
            );

            if let Some(theme_mode) = mode {
                registry::set_theme_mode(theme_mode)?;
                println!("[theme] Set Apps & System theme mode to {theme_mode:?}");
            }

            if let Some(abgr) = parsed_abgr {
                registry::set_accent_color(abgr, accent_bars)?;
                println!(
                    "[accent] Set AccentColor={} (0x{abgr:08X}), ColorPrevalence={}",
                    registry::abgr_to_rgb_hex(abgr),
                    u32::from(accent_bars)
                );
            } else if accent_bars {
                registry::set_color_prevalence(true)?;
                println!(
                    "[accent] Enabled title bar & window border accent color (ColorPrevalence=1)"
                );
            }

            shell::notify_theme_change()?;
            println!(
                "[shell] Broadcasted WM_SETTINGCHANGE (ImmersiveColorSet, WindowsThemeElement)"
            );
        }

        Commands::Wallpaper { image_path } => {
            if !image_path.is_file() {
                return Err(Box::new(PersonalizeError::InvalidInput(format!(
                    "wallpaper image '{}' does not exist or is not a regular file",
                    image_path.display()
                ))));
            }

            let backup_file = backup::save_state_backup()?;
            println!(
                "[backup] Saved pre-change state to '{}'",
                backup_file.display()
            );

            shell::set_wallpaper(&image_path)?;
            println!(
                "[wallpaper] Updated desktop wallpaper to '{}'",
                image_path.display()
            );
        }

        Commands::FolderIcon { path, icon, index } => {
            icons::set_folder_icon(&path, &icon, index)?;
            println!(
                "[folder-icon] Applied icon '{}' (index {index}) to '{}'",
                icon.display(),
                path.display()
            );
        }

        Commands::Backup => handle_backup()?,

        Commands::Restore => handle_restore()?,

        Commands::Status { json } => {
            let (apps_theme, system_theme) = registry::get_theme_mode()?;
            let (abgr, color_prevalence) = registry::get_accent_color()?;
            let wallpaper = registry::get_wallpaper_path()?;

            let report = StatusReport {
                apps_theme,
                system_theme,
                accent_abgr: format!("0x{abgr:08X}"),
                accent_rgb_hex: registry::abgr_to_rgb_hex(abgr),
                color_prevalence,
                wallpaper,
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Apps Theme       : {:?}", report.apps_theme);
                println!("System Theme     : {:?}", report.system_theme);
                println!(
                    "Accent Color     : {} ({})",
                    report.accent_rgb_hex, report.accent_abgr
                );
                println!("Color Prevalence : {}", report.color_prevalence);
                println!("Wallpaper        : {}", report.wallpaper);
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::{CommandFactory, Parser};

    use super::{Cli, Commands};
    use veneer::registry::{self, ThemeMode};

    #[test]
    fn verify_cli_schema() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_set_subcommand_and_verifies_e2e_accent_abgr() {
        let cli = Cli::try_parse_from([
            "veneer",
            "set",
            "--mode",
            "dark",
            "--accent",
            "#2A6B9C",
            "--accent-bars",
        ])
        .expect("valid `set` CLI invocation");

        match cli.command {
            Some(Commands::Set {
                mode,
                accent,
                accent_bars,
            }) => {
                assert_eq!(mode, Some(ThemeMode::Dark));
                assert_eq!(accent.as_deref(), Some("#2A6B9C"));
                assert!(accent_bars);
                let abgr = registry::parse_accent_color("#2A6B9C").expect("parse #2A6B9C");
                assert_eq!(abgr, 0xFF_9C_6B_2A);
            }
            other => panic!("expected Set command, got {other:?}"),
        }
    }

    #[test]
    fn parses_folder_icon_subcommand() {
        let cli = Cli::try_parse_from([
            "veneer",
            "folder-icon",
            "--path",
            r"C:\Users\Standard\Projects",
            "--icon",
            r"C:\Users\Standard\Icons\code.ico",
        ])
        .expect("valid `folder-icon` CLI invocation");

        match cli.command {
            Some(Commands::FolderIcon { path, icon, index }) => {
                assert_eq!(path, Path::new(r"C:\Users\Standard\Projects"));
                assert_eq!(icon, Path::new(r"C:\Users\Standard\Icons\code.ico"));
                assert_eq!(index, 0);
            }
            other => panic!("expected FolderIcon command, got {other:?}"),
        }
    }

    #[test]
    fn parses_both_subcommands_and_top_level_restore_backup_flags() {
        let wall = Cli::try_parse_from(["veneer", "wallpaper", r"C:\Wallpapers\aurora.jpg"])
            .expect("valid `wallpaper` CLI invocation");
        assert!(matches!(wall.command, Some(Commands::Wallpaper { .. })));

        let bkp_sub = Cli::try_parse_from(["veneer", "backup"]).expect("valid `backup` subcommand");
        assert!(matches!(bkp_sub.command, Some(Commands::Backup)));

        let rst_sub =
            Cli::try_parse_from(["veneer", "restore"]).expect("valid `restore` subcommand");
        assert!(matches!(rst_sub.command, Some(Commands::Restore)));

        let rst_flag = Cli::try_parse_from(["veneer", "--restore"]).expect("valid `--restore`");
        assert!(rst_flag.restore);
        assert!(rst_flag.command.is_none());

        let bkp_flag = Cli::try_parse_from(["veneer", "--backup"]).expect("valid `--backup`");
        assert!(bkp_flag.backup);
        assert!(bkp_flag.command.is_none());
    }
}
