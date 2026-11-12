# Veneer (`win-personalize`)

Zero-privilege, zero-dependency Windows 11 personalization CLI written in Rust.

Veneer runs strictly in standard user-space (**Medium Integrity Level**) without requiring Administrator rights (UAC elevation) or touching `HKEY_LOCAL_MACHINE`. All operations target `HKEY_CURRENT_USER` and local user paths, and the binary is compiled with static CRT linkage (`+crt-static`) so it runs out of the box from any user directory or USB drive without the Visual C++ Redistributable.

## Features

- **Theme Polarity**: Switch Windows 11 app and system modes (`AppsUseLightTheme` & `SystemUsesLightTheme`) between Dark (`0`) and Light (`1`).
- **DWM Accent Color**: Set `AccentColor` (`AABBGGRR` DWORD) and title bar/border `ColorPrevalence` under `HKCU\Software\Microsoft\Windows\DWM`.
- **Live Shell Broadcast**: Dispatches `WM_SETTINGCHANGE` (`ImmersiveColorSet` & `WindowsThemeElement`) via `SendMessageTimeoutW` (`150ms` timeout) so Explorer and DWM repaint immediately.
- **Desktop Wallpaper**: Updates the desktop background via `SystemParametersInfoW(SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)`.
- **Folder Icons**: Writes `desktop.ini` (`FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`), marks the target directory `FILE_ATTRIBUTE_READONLY`, and flushes Explorer's icon cache via `SHChangeNotify`.
- **Automatic Backup & Rollback**: Snapshots `HKCU` state to `%LOCALAPPDATA%\win-personalize\state_backup.json` before mutations and restores defaults via `--restore` / `restore`.

## Prebuilt Windows Binaries

Prebuilt standalone executables for **Windows 11 x64** (`x86_64-pc-windows-msvc`) and **Windows 11 ARM64** (`aarch64-pc-windows-msvc`) are built automatically via GitHub Actions:

- **Releases**: Download `veneer-x86_64-pc-windows-msvc.exe` (or `.zip`) from the **Releases** page.
- **CI Artifacts**: Every push to `main` produces verified prebuilt binaries in the **Actions** tab.

## Usage

```powershell
# Apply Dark mode, custom accent color (#2A6B9C), and enable title-bar/border color prevalence
veneer.exe set --mode dark --accent "#2A6B9C" --accent-bars

# Set desktop wallpaper
veneer.exe wallpaper "$env:USERPROFILE\Pictures\wallpaper.jpg"

# Customize a folder icon and refresh Windows Explorer immediately
veneer.exe folder-icon --path "$env:USERPROFILE\Projects" --icon "$env:USERPROFILE\Icons\rust.ico"

# Inspect current HKCU personalization settings
veneer.exe status --json

# Manual state snapshot & full rollback
veneer.exe backup
veneer.exe --restore
```

## Building & Verifying from Source

```powershell
# Build size-optimized static-CRT release executable
cargo build --release --locked --target x86_64-pc-windows-msvc

# Run the non-elevated End-to-End verification script on Windows 11
.\scripts\verify-e2e.cmd
```

## Creating a New Release

Push a `v*` tag to trigger the `.github/workflows/release.yml` pipeline and automatically publish prebuilt Windows binaries and `SHA256SUMS.txt` to GitHub Releases:

```bash
git tag v0.1.0
git push origin v0.1.0
```
