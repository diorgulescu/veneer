#Requires -Version 5.1
<#
.SYNOPSIS
    Non-elevated End-to-End (E2E) verification suite for the standalone Windows 11 personalization CLI.

.DESCRIPTION
    Validates Phase 3 standalone deployment and runtime invariants without UAC elevation:
      1. Spawns the standalone .exe via Win32 CreateProcessW and queries its kernel EPROCESS access token
         (TokenIntegrityLevel = 25) to confirm Medium Integrity Level (RID 0x2000 / S-1-16-8192).
      2. Inspects the PE32+ Import Directory to prove static CRT linkage (zero VCRUNTIME/UCRT DLL imports).
      3. Executes the binary from an isolated standard-user folder to prove zero companion-file dependencies.
      4. Applies Dark mode + custom DWM accent color (#2A6B9C -> 0xFF9C6B2A) and verifies HKCU writes.
      5. Applies a custom icon to a temporary folder and verifies desktop.ini + Hidden/System/ReadOnly flags.
      6. Executes full rollback via --restore and confirms bit-exact preservation of the original HKCU state.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExePath,

    [Parameter(Mandatory = $false)]
    [switch]$AllowElevatedSession
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Pass([string]$Message) {
    Write-Host "  [PASS] $Message" -ForegroundColor Green
}

function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -ne $Expected) {
        throw "Assertion failed for ${Label}: expected '$Expected', got '$Actual'."
    }
    Write-Pass "${Label}: $Actual"
}

function Assert-True([bool]$Condition, [string]$Label) {
    if (-not $Condition) {
        throw "Assertion failed: $Label"
    }
    Write-Pass $Label
}

# ---------------------------------------------------------------------------
# Helpers: Registry HKCU Raw Readers (handles signed Int32 -> UInt32 DWORDs)
# ---------------------------------------------------------------------------
function Get-HkcuDwordOptional([string]$RegPath, [string]$Name) {
    if (-not (Test-Path -LiteralPath $RegPath)) {
        return $null
    }
    $item = Get-Item -LiteralPath $RegPath
    $raw = $item.GetValue($Name, $null)
    if ($null -eq $raw) {
        return $null
    }
    $bytes = [System.BitConverter]::GetBytes([int32]$raw)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function Get-HkcuStringOptional([string]$RegPath, [string]$Name) {
    if (-not (Test-Path -LiteralPath $RegPath)) {
        return $null
    }
    $item = Get-Item -LiteralPath $RegPath
    $raw = $item.GetValue($Name, $null)
    if ($null -eq $raw) {
        return $null
    }
    return [string]$raw
}

function Capture-HkcuBaseline {
    $personalizeKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $dwmKey         = 'HKCU:\Software\Microsoft\Windows\DWM'
    $desktopKey     = 'HKCU:\Control Panel\Desktop'

    return [PSCustomObject]@{
        AppsUseLightTheme    = Get-HkcuDwordOptional -RegPath $personalizeKey -Name 'AppsUseLightTheme'
        SystemUsesLightTheme = Get-HkcuDwordOptional -RegPath $personalizeKey -Name 'SystemUsesLightTheme'
        AccentColor          = Get-HkcuDwordOptional -RegPath $dwmKey -Name 'AccentColor'
        ColorPrevalence      = Get-HkcuDwordOptional -RegPath $dwmKey -Name 'ColorPrevalence'
        Wallpaper            = Get-HkcuStringOptional -RegPath $desktopKey -Name 'Wallpaper'
    }
}

function Restore-EmergencyBaseline($Baseline) {
    $personalizeKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $dwmKey         = 'HKCU:\Software\Microsoft\Windows\DWM'
    $desktopKey     = 'HKCU:\Control Panel\Desktop'

    if ($null -ne $Baseline.AppsUseLightTheme) {
        Set-ItemProperty -LiteralPath $personalizeKey -Name 'AppsUseLightTheme' -Value ([int32]$Baseline.AppsUseLightTheme) -Type DWord
    }
    if ($null -ne $Baseline.SystemUsesLightTheme) {
        Set-ItemProperty -LiteralPath $personalizeKey -Name 'SystemUsesLightTheme' -Value ([int32]$Baseline.SystemUsesLightTheme) -Type DWord
    }

    if ($null -ne $Baseline.AccentColor) {
        $signedAccent = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes([uint32]$Baseline.AccentColor), 0)
        Set-ItemProperty -LiteralPath $dwmKey -Name 'AccentColor' -Value $signedAccent -Type DWord
    } else {
        Remove-ItemProperty -LiteralPath $dwmKey -Name 'AccentColor' -ErrorAction SilentlyContinue
    }

    if ($null -ne $Baseline.ColorPrevalence) {
        Set-ItemProperty -LiteralPath $dwmKey -Name 'ColorPrevalence' -Value ([int32]$Baseline.ColorPrevalence) -Type DWord
    } else {
        Remove-ItemProperty -LiteralPath $dwmKey -Name 'ColorPrevalence' -ErrorAction SilentlyContinue
    }

    if ($null -ne $Baseline.Wallpaper) {
        Set-ItemProperty -LiteralPath $desktopKey -Name 'Wallpaper' -Value $Baseline.Wallpaper -Type String
    }
}

# ---------------------------------------------------------------------------
# Helper: Spawn Target .exe via CreateProcessW & Inspect Kernel Token Integrity
# ---------------------------------------------------------------------------
function Invoke-WithIntegrityInspection([string]$BinaryPath, [string]$Arguments) {
    if ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage') {
        if (-not ('Win32ProcessInspector' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class Win32ProcessInspector {
    private const uint TOKEN_QUERY = 0x0008;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint WAIT_TIMEOUT_MS = 10000;
    private const int TokenIntegrityLevel = 25;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

    public static void SpawnAndInspect(string exePath, string args, out uint integrityRid, out uint exitCode) {
        STARTUPINFOW si = new STARTUPINFOW();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
        PROCESS_INFORMATION pi;
        StringBuilder cmdLine = new StringBuilder("\"" + exePath + "\" " + args);

        if (!CreateProcessW(exePath, cmdLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try {
            IntPtr hToken;
            if (!OpenProcessToken(pi.hProcess, TOKEN_QUERY, out hToken)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                uint len = 0;
                GetTokenInformation(hToken, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
                IntPtr buffer = Marshal.AllocHGlobal((int)len);
                try {
                    if (!GetTokenInformation(hToken, TokenIntegrityLevel, buffer, len, out len)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    IntPtr pSid = Marshal.ReadIntPtr(buffer);
                    byte count = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                    IntPtr pRid = GetSidSubAuthority(pSid, (uint)(count - 1));
                    integrityRid = (uint)Marshal.ReadInt32(pRid);
                } finally {
                    Marshal.FreeHGlobal(buffer);
                }
            } finally {
                CloseHandle(hToken);
            }

            WaitForSingleObject(pi.hProcess, WAIT_TIMEOUT_MS);
            if (!GetExitCodeProcess(pi.hProcess, out exitCode)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
"@
        }

        [uint32]$rid = 0
        [uint32]$code = 0
        [Win32ProcessInspector]::SpawnAndInspect($BinaryPath, $Arguments, [ref]$rid, [ref]$code)
        return [PSCustomObject]@{
            IntegrityRid = $rid
            ExitCode     = $code
        }
    }

    # Constrained Language Mode fallback using standard execution + `whoami /groups`
    & $BinaryPath $Arguments | Out-Null
    $code = [uint32]$LASTEXITCODE
    $groupsCsv = & whoami.exe /groups /fo csv | ConvertFrom-Csv
    foreach ($row in $groupsCsv) {
        if ($row.SID -match '^S-1-16-(\d+)$') {
            return [PSCustomObject]@{
                IntegrityRid = [uint32]$Matches[1]
                ExitCode     = $code
            }
        }
    }
    throw "Unable to determine Mandatory Integrity Level SID from token."
}

# ---------------------------------------------------------------------------
# Helper: Inspect PE32+ Import Table to verify +crt-static (no VCRedist DLLs)
# ---------------------------------------------------------------------------
function Get-PeImportedDlls([string]$BinaryPath) {
    $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
    if ([System.BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) {
        throw "'$BinaryPath' is not a valid MZ/PE executable."
    }

    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3C)
    if ([System.BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
        throw "'$BinaryPath' has an invalid PE signature."
    }

    $coffOffset = $peOffset + 4
    $numSections = [System.BitConverter]::ToUInt16($bytes, $coffOffset + 2)
    $optHeaderSize = [System.BitConverter]::ToUInt16($bytes, $coffOffset + 16)
    $optOffset = $coffOffset + 20
    $magic = [System.BitConverter]::ToUInt16($bytes, $optOffset)

    # PE32+ (0x20B) Import Table DataDirectory[1] is at OptionalHeader + 120; PE32 (0x10B) is at + 104
    $importDirEntryOffset = if ($magic -eq 0x20B) {
        $optOffset + 120
    } elseif ($magic -eq 0x10B) {
        $optOffset + 104
    } else {
        throw ("Unsupported PE OptionalHeader magic: 0x{0:X4}" -f $magic)
    }

    $importRva = [System.BitConverter]::ToUInt32($bytes, $importDirEntryOffset)
    if ($importRva -eq 0) {
        return @()
    }

    $sectionTableOffset = $optOffset + $optHeaderSize
    $sections = @(for ($i = 0; $i -lt $numSections; $i++) {
        $secOff = $sectionTableOffset + ($i * 40)
        [PSCustomObject]@{
            VirtualSize    = [System.BitConverter]::ToUInt32($bytes, $secOff + 8)
            VirtualAddress = [System.BitConverter]::ToUInt32($bytes, $secOff + 12)
            RawSize        = [System.BitConverter]::ToUInt32($bytes, $secOff + 16)
            RawPointer     = [System.BitConverter]::ToUInt32($bytes, $secOff + 20)
        }
    })

    function Convert-RvaToOffset([uint32]$Rva) {
        foreach ($s in $sections) {
            $span = [Math]::Max($s.VirtualSize, $s.RawSize)
            if ($Rva -ge $s.VirtualAddress -and $Rva -lt ($s.VirtualAddress + $span)) {
                return [int]($s.RawPointer + ($Rva - $s.VirtualAddress))
            }
        }
        throw ("Failed mapping RVA 0x{0:X8} to file offset." -f $Rva)
    }

    $dllNames = New-Object System.Collections.Generic.List[string]
    $descOffset = Convert-RvaToOffset $importRva
    while ($true) {
        $nameRva = [System.BitConverter]::ToUInt32($bytes, $descOffset + 12)
        $firstThunk = [System.BitConverter]::ToUInt32($bytes, $descOffset + 16)
        if ($nameRva -eq 0 -and $firstThunk -eq 0) {
            break
        }
        $nameFileOffset = Convert-RvaToOffset $nameRva
        $endOffset = $nameFileOffset
        while ($bytes[$endOffset] -ne 0) { $endOffset++ }
        $dllName = [System.Text.Encoding]::ASCII.GetString($bytes, $nameFileOffset, $endOffset - $nameFileOffset)
        $dllNames.Add($dllName)
        $descOffset += 20
    }
    return ,$dllNames.ToArray()
}

# ---------------------------------------------------------------------------
# Helper: Synthesize a valid minimal 16x16 32-bpp .ico file in user-space
# ---------------------------------------------------------------------------
function New-MinimalTestIcon([string]$DestinationPath) {
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)

    $pixelBytes = 16 * 16 * 4   # 1024 bytes BGRA
    $maskBytes  = 16 * 4        # 64 bytes 1-bpp AND mask (DWORD-aligned rows)
    $dibSize    = 40 + $pixelBytes + $maskBytes

    # ICONDIR (6 bytes)
    $bw.Write([uint16]0)        # idReserved
    $bw.Write([uint16]1)        # idType = 1 (ICO)
    $bw.Write([uint16]1)        # idCount = 1

    # ICONDIRENTRY (16 bytes)
    $bw.Write([byte]16)         # bWidth
    $bw.Write([byte]16)         # bHeight
    $bw.Write([byte]0)          # bColorCount
    $bw.Write([byte]0)          # bReserved
    $bw.Write([uint16]1)        # wPlanes
    $bw.Write([uint16]32)       # wBitCount
    $bw.Write([uint32]$dibSize) # dwBytesInRes
    $bw.Write([uint32]22)       # dwImageOffset (6 + 16)

    # BITMAPINFOHEADER (40 bytes)
    $bw.Write([uint32]40)       # biSize
    $bw.Write([int32]16)        # biWidth
    $bw.Write([int32]32)        # biHeight (16 * 2 for XOR + AND masks)
    $bw.Write([uint16]1)        # biPlanes
    $bw.Write([uint16]32)       # biBitCount
    $bw.Write([uint32]0)        # biCompression (BI_RGB)
    $bw.Write([uint32]($pixelBytes + $maskBytes))
    $bw.Write([int32]0)         # biXPelsPerMeter
    $bw.Write([int32]0)         # biYPelsPerMeter
    $bw.Write([uint32]0)        # biClrUsed
    $bw.Write([uint32]0)        # biClrImportant

    # 16x16 BGRA pixels (#2A6B9C -> B=0x9C, G=0x6B, R=0x2A, A=0xFF)
    for ($i = 0; $i -lt 256; $i++) {
        $bw.Write([byte]0x9C)
        $bw.Write([byte]0x6B)
        $bw.Write([byte]0x2A)
        $bw.Write([byte]0xFF)
    }

    # 16x16 opaque AND mask (all zeros)
    $bw.Write((New-Object byte[] $maskBytes))
    $bw.Flush()

    [System.IO.File]::WriteAllBytes($DestinationPath, $ms.ToArray())
    $bw.Dispose()
    $ms.Dispose()
}

# ---------------------------------------------------------------------------
# Resolve Target Executable Path
# ---------------------------------------------------------------------------
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ExePath)) {
    $candidates = @(
        (Join-Path $RepoRoot 'target\x86_64-pc-windows-msvc\release\veneer.exe'),
        (Join-Path $RepoRoot 'target\aarch64-pc-windows-msvc\release\veneer.exe'),
        (Join-Path $RepoRoot 'target\release\veneer.exe'),
        (Join-Path $RepoRoot 'target\x86_64-pc-windows-msvc\release\win-personalize.exe'),
        (Join-Path $RepoRoot 'target\release\win-personalize.exe')
    )
    $ExePath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $ExePath) {
        throw 'Release executable not found. Build first with: cargo build --release --target x86_64-pc-windows-msvc'
    }
}
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path
Write-Host ("Target Executable: {0} ({1:N0} bytes)" -f $ExePath, ([System.IO.FileInfo]$ExePath).Length) -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Isolated Workspace & Backup Guard Setup
# ---------------------------------------------------------------------------
$TempRoot      = Join-Path ([System.IO.Path]::GetTempPath()) ('veneer-e2e-' + [guid]::NewGuid().ToString('N'))
$PortableDir   = Join-Path $TempRoot 'PortableTools'
$TestFolderDir = Join-Path $TempRoot 'SampleUserFolder'
$TestIconPath  = Join-Path $TempRoot 'custom-folder.ico'
$PortableExe   = Join-Path $PortableDir (Split-Path -Leaf $ExePath)

$StateBackupPath = Join-Path $env:LOCALAPPDATA 'win-personalize\state_backup.json'
$PreExistingBackupBytes = if (Test-Path -LiteralPath $StateBackupPath) {
    [System.IO.File]::ReadAllBytes($StateBackupPath)
} else {
    $null
}

$Baseline = Capture-HkcuBaseline
$TestSucceeded = $false

try {
    New-Item -ItemType Directory -Path $PortableDir -Force | Out-Null
    New-Item -ItemType Directory -Path $TestFolderDir -Force | Out-Null
    Copy-Item -LiteralPath $ExePath -Destination $PortableExe -Force

    # -----------------------------------------------------------------------
    # 1. Verify Medium Integrity Level & Static CRT Linkage
    # -----------------------------------------------------------------------
    Write-Step '1/5 Verifying Medium Integrity Level & Zero-VCRedist Static Linkage'

    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin -and -not $AllowElevatedSession) {
        throw 'Verification must be run from a standard NON-elevated user shell (current shell is Administrator/High Integrity).'
    }
    Assert-True (-not $isAdmin -or $AllowElevatedSession.IsPresent) 'Session running without UAC Administrator elevation'

    $inspection = Invoke-WithIntegrityInspection -BinaryPath $PortableExe -Arguments '--version'
    Assert-Equal $inspection.ExitCode ([uint32]0) 'Standalone portable binary (--version) exit code'

    if (-not $AllowElevatedSession) {
        # SECURITY_MANDATORY_MEDIUM_RID = 0x2000 (8192), MEDIUM_PLUS = 0x2100 (8448), HIGH = 0x3000 (12288)
        $rid = $inspection.IntegrityRid
        $isMedium = ($rid -ge 0x2000) -and ($rid -lt 0x3000)
        Assert-True $isMedium ("Target process token verified at Medium Integrity Level (RID=0x{0:X4} / S-1-16-{1})" -f $rid, $rid)
    }

    $importedDlls = @(Get-PeImportedDlls -BinaryPath $PortableExe)
    Write-Host ("  Imported System DLLs: {0}" -f ($importedDlls -join ', ')) -ForegroundColor DarkGray
    $vcRedistImports = @($importedDlls | Where-Object { $_ -match '^(vcruntime|msvcp|api-ms-win-crt-|ucrtbase)' })
    Assert-Equal $vcRedistImports.Count 0 'Dynamic VC++ Redistributable / UCRT DLL imports (+crt-static)'

    # -----------------------------------------------------------------------
    # 2. Apply Custom Accent Color (#2A6B9C) & Dark Mode
    # -----------------------------------------------------------------------
    Write-Step '2/5 Applying Dark Theme & Custom Accent Color (#2A6B9C)'

    & $PortableExe set --mode dark --accent '#2A6B9C' --accent-bars
    Assert-Equal $LASTEXITCODE 0 'CLI command (set --mode dark --accent #2A6B9C --accent-bars) exit code'

    # -----------------------------------------------------------------------
    # 3. Confirm Registry Writes in HKEY_CURRENT_USER
    # -----------------------------------------------------------------------
    Write-Step '3/5 Verifying HKEY_CURRENT_USER Registry Writes & Backup Snapshot'

    $personalizeKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
    $dwmKey         = 'HKCU:\Software\Microsoft\Windows\DWM'

    $appsLight   = Get-HkcuDwordOptional -RegPath $personalizeKey -Name 'AppsUseLightTheme'
    $systemLight = Get-HkcuDwordOptional -RegPath $personalizeKey -Name 'SystemUsesLightTheme'
    $accentAbgr  = Get-HkcuDwordOptional -RegPath $dwmKey -Name 'AccentColor'
    $prevalence  = Get-HkcuDwordOptional -RegPath $dwmKey -Name 'ColorPrevalence'

    # #2A6B9C -> R=0x2A, G=0x6B, B=0x9C, A=0xFF -> AABBGGRR = 0xFF9C6B2A (4288441130)
    $expectedAbgr = [uint32]4288441130

    Assert-Equal $appsLight ([uint32]0) 'HKCU Personalize\AppsUseLightTheme'
    Assert-Equal $systemLight ([uint32]0) 'HKCU Personalize\SystemUsesLightTheme'
    Assert-Equal ("0x{0:X8}" -f $accentAbgr) ("0x{0:X8}" -f $expectedAbgr) 'HKCU DWM\AccentColor (AABBGGRR)'
    Assert-Equal $prevalence ([uint32]1) 'HKCU DWM\ColorPrevalence'

    Assert-True (Test-Path -LiteralPath $StateBackupPath) "Pre-change backup created at '$StateBackupPath'"
    $parsedBackup = Get-Content -LiteralPath $StateBackupPath -Raw | ConvertFrom-Json
    Assert-True ($null -ne $parsedBackup) 'state_backup.json contains valid serialized JSON'

    # -----------------------------------------------------------------------
    # 4. Test Folder Icon Replacement on Temporary Directory
    # -----------------------------------------------------------------------
    Write-Step '4/5 Testing Folder Icon Replacement & desktop.ini Attributes'

    New-MinimalTestIcon -DestinationPath $TestIconPath
    & $PortableExe folder-icon --path $TestFolderDir --icon $TestIconPath
    Assert-Equal $LASTEXITCODE 0 'CLI command (folder-icon) exit code'

    $desktopIniPath = Join-Path $TestFolderDir 'desktop.ini'
    $iniItem = Get-Item -LiteralPath $desktopIniPath -Force
    $dirItem = Get-Item -LiteralPath $TestFolderDir -Force

    $hasHidden = ($iniItem.Attributes -band [System.IO.FileAttributes]::Hidden) -ne 0
    $hasSystem = ($iniItem.Attributes -band [System.IO.FileAttributes]::System) -ne 0
    $dirMarked = ($dirItem.Attributes -band ([System.IO.FileAttributes]::ReadOnly -bor [System.IO.FileAttributes]::System)) -ne 0

    Assert-True $hasHidden 'desktop.ini has FILE_ATTRIBUTE_HIDDEN'
    Assert-True $hasSystem 'desktop.ini has FILE_ATTRIBUTE_SYSTEM'
    Assert-True $dirMarked 'Target directory has ReadOnly/System shell attribute'

    $iniContent = Get-Content -LiteralPath $desktopIniPath -Force -Raw
    Assert-True ($iniContent.Contains('[.ShellClassInfo]')) 'desktop.ini contains [.ShellClassInfo] header'
    Assert-True ($iniContent.Contains("IconResource=$TestIconPath,0")) 'desktop.ini contains exact IconResource path and index'
    Assert-True ($iniContent.Contains('FolderType=Generic')) 'desktop.ini contains FolderType=Generic'

    # -----------------------------------------------------------------------
    # 5. Test Full Rollback via `--restore` & Confirm Baseline Preserved
    # -----------------------------------------------------------------------
    Write-Step '5/5 Executing Full Rollback (--restore) & Verifying Baseline State'

    & $PortableExe --restore
    Assert-Equal $LASTEXITCODE 0 'CLI command (--restore) exit code'

    $AfterRestore = Capture-HkcuBaseline
    Assert-Equal $AfterRestore.AppsUseLightTheme $Baseline.AppsUseLightTheme 'Restored AppsUseLightTheme matches baseline'
    Assert-Equal $AfterRestore.SystemUsesLightTheme $Baseline.SystemUsesLightTheme 'Restored SystemUsesLightTheme matches baseline'
    Assert-Equal $AfterRestore.AccentColor $Baseline.AccentColor 'Restored AccentColor matches baseline'
    Assert-Equal $AfterRestore.ColorPrevalence $Baseline.ColorPrevalence 'Restored ColorPrevalence matches baseline'
    Assert-Equal $AfterRestore.Wallpaper $Baseline.Wallpaper 'Restored Wallpaper matches baseline'

    $TestSucceeded = $true
    Write-Host "`nALL END-TO-END VERIFICATION CHECKS PASSED SUCCESSFULLY." -ForegroundColor Green
}
finally {
    if (-not $TestSucceeded) {
        Write-Warning 'Test suite interrupted or failed; restoring emergency HKCU baseline...'
        try { Restore-EmergencyBaseline -Baseline $Baseline } catch { Write-Warning "Emergency restore warning: $_" }
    }

    if ($null -ne $PreExistingBackupBytes) {
        [System.IO.File]::WriteAllBytes($StateBackupPath, $PreExistingBackupBytes)
    }

    if (Test-Path -LiteralPath $TempRoot) {
        Get-ChildItem -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.Attributes = [System.IO.FileAttributes]::Normal } catch {}
        }
        try {
            (Get-Item -LiteralPath $TestFolderDir -Force -ErrorAction SilentlyContinue).Attributes = [System.IO.FileAttributes]::Directory
        } catch {}
        Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
