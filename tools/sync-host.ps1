Param(
  [string]$ChromeExtensionId,
  [string]$BraveExtensionId,
  [string]$UpdateUrl = 'https://clients2.google.com/service/update2/crx',
  [switch]$UserPolicy,
  [switch]$MachinePolicy
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[sync-host] $msg" }
function Write-Warn($msg) { Write-Host "[sync-host] WARN: $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[sync-host] ERROR: $msg" -ForegroundColor Red }

# Resolve paths
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Join-Path $root 'src-tauri\target\release\SecurePasswordManager.exe'
$destDir = Join-Path $root 'native-host-bin'
$dest = Join-Path $destDir 'SecurePasswordManager.exe'
$manifestSrc = Join-Path $root 'browser-extension\native-messaging-host\com.passwordmanager.native.json'
$manifestDest = Join-Path $destDir 'com.passwordmanager.native.json'
$unpackedExtDir = Join-Path $root 'browser-extension'

Write-Info "Root: $root"
Write-Info "Source: $source"
Write-Info "Destination: $dest"

# --- Helper: detect unpacked extension ID from browser Preferences ---
function Get-UnpackedExtensionId {
  param(
    [Parameter(Mandatory=$true)][string]$PreferencesPath,
    [Parameter(Mandatory=$true)][string]$UnpackedDir
  )
  try {
    if (!(Test-Path $PreferencesPath)) { return $null }
    $json = Get-Content -Path $PreferencesPath -Raw | ConvertFrom-Json
    if ($null -eq $json.extensions -or $null -eq $json.extensions.settings) { return $null }
    $settings = $json.extensions.settings
    # When deserialized, $settings is a PSCustomObject with properties named by extension IDs
    $props = $settings.PSObject.Properties | ForEach-Object { $_ }
    foreach ($p in $props) {
      $id = $p.Name
      $entry = $p.Value
      # Prefer matching unpacked path (Chrome stores absolute path for unpacked extensions)
      $path = $entry.path
      $loc = $entry.location
      $isUnpacked = ($loc -eq 'unpacked' -or $entry.from_webstore -eq $false)
      if ($path) {
        # Normalize slashes and case for comparison
        $pathNorm = ($path -replace '/', '\').ToLowerInvariant()
        $dirNorm = $UnpackedDir.ToLowerInvariant()
        if ($pathNorm -like "$dirNorm*") { return $id }
      }
      # Fallback: match by manifest name
      if ($entry.manifest -and $entry.manifest.name -eq 'Password Manager' -and $isUnpacked) { return $id }
    }
    return $null
  } catch {
    Write-Warn "Failed to parse Preferences at $PreferencesPath: $($_.Exception.Message)"
    return $null
  }
}

# --- Helper: locate installed app executable automatically ---
function Get-InstalledExePath {
  try {
    $exeName = 'SecurePasswordManager.exe'
    $candidates = @()
    $uninstallRoots = @(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
      'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($rootKey in $uninstallRoots) {
      if (Test-Path $rootKey) {
        Get-ChildItem -Path $rootKey -ErrorAction SilentlyContinue | ForEach-Object {
          $props = Get-ItemProperty -Path $_.PsPath -ErrorAction SilentlyContinue
          if ($props) {
            $name = ("$($props.DisplayName)").ToLower()
            $publisher = ("$($props.Publisher)").ToLower()
            $appid = ("$($props.ProductID)")
            $installLoc = $props.InstallLocation
            $displayIcon = $props.DisplayIcon
            if ($name -match 'password.?manager' -or $name -match 'securepasswordmanager' -or $publisher -match 'grecu' -or $appid -match 'com.liviu.passwordmanager') {
              if ($installLoc) {
                $path = Join-Path $installLoc $exeName
                if (Test-Path $path) { $candidates += $path }
              }
              if ($displayIcon) {
                $iconPath = $displayIcon -replace '"', ''
                if ($iconPath -and (Split-Path $iconPath -Leaf) -eq $exeName -and (Test-Path $iconPath)) {
                  $candidates += $iconPath
                }
              }
            }
          }
        }
      }
    }
    foreach ($p in $candidates) { return $p }
    $known = @(
      (Join-Path $env:ProgramFiles 'passwordmanager\SecurePasswordManager.exe'),
      (Join-Path $env:ProgramFiles 'SecurePasswordManager\SecurePasswordManager.exe'),
      (Join-Path $env:ProgramFiles 'PasswordManager\SecurePasswordManager.exe'),
      (Join-Path ${env:ProgramFiles(x86)} 'passwordmanager\SecurePasswordManager.exe'),
      (Join-Path ${env:ProgramFiles(x86)} 'PasswordManager\SecurePasswordManager.exe'),
      (Join-Path $env:LOCALAPPDATA 'Programs\passwordmanager\SecurePasswordManager.exe'),
      (Join-Path $env:LOCALAPPDATA 'PasswordManager\SecurePasswordManager.exe')
    )
    foreach ($k in $known) { if ($k -and (Test-Path $k)) { return $k } }
    return $null
  } catch { return $null }
}

# If no IDs provided, try to auto-detect after user loads the unpacked extension once
if (-not $ChromeExtensionId) {
  $chromePrefs = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Preferences'
  $ChromeExtensionId = Get-UnpackedExtensionId -PreferencesPath $chromePrefs -UnpackedDir $unpackedExtDir
  if ($ChromeExtensionId) { Write-Info "Detected Chrome unpacked extension ID: $ChromeExtensionId" } else { Write-Warn "Could not detect Chrome unpacked extension ID. Ensure you've loaded the unpacked extension once in Chrome (chrome://extensions)." }
}
if (-not $BraveExtensionId) {
  $bravePrefs = Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data\Default\Preferences'
  $BraveExtensionId = Get-UnpackedExtensionId -PreferencesPath $bravePrefs -UnpackedDir $unpackedExtDir
  if ($BraveExtensionId) { Write-Info "Detected Brave unpacked extension ID: $BraveExtensionId" } else { Write-Warn "Could not detect Brave unpacked extension ID. Ensure you've loaded the unpacked extension once in Brave (brave://extensions)." }
}

# Resolve final executable path: prefer installed app; fallback to dev build copy
$finalExe = $null
$installedExe = Get-InstalledExePath
if ($installedExe) {
  $finalExe = $installedExe
  Write-Info ("Detected installed executable: {0}" -f $finalExe)
} elseif (Test-Path $source) {
  Write-Info "Installed app not found; will use dev build source and copy to native-host-bin."
} else {
  Write-Err "Installed app not found and dev build source missing. Install via MSI or build with 'cargo build --release' first."
  exit 1
}

# Stop running host instances that lock the destination copy
try {
  $procs = Get-Process -Name SecurePasswordManager -ErrorAction SilentlyContinue
  foreach ($p in $procs) {
    $targetPath = $finalExe
    if (-not $targetPath) { $targetPath = $dest }
    if ($null -ne $p.Path -and ($p.Path -ieq $targetPath)) {
      Write-Info "Stopping running host instance (PID: $($p.Id)) at $($p.Path)"
      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
  }
  Start-Sleep -Milliseconds 400
} catch {
  Write-Warn "Failed to enumerate/stop running host instances: $($_.Exception.Message)"
}

# Copy the executable only when using dev build source (skip when installed is found)
if (-not $finalExe) {
  try {
    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    Copy-Item -Path $source -Destination $dest -Force
    $finalExe = $dest
    Write-Info "Copied host executable to native-host-bin"
  } catch {
    Write-Err "Failed to copy executable: $($_.Exception.Message)"
    exit 1
  }
}

# Decide manifest destination path based on privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$manifestOutPath = $manifestDest
if ($finalExe) {
  if ($isAdmin) {
    $manifestOutPath = Join-Path $env:ProgramData 'PasswordManager\native\com.passwordmanager.native.json'
  } else {
    $manifestOutPath = Join-Path $env:LOCALAPPDATA 'PasswordManager\native\com.passwordmanager.native.json'
  }
}
Write-Info "Manifest will be written to: $manifestOutPath"

# Ensure manifest is installed and registry is updated (Chrome/Brave)
try {
  if (Test-Path $manifestSrc) {
    # Read, update path to installed exe, update allowed_origins, and write manifest next to host exe
    $manifestJson = Get-Content -Path $manifestSrc -Raw | ConvertFrom-Json
    $manifestJson.path = $finalExe
    if ($ChromeExtensionId -or $BraveExtensionId) {
      $origins = @()
      if ($ChromeExtensionId) { $origins += "chrome-extension://$ChromeExtensionId/" }
      if ($BraveExtensionId -and $BraveExtensionId -ne $ChromeExtensionId) { $origins += "chrome-extension://$BraveExtensionId/" }
      if ($manifestJson.allowed_origins) {
        foreach ($o in $manifestJson.allowed_origins) {
          if ($origins -notcontains $o) { $origins += $o }
        }
      }
      $manifestJson.allowed_origins = $origins
    }
    $manifestOut = $manifestJson | ConvertTo-Json -Depth 5

    $manifestDir = Split-Path $manifestOutPath -Parent
    New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
    Set-Content -Path $manifestOutPath -Value $manifestOut -Encoding UTF8
    Write-Info "Wrote manifest and updated path -> $finalExe"

    # Register native host via registry for Chrome and Brave (per-user)
    $hostName = [System.IO.Path]::GetFileNameWithoutExtension($manifestOutPath)

    $chromeReg = "HKCU\Software\Google\Chrome\NativeMessagingHosts\$hostName"
    $braveReg  = "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$hostName"

    & reg add $chromeReg /ve /t REG_SZ /d $manifestOutPath /f | Out-Null
    Write-Info "Registered native host for Chrome: $chromeReg -> $manifestOutPath"

    & reg add $braveReg /ve /t REG_SZ /d $manifestOutPath /f | Out-Null
    Write-Info "Registered native host for Brave: $braveReg -> $manifestOutPath"

    # Also register machine-level if running elevated
    if ($isAdmin) {
      $chromeRegMachine = "HKLM\Software\Google\Chrome\NativeMessagingHosts\$hostName"
      $braveRegMachine  = "HKLM\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$hostName"
      & reg add $chromeRegMachine /ve /t REG_SZ /d $manifestOutPath /f | Out-Null
      Write-Info "Registered native host for Chrome (machine): $chromeRegMachine -> $manifestOutPath"
      & reg add $braveRegMachine /ve /t REG_SZ /d $manifestOutPath /f | Out-Null
      Write-Info "Registered native host for Brave (machine): $braveRegMachine -> $manifestOutPath"
    } else {
      Write-Warn "Not running as Administrator; skipping machine-level native host registration."
    }
  } else {
    Write-Warn "Manifest source not found at $manifestSrc"
  }
} catch {
  Write-Warn "Failed to install manifest or update registry: $($_.Exception.Message)"
}

# Register ExtensionInstallForceList policies (optional auto-install of extension)
if ($ChromeExtensionId -or $BraveExtensionId) {
  $pairChrome = if ($ChromeExtensionId) { "$ChromeExtensionId;$UpdateUrl" } else { $null }
  $pairBrave  = if ($BraveExtensionId)   { "$BraveExtensionId;$UpdateUrl" } else { $null }

  $applyMachine = [bool]$MachinePolicy
  $applyUser    = [bool]$UserPolicy
  if (-not $applyMachine -and -not $applyUser) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { $applyMachine = $true } else { $applyUser = $true }
    Write-Info ("No policy scope specified; defaulting to {0}-level policies." -f ($isAdmin ? 'machine' : 'user'))
  }

  if ($applyMachine) {
    if ($pairChrome) {
      $key = 'HKLM:SOFTWARE\Policies\Google\Chrome\ExtensionInstallForceList'
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name '1' -Value $pairChrome -PropertyType String -Force | Out-Null
      Write-Info "Configured machine policy for Chrome ExtensionInstallForceList: $pairChrome"
    }
    if ($pairBrave) {
      $key = 'HKLM:SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForceList'
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name '1' -Value $pairBrave -PropertyType String -Force | Out-Null
      Write-Info "Configured machine policy for Brave ExtensionInstallForceList: $pairBrave"
    }
  }

  if ($applyUser) {
    if ($pairChrome) {
      $key = 'HKCU:SOFTWARE\Policies\Google\Chrome\ExtensionInstallForceList'
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name '1' -Value $pairChrome -PropertyType String -Force | Out-Null
      Write-Info "Configured user policy for Chrome ExtensionInstallForceList: $pairChrome"
    }
    if ($pairBrave) {
      $key = 'HKCU:SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForceList'
      New-Item -Path $key -Force | Out-Null
      New-ItemProperty -Path $key -Name '1' -Value $pairBrave -PropertyType String -Force | Out-Null
      Write-Info "Configured user policy for Brave ExtensionInstallForceList: $pairBrave"
    }
  }
}

Write-Info "Sync complete."