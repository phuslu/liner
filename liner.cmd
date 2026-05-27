rem =======================================================
rem Liner Windows system tray app
rem =======================================================
@echo off
setlocal
set "LINER_CMD_SELF=%~f0"
start "" powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$p=$env:LINER_CMD_SELF; $s=[IO.File]::ReadAllText($p); $m=([char]35)+' POWERSHELL_BEGIN'; $i=$s.IndexOf($m); if($i -lt 0){throw 'PowerShell marker not found'}; iex $s.Substring($i + $m.Length)"
exit /b
# POWERSHELL_BEGIN
$ErrorActionPreference = 'Stop'

$script:ScriptPath = [Environment]::GetEnvironmentVariable('LINER_CMD_SELF')
if (-not $script:ScriptPath) {
    $script:ScriptPath = $PSCommandPath
}
if (-not $script:ScriptPath) {
    $script:ScriptPath = $MyInvocation.MyCommand.Path
}

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'liner.cmd requires Windows.'
    exit 1
}

if ($PSVersionTable.PSVersion.Major -lt 5 -or $PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Error 'liner.cmd requires Windows PowerShell 5.1 Desktop Edition.'
    exit 1
}

if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if (-not $script:ScriptPath) {
        Write-Error 'Cannot resolve liner.cmd path for STA relaunch.'
        exit 1
    }
    [Environment]::SetEnvironmentVariable('LINER_CMD_SELF', $script:ScriptPath, 'Process')
    Start-Process -FilePath 'powershell.exe' -ArgumentList @(
        '-NoProfile',
        '-STA',
        '-ExecutionPolicy',
        'Bypass',
        '-WindowStyle',
        'Hidden',
        '-Command',
        '$p=$env:LINER_CMD_SELF; $s=[IO.File]::ReadAllText($p); $m=([char]35)+'' POWERSHELL_BEGIN''; $i=$s.IndexOf($m); if($i -lt 0){throw ''PowerShell marker not found''}; iex $s.Substring($i + $m.Length)'
    )
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if (-not ([System.Management.Automation.PSTypeName]'LinerNativeMethods').Type) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class LinerNativeMethods
{
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, int Msg, UIntPtr wParam, string lParam, int fuFlags, int uTimeout, out UIntPtr lpdwResult);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AttachConsole(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeConsole();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EmptyWorkingSet(IntPtr hProcess);
}
'@
}

[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$script:ChildBin = 'liner.exe'
$script:AppTitle = 'Liner'
$script:IgnoredProfileFiles = @('example.yaml')
$script:InternetSettingsPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$script:ChildStopTimeoutMs = 5000
$script:WorkingSetTrimInterval = [TimeSpan]::FromMinutes(10)

$script:WorkDir = Split-Path -Parent $script:ScriptPath
$script:Profiles = @()
$script:ProfilesSignature = ''
$script:SelectedProfile = $null
$script:ChildProcess = $null
$script:ChildConsoleHandle = [IntPtr]::Zero
$script:ExpectedStopPids = @{}
$script:LastWorkingSetTrim = [datetime]::MinValue

$script:TrayIcon = $null
$script:TrayIconRunning = $null
$script:TrayIconStopped = $null
$script:AppContext = $null
$script:ContextMenu = $null
$script:ConsoleItem = $null
$script:ProfileMenu = $null
$script:ProfileItems = @{}
$script:NetworkMenu = $null
$script:ProxyDisableItem = $null
$script:ProxyPacItem = $null
$script:ProxyManualItem = $null
$script:PreferencesItem = $null
$script:StartStopItem = $null
$script:Timer = $null

function Show-ErrorMessage {
    param([string]$Message)
    if ($script:TrayIcon) {
        $script:TrayIcon.BalloonTipTitle = $script:AppTitle
        $script:TrayIcon.BalloonTipText = $Message
        $script:TrayIcon.ShowBalloonTip(5000)
    }
    [System.Windows.Forms.MessageBox]::Show(
        $Message,
        $script:AppTitle,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
}

function Show-Notice {
    param(
        [string]$Title,
        [string]$Message
    )
    if (-not $script:TrayIcon) {
        return
    }
    $script:TrayIcon.BalloonTipTitle = $Title
    $script:TrayIcon.BalloonTipText = $Message
    $script:TrayIcon.ShowBalloonTip(3000)
}

function Invoke-UiAction {
    param([scriptblock]$Action)
    try {
        & $Action
    } catch {
        Show-ErrorMessage $_.Exception.Message
    }
}

function Invoke-WorkingSetTrim {
    try {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        [LinerNativeMethods]::EmptyWorkingSet([LinerNativeMethods]::GetCurrentProcess()) | Out-Null
    } catch {
    } finally {
        $script:LastWorkingSetTrim = [datetime]::UtcNow
    }
}

function Strip-MatchingQuotes {
    param([string]$Value)
    if ($null -eq $Value) {
        return ''
    }
    if ($Value.Length -ge 2 -and $Value[0] -eq $Value[$Value.Length - 1] -and ($Value[0] -eq '"' -or $Value[0] -eq "'")) {
        return $Value.Substring(1, $Value.Length - 2)
    }
    return $Value
}

function Strip-YamlComment {
    param([string]$Value)
    if ($null -eq $Value) {
        return ''
    }
    return ($Value -split '#', 2)[0].Trim()
}

function Clean-YamlScalar {
    param([string]$Value)
    $clean = Strip-YamlComment $Value
    if (-not $clean -or $clean -eq '|' -or $clean -eq '>') {
        return $null
    }
    return (Strip-MatchingQuotes $clean).Trim()
}

function Get-UrlHost {
    param([string]$HostName)
    if ($HostName -like '*:*' -and -not $HostName.StartsWith('[') -and -not $HostName.EndsWith(']')) {
        return '[' + $HostName + ']'
    }
    return $HostName
}

function New-ProxySettings {
    param(
        [string]$HostName,
        [string]$Port,
        [string]$PacUrl
    )
    [pscustomobject]@{
        Host = $HostName
        Port = $Port
        PacUrl = $PacUrl
        Address = ('{0}:{1}' -f (Get-UrlHost $HostName), $Port)
    }
}

function Test-LinerProfileFile {
    param([string]$Path)
    try {
        foreach ($rawLine in Get-Content -LiteralPath $Path -Encoding UTF8) {
            $line = $rawLine.Trim()
            if (-not $line -or $line.StartsWith('#')) {
                continue
            }
            return $line.StartsWith('global:')
        }
    } catch {
        return $false
    }
    return $false
}

function Scan-Profiles {
    if (-not (Test-Path -LiteralPath $script:WorkDir -PathType Container)) {
        return @()
    }
    $profiles = @()
    foreach ($entry in Get-ChildItem -LiteralPath $script:WorkDir -Filter '*.yaml' -File | Sort-Object Name) {
        if ($script:IgnoredProfileFiles -contains $entry.Name) {
            continue
        }
        if (Test-LinerProfileFile $entry.FullName) {
            $profiles += $entry.Name
        }
    }
    return $profiles
}

function Load-Profiles {
    $script:Profiles = @(Scan-Profiles)
    if ($script:Profiles.Count -eq 1) {
        $script:SelectedProfile = $script:Profiles[0]
    } elseif (-not ($script:Profiles -contains $script:SelectedProfile)) {
        $script:SelectedProfile = $null
    }
}

function Get-ProfilesSignature {
    if (-not (Test-Path -LiteralPath $script:WorkDir -PathType Container)) {
        return ''
    }

    $parts = @()
    foreach ($entry in Get-ChildItem -LiteralPath $script:WorkDir -Filter '*.yaml' -File | Sort-Object Name) {
        if ($script:IgnoredProfileFiles -contains $entry.Name) {
            continue
        }
        $parts += ('{0}|{1}|{2}' -f $entry.Name, $entry.Length, $entry.LastWriteTimeUtc.Ticks)
    }
    return ($parts -join "`n")
}

function Refresh-ProfilesIfChanged {
    $signature = Get-ProfilesSignature
    if ($signature -eq $script:ProfilesSignature) {
        return
    }

    $script:ProfilesSignature = $signature
    Load-Profiles
    Rebuild-ProfileMenu
}

function Get-ConfigDataPaths {
    param([string]$ConfigPath)
    $base = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName($ConfigPath),
        [System.IO.Path]::GetFileNameWithoutExtension($ConfigPath)
    )
    $overlayDir = $base + '.d'
    $paths = @($ConfigPath)
    if (Test-Path -LiteralPath $overlayDir -PathType Container) {
        foreach ($entry in Get-ChildItem -LiteralPath $overlayDir -Filter '*.yaml' -File | Sort-Object Name) {
            $paths += $entry.FullName
        }
    }
    return $paths
}

function Get-FirstListenScalar {
    param([string]$Raw)
    $value = Strip-YamlComment $Raw
    if ($value.StartsWith('[') -and $value.EndsWith(']')) {
        $value = $value.Trim('[', ']')
        if ($value) {
            $value = ($value -split ',', 2)[0]
        }
    }
    return Clean-YamlScalar $value
}

function Get-FirstHttpListen {
    param([string]$YamlText)
    $inHttp = $false
    $inListenBlock = $false

    foreach ($rawLine in ($YamlText -split "`r?`n")) {
        $trimmed = $rawLine.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }

        if (-not $inHttp) {
            if ($trimmed -eq 'http:' -or $trimmed.StartsWith('http: ')) {
                $inHttp = $true
            }
            continue
        }

        if ($rawLine.Length -gt 0 -and -not [char]::IsWhiteSpace($rawLine[0]) -and -not $trimmed.StartsWith('- ')) {
            return [pscustomobject]@{ HasHttp = $true; Listen = $null }
        }

        if ($inListenBlock) {
            if ($trimmed.StartsWith('- ')) {
                $value = Clean-YamlScalar $trimmed.Substring(2)
                if ($value) {
                    return [pscustomobject]@{ HasHttp = $true; Listen = $value }
                }
            }
            if (-not $trimmed.StartsWith('#')) {
                $inListenBlock = $false
            }
        }

        if ($trimmed.StartsWith('- ')) {
            $candidate = $trimmed.Substring(2).Trim()
        } else {
            $candidate = $trimmed
        }
        if (-not $candidate.StartsWith('listen:')) {
            continue
        }

        $rawValue = $candidate.Substring('listen:'.Length).Trim()
        if (-not $rawValue) {
            $inListenBlock = $true
        } else {
            return [pscustomobject]@{ HasHttp = $true; Listen = (Get-FirstListenScalar $rawValue) }
        }
    }
    return [pscustomobject]@{ HasHttp = $inHttp; Listen = $null }
}

function Get-LineIndent {
    param([string]$RawLine)
    return $RawLine.Length - $RawLine.TrimStart().Length
}

function Normalize-WebLocation {
    param([string]$Location)
    if (-not $Location.StartsWith('/')) {
        return '/' + $Location
    }
    return $Location
}

function Test-PacLocation {
    param([string]$Location)
    if (-not $Location) {
        return $false
    }
    $path = ($Location -split '\?', 2)[0].ToLowerInvariant()
    return $path.EndsWith('.pac')
}

function Get-PacUrl {
    param(
        [string]$HostName,
        [string]$Port,
        [string]$Location
    )
    return 'http://{0}:{1}{2}' -f (Get-UrlHost $HostName), $Port, (Normalize-WebLocation $Location)
}

function Get-FirstHttpPacLocation {
    param([string]$YamlText)
    $inHttp = $false
    $inWeb = $false
    $webIndent = 0
    $webItemIndent = $null
    $webLocation = $null
    $webFile = $null
    $webHasIndex = $false

    $flushWebItem = {
        if (-not $webLocation -or -not $webHasIndex) {
            return $null
        }
        if ((Test-PacLocation $webLocation) -or ($webFile -and (Test-PacLocation $webFile))) {
            return Normalize-WebLocation $webLocation
        }
        return $null
    }

    foreach ($rawLine in ($YamlText -split "`r?`n")) {
        $trimmed = $rawLine.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }

        $indent = Get-LineIndent $rawLine
        if (-not $inHttp) {
            if ($trimmed -eq 'http:' -or $trimmed.StartsWith('http: ')) {
                $inHttp = $true
            }
            continue
        }

        if ($rawLine.Length -gt 0 -and -not [char]::IsWhiteSpace($rawLine[0]) -and -not $trimmed.StartsWith('- ')) {
            return & $flushWebItem
        }

        if ($inWeb -and $indent -le $webIndent) {
            $location = & $flushWebItem
            if ($location) {
                return $location
            }
            $inWeb = $false
            $webItemIndent = $null
            $webLocation = $null
            $webFile = $null
            $webHasIndex = $false
        }

        if ($trimmed.StartsWith('- ')) {
            $candidate = $trimmed.Substring(2).Trim()
        } else {
            $candidate = $trimmed
        }

        if ($inWeb) {
            if ($trimmed.StartsWith('- ') -and $indent -gt $webIndent) {
                if ($null -eq $webItemIndent) {
                    $webItemIndent = $indent
                }
                if ($indent -eq $webItemIndent) {
                    $location = & $flushWebItem
                    if ($location) {
                        return $location
                    }
                    $webLocation = $null
                    $webFile = $null
                    $webHasIndex = $false
                    $candidate = $trimmed.Substring(2).Trim()
                }
            }

            if ($candidate.StartsWith('location:')) {
                $webLocation = Clean-YamlScalar $candidate.Substring('location:'.Length).Trim()
            } elseif ($candidate.StartsWith('index:')) {
                $webHasIndex = $true
            } elseif ($candidate.StartsWith('file:')) {
                $webFile = Clean-YamlScalar $candidate.Substring('file:'.Length).Trim()
            }

            $location = & $flushWebItem
            if ($location) {
                return $location
            }
            continue
        }

        if ($candidate.StartsWith('web:')) {
            $inWeb = $true
            $webIndent = $indent
            $webItemIndent = $null
            $webLocation = $null
            $webFile = $null
            $webHasIndex = $false
        }
    }

    if ($inHttp) {
        return & $flushWebItem
    }
    return $null
}

function Get-ProxyHostForListenHost {
    param([string]$HostName)
    $trimmed = $HostName.Trim()
    if (-not $trimmed -or $trimmed -eq '*' -or $trimmed -eq '0.0.0.0' -or $trimmed -eq '::' -or $trimmed -eq '::0') {
        return '127.0.0.1'
    }
    return $trimmed
}

function Get-ProxySettingsFromListen {
    param([string]$RawListen)
    $listen = $RawListen.Trim()
    if ($listen.Contains('://')) {
        $listen = ($listen -split '://', 2)[1]
    }
    if ($listen.Contains('/')) {
        $listen = ($listen -split '/', 2)[0]
    }
    if ($listen.Contains('?')) {
        $listen = ($listen -split '\?', 2)[0]
    }

    $hostName = ''
    $port = ''
    if ($listen.StartsWith('[') -and $listen.Contains(']')) {
        $close = $listen.IndexOf(']')
        $hostName = $listen.Substring(1, $close - 1)
        $rest = $listen.Substring($close + 1)
        if (-not $rest.StartsWith(':')) {
            return $null
        }
        $port = $rest.Substring(1)
    } elseif ($listen.Contains(':')) {
        $index = $listen.LastIndexOf(':')
        $hostName = $listen.Substring(0, $index)
        $port = $listen.Substring($index + 1)
    } elseif ($listen -match '^\d+$') {
        $hostName = ''
        $port = $listen
    } else {
        return $null
    }

    $portNumber = 0
    if (-not [int]::TryParse($port, [ref]$portNumber)) {
        return $null
    }
    if ($portNumber -lt 1 -or $portNumber -gt 65535) {
        return $null
    }

    return New-ProxySettings (Get-ProxyHostForListenHost $hostName) ([string]$portNumber) $null
}

function Get-ProxySettingsUnavailableTooltip {
    if (-not $script:SelectedProfile) {
        return 'No profile selected'
    }
    $config = Inspect-ProxyConfig
    if (-not $config.HasHttp) {
        return 'No http: section in selected profile'
    }
    return 'No HTTP listen address found'
}

function Get-ProxyPacUnavailableTooltip {
    return "No .pac web location in selected profile's http: section"
}

function Inspect-ProxyConfig {
    if (-not $script:SelectedProfile) {
        return [pscustomobject]@{ HasHttp = $false; Settings = $null }
    }

    $hasHttp = $false
    $settings = $null
    $pacLocation = $null
    $configPath = Join-Path $script:WorkDir $script:SelectedProfile
    foreach ($path in Get-ConfigDataPaths $configPath) {
        try {
            $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        } catch {
            continue
        }
        $listenInfo = Get-FirstHttpListen $content
        $hasHttp = $hasHttp -or [bool]$listenInfo.HasHttp
        if (-not $settings -and $listenInfo.Listen) {
            $settings = Get-ProxySettingsFromListen $listenInfo.Listen
        }
        if (-not $pacLocation) {
            $pacLocation = Get-FirstHttpPacLocation $content
        }
    }
    if ($settings -and $pacLocation) {
        $settings.PacUrl = Get-PacUrl $settings.Host $settings.Port $pacLocation
    }
    return [pscustomobject]@{ HasHttp = $hasHttp; Settings = $settings }
}

function Set-RegDword {
    param(
        [string]$Name,
        [int]$Value
    )
    New-ItemProperty -LiteralPath $script:InternetSettingsPath -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegString {
    param(
        [string]$Name,
        [string]$Value
    )
    New-ItemProperty -LiteralPath $script:InternetSettingsPath -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Remove-RegValue {
    param([string]$Name)
    Remove-ItemProperty -LiteralPath $script:InternetSettingsPath -Name $Name -ErrorAction SilentlyContinue
}

function Invoke-InternetSettingsChanged {
    [LinerNativeMethods]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [LinerNativeMethods]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    $result = [UIntPtr]::Zero
    [LinerNativeMethods]::SendMessageTimeout([IntPtr]65535, 0x001A, [UIntPtr]::Zero, 'Internet Settings', 0x0002, 5000, [ref]$result) | Out-Null
}

function Get-SystemProxyMode {
    try {
        $settings = Get-ItemProperty -LiteralPath $script:InternetSettingsPath -ErrorAction Stop
    } catch {
        return $null
    }

    if ($settings.AutoConfigURL) {
        return 'pac'
    }
    if (($settings.ProxyEnable -as [int]) -ne 0) {
        return 'http'
    }
    return 'off'
}

function Set-SystemProxy {
    param(
        [string]$Mode,
        $Settings
    )

    New-Item -Path $script:InternetSettingsPath -Force | Out-Null
    switch ($Mode) {
        'off' {
            Set-RegDword 'ProxyEnable' 0
            Set-RegDword 'AutoDetect' 0
            Remove-RegValue 'ProxyServer'
            Remove-RegValue 'AutoConfigURL'
        }
        'pac' {
            if (-not $Settings -or -not $Settings.PacUrl) {
                throw 'missing proxy settings'
            }
            Set-RegDword 'ProxyEnable' 0
            Set-RegDword 'AutoDetect' 0
            Remove-RegValue 'ProxyServer'
            Set-RegString 'AutoConfigURL' $Settings.PacUrl
        }
        'http' {
            if (-not $Settings) {
                throw 'missing proxy settings'
            }
            Set-RegDword 'ProxyEnable' 1
            Set-RegDword 'AutoDetect' 0
            Remove-RegValue 'AutoConfigURL'
            Set-RegString 'ProxyServer' ('http={0};https={0}' -f $Settings.Address)
        }
        default {
            throw "unsupported proxy mode: $Mode"
        }
    }

    Invoke-InternetSettingsChanged
    return @('Current user WinINet')
}

function Test-ChildRunning {
    if (-not $script:ChildProcess) {
        return $false
    }
    try {
        return -not $script:ChildProcess.HasExited
    } catch {
        return $false
    }
}

function Get-ChildAttachedConsoleWindow {
    if (-not (Test-ChildRunning)) {
        return [IntPtr]::Zero
    }

    [LinerNativeMethods]::FreeConsole() | Out-Null
    try {
        if (-not [LinerNativeMethods]::AttachConsole([uint32]$script:ChildProcess.Id)) {
            return [IntPtr]::Zero
        }
        return [LinerNativeMethods]::GetConsoleWindow()
    } finally {
        [LinerNativeMethods]::FreeConsole() | Out-Null
    }
}

function Get-ChildConsoleHandle {
    if (-not (Test-ChildRunning)) {
        $script:ChildConsoleHandle = [IntPtr]::Zero
        return [IntPtr]::Zero
    }

    if ($script:ChildConsoleHandle -ne [IntPtr]::Zero -and [LinerNativeMethods]::IsWindow($script:ChildConsoleHandle)) {
        return $script:ChildConsoleHandle
    }

    $script:ChildProcess.Refresh()
    $handle = $script:ChildProcess.MainWindowHandle
    if ($handle -ne [IntPtr]::Zero -and [LinerNativeMethods]::IsWindow($handle)) {
        $script:ChildConsoleHandle = $handle
        return $handle
    }

    $handle = Get-ChildAttachedConsoleWindow
    if ($handle -ne [IntPtr]::Zero -and [LinerNativeMethods]::IsWindow($handle)) {
        $script:ChildConsoleHandle = $handle
        return $handle
    }

    $script:EnumWindowTargetPid = [uint32]$script:ChildProcess.Id
    $script:EnumWindowFoundHandle = [IntPtr]::Zero
    $callback = [LinerNativeMethods+EnumWindowsProc]{
        param([IntPtr]$windowHandle, [IntPtr]$lParam)
        $windowPid = [uint32]0
        [LinerNativeMethods]::GetWindowThreadProcessId($windowHandle, [ref]$windowPid) | Out-Null
        if ($windowPid -eq $script:EnumWindowTargetPid) {
            $script:EnumWindowFoundHandle = $windowHandle
            return $false
        }
        return $true
    }
    [LinerNativeMethods]::EnumWindows($callback, [IntPtr]::Zero) | Out-Null
    $found = $script:EnumWindowFoundHandle
    Remove-Variable -Name EnumWindowFoundHandle -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name EnumWindowTargetPid -Scope Script -ErrorAction SilentlyContinue

    if ($found -ne [IntPtr]::Zero -and [LinerNativeMethods]::IsWindow($found)) {
        $script:ChildConsoleHandle = $found
        return $found
    }

    return [IntPtr]::Zero
}

function Test-ChildConsoleVisible {
    $handle = Get-ChildConsoleHandle
    return $handle -ne [IntPtr]::Zero -and [LinerNativeMethods]::IsWindowVisible($handle)
}

function Show-ChildConsole {
    if (-not (Test-ChildRunning)) {
        Show-Notice $script:AppTitle 'liner is not running.'
        return
    }
    $handle = Get-ChildConsoleHandle
    if ($handle -eq [IntPtr]::Zero) {
        Show-Notice $script:AppTitle 'Console window is not available yet.'
        return
    }
    [LinerNativeMethods]::ShowWindow($handle, 5) | Out-Null
    [LinerNativeMethods]::ShowWindow($handle, 9) | Out-Null
    [LinerNativeMethods]::SetForegroundWindow($handle) | Out-Null
}

function Hide-ChildConsole {
    if (-not (Test-ChildRunning)) {
        Show-Notice $script:AppTitle 'liner is not running.'
        return
    }
    $handle = Get-ChildConsoleHandle
    if ($handle -eq [IntPtr]::Zero) {
        Show-Notice $script:AppTitle 'Console window is not available yet.'
        return
    }
    [LinerNativeMethods]::ShowWindow($handle, 0) | Out-Null
}

function Toggle-ChildConsole {
    if (Test-ChildConsoleVisible) {
        Hide-ChildConsole
    } else {
        Show-ChildConsole
    }
    Update-ConsoleMenuState
}

function Update-ConsoleMenuState {
    if (-not $script:ConsoleItem) {
        return
    }
    $running = Test-ChildRunning
    $script:ConsoleItem.Enabled = $running
    if ($running -and (Test-ChildConsoleVisible)) {
        $script:ConsoleItem.Text = 'Hide Console'
    } else {
        $script:ConsoleItem.Text = 'Show Console'
    }
}

function Update-ProcessMenuState {
    $running = Test-ChildRunning
    if ($script:TrayIcon) {
        if ($running -and $script:TrayIconRunning) {
            $script:TrayIcon.Icon = $script:TrayIconRunning
        } elseif ($script:TrayIconStopped) {
            $script:TrayIcon.Icon = $script:TrayIconStopped
        }
    }

    if (-not $script:StartStopItem) {
        return
    }

    if ($running) {
        $script:StartStopItem.Text = 'Stop'
    } else {
        $script:StartStopItem.Text = 'Start'
    }
    Update-ConsoleMenuState
}

function Update-ProfileMenuState {
    foreach ($profile in $script:ProfileItems.Keys) {
        $script:ProfileItems[$profile].Checked = ($profile -eq $script:SelectedProfile)
    }
    if ($script:PreferencesItem) {
        $script:PreferencesItem.Enabled = [bool]$script:SelectedProfile
    }
}

function Rebuild-ProfileMenu {
    if (-not $script:ProfileMenu) {
        return
    }
    $script:ProfileMenu.DropDownItems.Clear()
    $script:ProfileItems = @{}

    if ($script:Profiles.Count -eq 0) {
        $item = New-Object System.Windows.Forms.ToolStripMenuItem
        $item.Text = 'No Liner Profiles'
        $item.Enabled = $false
        $script:ProfileMenu.DropDownItems.Add($item) | Out-Null
        return
    }

    foreach ($profile in $script:Profiles) {
        $item = New-Object System.Windows.Forms.ToolStripMenuItem
        $item.Text = $profile
        $item.CheckOnClick = $false
        $item.Tag = $profile
        $item.Add_Click({
            param($sender, $eventArgs)
            $profileName = [string]$sender.Tag
            Invoke-UiAction {
                if (-not ($script:Profiles -contains $profileName)) {
                    Load-Profiles
                    Rebuild-ProfileMenu
                    Update-ProfileMenuState
                    throw "Profile not found: $profileName"
                }
                $script:SelectedProfile = $profileName
                Update-ProfileMenuState
                Update-ProxyMenuState
                if (Test-ChildRunning) {
                    Show-Notice $script:AppTitle 'Restart liner to apply the selected profile.'
                }
            }
        })
        $script:ProfileItems[$profile] = $item
        $script:ProfileMenu.DropDownItems.Add($item) | Out-Null
    }
    Update-ProfileMenuState
}

function Update-ProxyMenuState {
    if (-not ($script:ProxyDisableItem -and $script:ProxyPacItem -and $script:ProxyManualItem)) {
        return
    }

    $running = Test-ChildRunning
    $settings = $null
    if ($running) {
        $settings = (Inspect-ProxyConfig).Settings
    }
    $script:ProxyPacItem.Enabled = [bool]($running -and $settings -and $settings.PacUrl)
    $script:ProxyManualItem.Enabled = [bool]($running -and $settings)
    if (-not $running) {
        $tooltip = 'liner is not running'
        $script:ProxyPacItem.ToolTipText = $tooltip
        $script:ProxyManualItem.ToolTipText = $tooltip
    } elseif ($settings) {
        if ($settings.PacUrl) {
            $script:ProxyPacItem.ToolTipText = $settings.PacUrl
        } else {
            $script:ProxyPacItem.ToolTipText = Get-ProxyPacUnavailableTooltip
        }
        $script:ProxyManualItem.ToolTipText = $settings.Address
    } else {
        $tooltip = Get-ProxySettingsUnavailableTooltip
        $script:ProxyPacItem.ToolTipText = $tooltip
        $script:ProxyManualItem.ToolTipText = $tooltip
    }

    $mode = $null
    try {
        $mode = Get-SystemProxyMode
    } catch {
        $mode = $null
    }

    $script:ProxyDisableItem.Checked = ($mode -eq 'off')
    $script:ProxyPacItem.Checked = ($mode -eq 'pac')
    $script:ProxyManualItem.Checked = ($mode -eq 'http')
}

function Apply-ProxyMode {
    param([string]$Mode)
    if ($Mode -eq 'off') {
        $settings = $null
    } else {
        if (-not (Test-ChildRunning)) {
            Update-ProxyMenuState
            throw 'System proxy mode unavailable: liner is not running.'
        }
        $settings = (Inspect-ProxyConfig).Settings
        if (-not $settings -or ($Mode -eq 'pac' -and -not $settings.PacUrl)) {
            Update-ProxyMenuState
            throw 'System proxy mode unavailable: selected profile has no usable proxy endpoint.'
        }
    }
    $services = Set-SystemProxy $Mode $settings
    Update-ProxyMenuState
    switch ($Mode) {
        'off' { $modeName = 'Disable' }
        'pac' { $modeName = 'PAC ' + $settings.PacUrl }
        default { $modeName = 'HTTP/HTTPS ' + $settings.Address }
    }
    Show-Notice $script:AppTitle ("Applied System Proxy '{0}' to: {1}" -f $modeName, ($services -join ', '))
}

function Start-Child {
    if (Test-ChildRunning) {
        Show-Notice $script:AppTitle 'liner is already running.'
        Update-ProcessMenuState
        Update-ProxyMenuState
        return $true
    }

    $binPath = Join-Path $script:WorkDir $script:ChildBin
    if (-not (Test-Path -LiteralPath $binPath -PathType Leaf)) {
        Update-ProcessMenuState
        throw "Cannot find executable: $binPath"
    }

    $configFile = $script:SelectedProfile
    if (-not $configFile) {
        Update-ProcessMenuState
        throw 'No profile selected. Choose one from Profiles in the tray menu.'
    }

    $configPath = Join-Path $script:WorkDir $configFile
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        Update-ProcessMenuState
        throw "Config file not found: $configPath"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $binPath
    $psi.WorkingDirectory = $script:WorkDir
    $psi.UseShellExecute = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
    $psi.Arguments = '"' + $configFile + '"'

    $process = [System.Diagnostics.Process]::Start($psi)
    if (-not $process) {
        Update-ProcessMenuState
        throw "Failed to start $script:ChildBin"
    }

    $script:ChildProcess = $process
    $script:ChildConsoleHandle = [IntPtr]::Zero
    Update-ProcessMenuState
    Update-ProxyMenuState
    Show-Notice $script:AppTitle 'Started.'
    return $true
}

function Stop-Child {
    $process = $script:ChildProcess
    if (-not $process) {
        Update-ProcessMenuState
        Update-ProxyMenuState
        return $true
    }

    $script:ExpectedStopPids[$process.Id] = $true
    try {
        if (-not $process.HasExited) {
            $closed = $false
            try {
                $closed = $process.CloseMainWindow()
            } catch {
                $closed = $false
            }
            if ($closed) {
                $process.WaitForExit($script:ChildStopTimeoutMs) | Out-Null
            }
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                try {
                    $process.WaitForExit(2000) | Out-Null
                } catch {
                }
            }
        }
    } finally {
        try {
            $process.Refresh()
            if ($process.HasExited -and $script:ChildProcess -eq $process) {
                $script:ChildProcess = $null
            }
        } catch {
            if ($script:ChildProcess -eq $process) {
                $script:ChildProcess = $null
            }
        }
        $script:ChildConsoleHandle = [IntPtr]::Zero
        Update-ProcessMenuState
        Update-ProxyMenuState
    }
    return $true
}

function Restart-Child {
    Stop-Child | Out-Null
    Start-Child | Out-Null
}

function Check-ChildProcess {
    if (-not $script:ChildProcess) {
        return
    }
    $process = $script:ChildProcess
    try {
        if (-not $process.HasExited) {
            return
        }
        $childPid = $process.Id
        $exitCode = $process.ExitCode
    } catch {
        $childPid = 0
        $exitCode = $null
    }

    $expected = $false
    if ($childPid -and $script:ExpectedStopPids.ContainsKey($childPid)) {
        $expected = $true
        $script:ExpectedStopPids.Remove($childPid)
    }
    $script:ChildProcess = $null
    $script:ChildConsoleHandle = [IntPtr]::Zero
    Update-ProcessMenuState
    Update-ProxyMenuState

    if (-not $expected) {
        if ($null -eq $exitCode) {
            $reason = 'exited'
        } else {
            $reason = 'exit status ' + $exitCode
        }
        Show-Notice $script:AppTitle ("liner stopped: {0}" -f $reason)
    }
}

function Edit-Config {
    if (-not $script:SelectedProfile) {
        throw 'No profile selected. Choose one from Profiles in the tray menu.'
    }
    $configPath = Join-Path $script:WorkDir $script:SelectedProfile
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Config file not found: $configPath"
    }
    Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $configPath) | Out-Null
}

function New-LinerIcon {
    param([bool]$Stopped = $false)

    $bitmap = New-Object System.Drawing.Bitmap 32, 32
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $pen = $null
    $nodeBrush = $null
    $hicon = [IntPtr]::Zero
    try {
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
        $graphics.Clear([System.Drawing.Color]::Transparent)

        $systemUsesLightTheme = 0
        try {
            $personalize = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction Stop
            $systemUsesLightTheme = [int]$personalize.SystemUsesLightTheme
        } catch {
            $systemUsesLightTheme = 0
        }

        if ($Stopped) {
            if ($systemUsesLightTheme -ne 0) {
                $glyphColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
            } else {
                $glyphColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
            }
        } elseif ($systemUsesLightTheme -ne 0) {
            $glyphColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
        } else {
            $glyphColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
        }

        $pen = New-Object System.Drawing.Pen $glyphColor, 3.8
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $nodeBrush = New-Object System.Drawing.SolidBrush $glyphColor

        $graphics.DrawLine($pen, 8, 10, 16, 10)
        $graphics.DrawLine($pen, 16, 10, 24, 16)
        $graphics.DrawLine($pen, 8, 22, 16, 22)
        $graphics.DrawLine($pen, 16, 22, 24, 16)

        $graphics.FillEllipse($nodeBrush, 4.25, 6.25, 7.5, 7.5)
        $graphics.FillEllipse($nodeBrush, 20.25, 12.25, 7.5, 7.5)
        $graphics.FillEllipse($nodeBrush, 4.25, 18.25, 7.5, 7.5)

        $hicon = $bitmap.GetHicon()
        $icon = [System.Drawing.Icon]::FromHandle($hicon)
        return ([System.Drawing.Icon]($icon.Clone()))
    } finally {
        if ($nodeBrush) {
            $nodeBrush.Dispose()
        }
        if ($pen) {
            $pen.Dispose()
        }
        if ($graphics) {
            $graphics.Dispose()
        }
        if ($hicon -ne [IntPtr]::Zero) {
            [LinerNativeMethods]::DestroyIcon($hicon) | Out-Null
        }
        if ($bitmap) {
            $bitmap.Dispose()
        }
    }
}

function Dispose-TrayResources {
    if ($script:TrayIcon) {
        try {
            $script:TrayIcon.Visible = $false
            $script:TrayIcon.Icon = $null
        } catch {
        }
        $script:TrayIcon.Dispose()
        $script:TrayIcon = $null
    }
    if ($script:TrayIconRunning) {
        $script:TrayIconRunning.Dispose()
        $script:TrayIconRunning = $null
    }
    if ($script:TrayIconStopped) {
        $script:TrayIconStopped.Dispose()
        $script:TrayIconStopped = $null
    }
}

function New-MenuItem {
    param(
        [string]$Text,
        [scriptblock]$Click
    )
    $item = New-Object System.Windows.Forms.ToolStripMenuItem
    $item.Text = $Text
    if ($Click) {
        $item.Add_Click({
            param($sender, $eventArgs)
            Invoke-UiAction $Click
        }.GetNewClosure())
    }
    return $item
}

function Setup-Tray {
    $script:TrayIconRunning = New-LinerIcon
    $script:TrayIconStopped = New-LinerIcon -Stopped $true

    $script:TrayIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:TrayIcon.Icon = $script:TrayIconStopped
    $script:TrayIcon.Text = $script:AppTitle
    $script:TrayIcon.Visible = $true
    $script:TrayIcon.Add_MouseClick({
        param($sender, $eventArgs)
        if ($eventArgs.Button -eq [System.Windows.Forms.MouseButtons]::Left) {
            Invoke-UiAction { Toggle-ChildConsole }
        }
    })

    $script:ContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $script:ContextMenu.Add_Opening({
        Invoke-UiAction {
            Refresh-ProfilesIfChanged
            Update-ProxyMenuState
            Update-ProcessMenuState
        }
    })

    $script:ConsoleItem = New-MenuItem 'Show Console' { Toggle-ChildConsole }
    $script:ContextMenu.Items.Add($script:ConsoleItem) | Out-Null
    $script:ContextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $script:ProfileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $script:ProfileMenu.Text = 'Profiles'
    $script:ContextMenu.Items.Add($script:ProfileMenu) | Out-Null
    Rebuild-ProfileMenu

    $script:NetworkMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $script:NetworkMenu.Text = 'Network'
    $script:ProxyDisableItem = New-MenuItem 'Disable' { Apply-ProxyMode 'off' }
    $script:ProxyPacItem = New-MenuItem 'Auto Configuration (PAC)' { Apply-ProxyMode 'pac' }
    $script:ProxyManualItem = New-MenuItem 'Manual (HTTP/HTTPS)' { Apply-ProxyMode 'http' }
    $script:NetworkMenu.DropDownItems.Add($script:ProxyDisableItem) | Out-Null
    $script:NetworkMenu.DropDownItems.Add($script:ProxyPacItem) | Out-Null
    $script:NetworkMenu.DropDownItems.Add($script:ProxyManualItem) | Out-Null
    $script:NetworkMenu.Add_DropDownOpening({ Invoke-UiAction { Update-ProxyMenuState } })
    $script:ContextMenu.Items.Add($script:NetworkMenu) | Out-Null
    $script:ContextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $script:PreferencesItem = New-MenuItem 'Preferences...' { Edit-Config }
    $script:ContextMenu.Items.Add($script:PreferencesItem) | Out-Null
    $script:ContextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null

    $script:StartStopItem = New-MenuItem 'Start' {
        if (Test-ChildRunning) {
            Stop-Child | Out-Null
            Show-Notice $script:AppTitle 'Stopped.'
        } else {
            Start-Child | Out-Null
            Show-ChildConsole
        }
    }
    $script:ContextMenu.Items.Add($script:StartStopItem) | Out-Null
    $script:ContextMenu.Items.Add((New-MenuItem 'Restart' {
        Restart-Child
        Show-ChildConsole
        Show-Notice $script:AppTitle 'Restarted.'
    })) | Out-Null
    $script:ContextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator)) | Out-Null
    $script:ContextMenu.Items.Add((New-MenuItem ('Quit ' + $script:AppTitle) {
        Stop-Child | Out-Null
        Dispose-TrayResources
        if ($script:Timer) {
            $script:Timer.Stop()
            $script:Timer.Dispose()
            $script:Timer = $null
        }
        $script:AppContext.ExitThread()
    })) | Out-Null

    $script:TrayIcon.ContextMenuStrip = $script:ContextMenu
    Update-ProxyMenuState
    Update-ProfileMenuState
    Update-ProcessMenuState
}

$script:ProfilesSignature = Get-ProfilesSignature
Load-Profiles

$script:AppContext = New-Object System.Windows.Forms.ApplicationContext
Setup-Tray
Invoke-WorkingSetTrim

$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 1000
$script:Timer.Add_Tick({
    Invoke-UiAction {
        Check-ChildProcess
        if (([datetime]::UtcNow - $script:LastWorkingSetTrim) -ge $script:WorkingSetTrimInterval) {
            Invoke-WorkingSetTrim
        }
    }
})
$script:Timer.Start()

try {
    [System.Windows.Forms.Application]::Run($script:AppContext)
} finally {
    try {
        Stop-Child | Out-Null
    } catch {
    }
    Dispose-TrayResources
}
