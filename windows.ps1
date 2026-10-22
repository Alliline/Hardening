<#
.SYNOPSIS
    Windows 11 Ultimate Security Hardening & Environment Provisioning Script (v3.4 - 2026 Edition)
.DESCRIPTION
    Aggressive security hardening for Windows 11 26H2+.
.NOTES
    Run as Administrator in PowerShell 5.1 or 7+.
    Usage:
        .\windows.ps1 -Mode Audit
        .\windows.ps1 -Mode Apply -SSHPort 2222 -AllowedLocalSubnet "192.168.1.0/24"
        .\windows.ps1 -Mode Apply -CreateRestorePoint
    Effective usage (skip policy error):
    powershell.exe -ExecutionPolicy Bypass -File "C:\windows.ps1" -Mode Apply
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Audit', 'Apply')]
    [string]$Mode = 'Apply',

    [Parameter()]
    [int]$SSHPort = 4444,

    [Parameter()]
    [string]$AllowedLocalSubnet = "10.10.10.0/24",

    [Parameter()]
    [switch]$CreateRestorePoint
)

$ErrorActionPreference = 'Stop'
$LogFile = "C:\Windows\Logs\Windows11-Hardening-$((Get-Date).ToString('yyyyMMdd-HHmmss')).log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FormattedMessage = "[$Timestamp] [$Level] $Message"
    $Color = switch ($Level) {
        "OK"      { "Green" }
        "APPLIED" { "Cyan" }
        "WARN"    { "Yellow" }
        "FAIL"    { "Red" }
        "AUDIT"   { "Magenta" }
        default   { "White" }
    }
    Write-Host $FormattedMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $FormattedMessage -ErrorAction SilentlyContinue
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][object]$Value,
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$Type = 'DWord',
        [switch]$Optional
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($key.GetValueNames() -contains $Name) {
            Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -Force -ErrorAction Stop
        } else {
            New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        $actual = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        $isNumeric = $Type -in @('DWord', 'QWord')
        if ($isNumeric) {
            if ([uint64]$actual -ne [uint64]$Value) { throw "Verification failed: expected '$Value', got '$actual'." }
        } else {
            if ("$actual" -ne "$Value") { throw "Verification failed: expected '$Value', got '$actual'." }
        }
    }
    catch {
        $errMsg = "$_"
        if ($errMsg -match 'unauthorized|access is denied|0x80070005') {
            # Some shell-owned values (e.g. TaskbarDa) are blocked for the
            # Registry provider; reg.exe sometimes succeeds where Set-ItemProperty fails.
            $regType = switch ($Type) {
                'String'       { 'REG_SZ' }
                'ExpandString' { 'REG_EXPAND_SZ' }
                'Binary'       { 'REG_BINARY' }
                'DWord'        { 'REG_DWORD' }
                'MultiString'  { 'REG_MULTI_SZ' }
                'QWord'        { 'REG_QWORD' }
                default        { 'REG_DWORD' }
            }
            $hive = if ($Path -match '^HKCU:') { 'HKCU' } elseif ($Path -match '^HKLM:') { 'HKLM' } else { $null }
            if ($hive) {
                # Strip the provider prefix AND any leading backslash so we don't
                # end up with a double slash like HKCU\\Software\...
                $regPath = $Path -replace '^HK..:', '' -replace '^\\+', ''
                $regValue = if ($Type -in @('DWord','QWord')) { "$([uint64]$Value)" } else { "$Value" }
                # Run reg.exe via cmd.exe with native 2>nul redirection. This keeps
                # reg.exe stderr out of PowerShell entirely, so $ErrorActionPreference
                # = 'Stop' cannot promote it into a terminating/displayed
                # NativeCommandError. cmd /c propagates reg.exe's exit code to
                # $LASTEXITCODE, so success/failure detection still works.
                & cmd.exe /c "reg add `"$hive\$regPath`" /v `"$Name`" /t $regType /d `"$regValue`" /f 2>nul" | Out-Null
                $regExitCode = $LASTEXITCODE
                if ($regExitCode -eq 0) {
                    Write-Log "Registry write applied via reg.exe fallback: $Path\$Name" 'APPLIED'
                    return
                }
            }
            Write-Log "Registry write skipped (protected/optional): $Path\$Name : $errMsg" 'WARN'
        } elseif ($Optional) {
            Write-Log "Registry write skipped (optional): $Path\$Name : $errMsg" 'WARN'
        } else {
            Write-Log "Registry write failed: $Path\$Name : $errMsg" 'FAIL'
        }
    }
}

function Set-ServiceStartupType {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('auto','demand','disabled','delayed-auto')][string]$StartupType
    )
    try {
        & sc.exe config $Name start= $StartupType 2>$null | Out-Null
    } catch {
        Write-Log "Failed to set service $Name startup to $StartupType : $_" 'WARN'
    }
}

# FIX v3.4: Non-blocking service stop via sc.exe (does not wait for STOP_PENDING)
function Stop-ServiceSafe {
    param([Parameter(Mandatory=$true)][string]$Name)
    try {
        & sc.exe stop $Name 2>$null | Out-Null
    } catch {
        # ignore — service may not exist or be already stopped
    }
}

function Test-IsWindows11OrLater {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return [version]$os.Version -ge [version]"10.0.22000"
}

# --- Admin check ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Log "=== Windows 11 Ultimate Security Hardening v3.4 (2026) ===" "INFO"
Write-Log "Mode: $Mode | Host: $env:COMPUTERNAME | User: $env:USERNAME" "INFO"
Write-Log "OS Version: $((Get-CimInstance Win32_OperatingSystem).Version)" "INFO"

if (-not (Test-IsWindows11OrLater)) {
    Write-Log "This script is designed for Windows 11 26H2 and later." "WARN"
}

# ===========================================================================
# 0. Restore Point
# ===========================================================================
if ($Mode -eq 'Apply' -and $CreateRestorePoint) {
    Write-Log "--- 0. Creating System Restore Point ---" "INFO"
    try {
        $vss = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($vss -and $vss.Status -ne 'Running') { Start-Service -Name VSS -ErrorAction SilentlyContinue }
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Before Windows11 Hardening v3.4" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "System Restore Point created." "OK"
    } catch {
        Write-Log "Failed to create restore point: $_" "WARN"
    }
}

# ===========================================================================
# 1. AI / Copilot / Recall + Bloatware Removal
# ===========================================================================
Write-Log "--- 1. Removing AI, Copilot, Recall and Bloatware ---" "INFO"

$BloatPackages = @(
    "Microsoft.Windows.Ai.Copilot.Provider","Microsoft.Copilot","Microsoft.Windows.Recall",
    "Microsoft.Windows.ClickToDo","Microsoft.AIFabric","Microsoft.AIExplorer",
    "Microsoft.WindowsAI","Microsoft.CopilotEdge","Microsoft.Edge.Copilot",
    "Microsoft.Office.Copilot","Microsoft.Office.AI","Microsoft.Paint.AI",
    "Microsoft.Notepad.AI","Microsoft.VoiceAccess.AI","MicrosoftWindows.Client.WebExperience",
    "Microsoft.Windows.Ai.ContentSafety","Microsoft.Windows.Ai.Platform","Microsoft.Windows.Passkeys",
    "Microsoft.MicrosoftStickyNotes","Microsoft.People","Microsoft.Wallet",
    "Microsoft.BingNews","Microsoft.BingWeather","Microsoft.BingSearch","Microsoft.BingTranslator",
    "Microsoft.BingFinancial","Microsoft.BingSports","Microsoft.MicrosoftOfficeHub",
    "Microsoft.GetHelp","Microsoft.Getstarted",
    "Microsoft.WindowsFeedbackHub","Microsoft.Windows.Tips","Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop","Microsoft.OutlookForWindows","Microsoft.SkypeApp",
    "MicrosoftTeams","MSTeams","Microsoft.XboxApp","Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay","Microsoft.GamingApp","Microsoft.XboxGameCallableUI",
    "Microsoft.ZuneMusic","Microsoft.ZuneVideo","Clipchamp.Clipchamp","Microsoft.MixedReality.Portal",
    "Microsoft.YourPhone","Microsoft.Windows.DevHome","Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.549981C3F5F10",
    "Yandex.Browser","Yandex.Music","Yandex.Disk","Yandex.Maps","Yandex.Weather","Yandex.Translate",
    "Microsoft.Windows.Camera","Microsoft.ScreenSketch","Microsoft.WindowsSoundRecorder",
    "MicrosoftCorporationII.QuickAssist","Microsoft.Windows.NarratorQuickStart",
    # FIX v3.4: added LinkedIn, WhatsApp, GetStarted variants
    "LinkedIn","Microsoft.LinkedIn",
    "WhatsApp","5319275A.WhatsAppDesktop",
    "Getstarted","GetStarted"
)

foreach ($pkg in $BloatPackages) {
    $installed   = @(Get-AppxPackage -AllUsers -Name "*$pkg*" -ErrorAction SilentlyContinue)
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -like "*$pkg*" })

    if ($installed.Count -eq 0 -and $provisioned.Count -eq 0) {
        Write-Log "Package already absent: $pkg" "OK"
        continue
    }

    $removable = @($installed | Where-Object {
        $_.InstallLocation -and
        $_.InstallLocation -notlike "*\SystemApps\*" -and
        -not $_.NonRemovable
    })

    if ($installed.Count -gt 0 -and $removable.Count -eq 0) {
        # Per-user removal is blocked, but the provisioned (image-level) package
        # can still be removed so that new user profiles won't get it.
        if ($provisioned.Count -gt 0 -and $Mode -eq 'Apply') {
            try {
                foreach ($prov in $provisioned) {
                    Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                }
                Write-Log "Protected SystemApp kept, provisioned package removed: $pkg" "APPLIED"
            } catch {
                Write-Log "Protected SystemApp; provisioned removal failed for $pkg : $_" "WARN"
            }
        } else {
            Write-Log "Package is a protected SystemApp (cannot remove per-user, skipping): $pkg" "WARN"
        }
        continue
    }

    if ($Mode -eq 'Apply') {
        try {
            if ($removable.Count -gt 0) {
                $removable | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            }
            foreach ($prov in $provisioned) {
                Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null
            }
            Write-Log "Removed package: $pkg" "APPLIED"
        } catch {
            Write-Log "Failed to remove $pkg : $_" "WARN"
        }
    } else {
        Write-Log "Package present (will be removed): $pkg" "AUDIT"
    }
}

# ===========================================================================
# 1.1. Win32 Yandex apps detection
# ===========================================================================
Write-Log "--- 1.1. Detecting Win32 Yandex applications ---" "INFO"

$UninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$YandexApps = foreach ($root in $UninstallRoots) {
    Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayName -match '(?i)\bYandex\b|Яндекс' } |
        Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, PSPath
}
$YandexApps = @($YandexApps | Sort-Object PSPath -Unique)

if ($YandexApps.Count -eq 0) {
    Write-Log "No registered Win32 Yandex applications found." "OK"
} else {
    foreach ($app in $YandexApps) {
        Write-Log ("Detected Win32 app: {0} {1} | Publisher: {2}" -f
            $app.DisplayName, $app.DisplayVersion, $app.Publisher) "AUDIT"
        if ($Mode -eq 'Apply') {
            Write-Log ("Manual uninstall required for: {0}. UninstallString: {1}" -f
                $app.DisplayName, $app.UninstallString) "WARN"
        }
    }
}

if ($Mode -eq 'Apply') {
    $cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    @(
        "ContentDeliveryAllowed","OemPreInstalledAppsEnabled","PreInstalledAppsEnabled",
        "PreInstalledAppsEverEnabled","SilentInstalledAppsEnabled","SubscribedContent-338387Enabled",
        "SubscribedContent-338388Enabled","SubscribedContent-338389Enabled","SubscribedContent-338393Enabled",
        "SubscribedContent-353694Enabled","SubscribedContent-353696Enabled","SubscribedContent-353698Enabled",
        "SystemPaneSuggestionsEnabled"
    ) | ForEach-Object { Set-RegistryValue -Path $cdmPath -Name $_ -Value 0 }
    Write-Log "Content Delivery Manager locked down (prevents bloat reinstall)" "APPLIED"
}

# ===========================================================================
# 2. Telemetry & Privacy Kill
# ===========================================================================
Write-Log "--- 2. Disabling Telemetry and Tracking (deep) ---" "INFO"

$TelemetryServices = @(
    "DiagTrack","dmwappushservice","WerSvc","PcaSvc","RetailDemo",
    "DiagnosticPolicyService","DPS","WdiServiceHost","WdiSystemHost",
    "OneSyncSvc","MessagingService","PimIndexMaintenanceSvc","UnistoreSvc",
    "UserDataSvc","WbioSrvc","wisvc","XblAuthManager","XblGameSave",
    "XboxNetApiSvc","XboxGipSvc"
)

foreach ($srv in $TelemetryServices) {
    $svc = Get-Service -Name $srv -ErrorAction SilentlyContinue
    if ($svc) {
        if ($Mode -eq 'Apply') {
            Stop-ServiceSafe -Name $srv          # FIX v3.4: non-blocking
            Set-ServiceStartupType -Name $srv -StartupType disabled
            Write-Log "Disabled service: $srv" "APPLIED"
        } else {
            Write-Log "Service state: $srv = $($svc.Status) / $($svc.StartType)" "AUDIT"
        }
    }
}

if ($Mode -eq 'Apply') {
    $dataCollectionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
    Set-RegistryValue -Path $dataCollectionPath -Name 'LimitDiagnosticLogCollection' -Value 1
    Set-RegistryValue -Path $dataCollectionPath -Name 'LimitDumpCollection' -Value 1
    Set-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' -Name 'ShowedToastAtLevel' -Value 1

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableGenerativeFill" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableImageCreator" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9C5A40DA-B965-4FC3-8781-88D50EF4C533}" -Name "ScenarioExecutionEnabled" -Value 0

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value 1

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Value 1

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0
    # HKCU\...\Advanced\TaskbarDa is ACL-protected by the shell; even reg.exe
    # returns "Access is denied". The policy key above already disables Widgets,
    # so skip the per-user value entirely.

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\OneDrive" -Name "DisablePersonalSync" -Value 1

    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        "\Microsoft\Windows\PI\Sqm-Tasks",
        "\Microsoft\Windows\NetTrace\GatherNetworkInfo",
        "\Microsoft\Windows\AppListBackup\Backup",
        "\Microsoft\Windows\Device Information\Device",
        "\Microsoft\Windows\Device Information\Device User",
        "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
        "\Microsoft\Windows\Diagnosis\Scheduled",
        "\Microsoft\Windows\Shell\FamilySafetyMonitor",
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask",
        "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
        "\Microsoft\Windows\Maps\MapsToastTask",
        "\Microsoft\Windows\Maps\MapsUpdateTask",
        "\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        "\Microsoft\Windows\WindowsUpdate\sih",
        "\Microsoft\Windows\WindowsUpdate\sihboot",
        "\Microsoft\Windows\Maintenance\WinSAT"
    )
    foreach ($task in $tasks) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }

    # hosts file — safe append with FileShare.ReadWrite + retries
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $telemetryHosts = @(
        "0.0.0.0 vortex.data.microsoft.com","0.0.0.0 vortex-win.data.microsoft.com",
        "0.0.0.0 settings-win.data.microsoft.com","0.0.0.0 de-v20.events.data.microsoft.com",
        "0.0.0.0 watson.telemetry.microsoft.com","0.0.0.0 telecommand.telemetry.microsoft.com",
        "0.0.0.0 modern.watson.data.microsoft.com","0.0.0.0 v10.events.data.microsoft.com",
        "0.0.0.0 v10c.events.data.microsoft.com","0.0.0.0 v10.vortex-win.data.microsoft.com",
        "0.0.0.0 self.events.data.microsoft.com","0.0.0.0 functional.events.data.microsoft.com",
        "0.0.0.0 watson.events.data.microsoft.com","0.0.0.0 umwatsonc.events.data.microsoft.com",
        "0.0.0.0 ceuswatcab01.blob.core.windows.net","0.0.0.0 ceuswatcab02.blob.core.windows.net",
        "0.0.0.0 eaus2watcab01.blob.core.windows.net","0.0.0.0 eaus2watcab02.blob.core.windows.net",
        "0.0.0.0 weus2watcab01.blob.core.windows.net","0.0.0.0 weus2watcab02.blob.core.windows.net",
        "0.0.0.0 fe3.delivery.dsp.mp.microsoft.com","0.0.0.0 skydrive.facets.live.net",
        "0.0.0.0 choice.microsoft.com","0.0.0.0 choice.microsoft.com.nsatc.net",
        "0.0.0.0 df.telemetry.microsoft.com","0.0.0.0 reports.wes.df.telemetry.microsoft.com",
        "0.0.0.0 services.wes.df.telemetry.microsoft.com","0.0.0.0 sqm.df.telemetry.microsoft.com",
        "0.0.0.0 telemetry.microsoft.com","0.0.0.0 telemetry.urs.microsoft.com",
        "0.0.0.0 diagnostics.support.microsoft.com"
    )

    try {
        $existingContent = [System.IO.File]::ReadAllText($hostsPath)
    } catch {
        $existingContent = (Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue)
    }

    $currentLines = ($existingContent -split "`r?`n")
    $toAdd = $telemetryHosts | Where-Object { $currentLines -notcontains $_ }

    if ($toAdd.Count -gt 0) {
        $appendBlock = "`r`n# Windows11-Hardening Telemetry Block $(Get-Date -Format 'yyyy-MM-dd')`r`n" +
                       ($toAdd -join "`r`n") + "`r`n"
        $written = $false
        for ($i = 1; $i -le 5; $i++) {
            try {
                $fs = [System.IO.FileStream]::new(
                    $hostsPath,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::ReadWrite
                )
                $sw = New-Object System.IO.StreamWriter($fs)
                $sw.Write($appendBlock)
                $sw.Flush()
                $sw.Close()
                $fs.Close()
                $written = $true
                break
            } catch {
                Write-Log "hosts file locked (attempt $i/5): $($_.Exception.Message)" "WARN"
                Start-Sleep -Milliseconds 800
            }
        }
        if ($written) {
            Write-Log "Telemetry domains blocked via hosts file ($($toAdd.Count) entries)" "APPLIED"
        } else {
            Write-Log "Could not update hosts file after 5 attempts." "WARN"
        }
    } else {
        Write-Log "Hosts file already contains all telemetry blocks." "OK"
    }

    $fwRules = @(
        @{ Name = "Block-DiagTrack-Outbound"; Program = "%SystemRoot%\System32\svchost.exe"; Service = "DiagTrack" },
        @{ Name = "Block-CompatTelRunner"; Program = "%SystemRoot%\System32\CompatTelRunner.exe" },
        @{ Name = "Block-DeviceCensus"; Program = "%SystemRoot%\System32\DeviceCensus.exe" },
        @{ Name = "Block-BackgroundInference"; Program = "%SystemRoot%\System32\AIFabricHost.exe" },
        @{ Name = "Block-WidgetsProcess"; Program = "%SystemRoot%\System32\Widgets.exe" }
    )
    foreach ($rule in $fwRules) {
        Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $params = @{
            DisplayName = $rule.Name; Direction = "Outbound"; Action = "Block"
            Profile = "Any"; Enabled = "True"; Program = $rule.Program
        }
        if ($rule.Service) { $params.Service = $rule.Service }
        New-NetFirewallRule @params -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Log "Outbound firewall rules for telemetry processes created" "APPLIED"
} else {
    Write-Log "Deep telemetry hardening would be applied" "AUDIT"
}

# ===========================================================================
# 3. IPv6 Disablement
# ===========================================================================
Write-Log "--- 3. Completely Disabling IPv6 ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF
    foreach ($srv in @("TeredoTunneling", "iphlpsvc")) {
        Stop-ServiceSafe -Name $srv          # FIX v3.4
        Set-ServiceStartupType -Name $srv -StartupType disabled
    }
    Get-NetAdapterBinding -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue |
        Disable-NetAdapterBinding -ErrorAction SilentlyContinue | Out-Null
    Write-Log "IPv6 completely disabled system-wide (DisabledComponents = 0xFF)" "APPLIED"
} else {
    Write-Log "IPv6 would be completely disabled" "AUDIT"
}

# ===========================================================================
# 4. Kernel & OS Hardening
# ===========================================================================
Write-Log "--- 4. Kernel & OS Hardening ---" "INFO"

if ($Mode -eq 'Apply') {
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($smb1Feature) {
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Log "SMB1Protocol feature disabled." "APPLIED"
    } else { Write-Log "SMB1Protocol feature not present. Skipping." "OK" }

    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction Stop }
    catch { Write-Log "Set-SmbServerConfiguration (SMB1) failed: $_" "WARN" }

    $psV2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
    if ($psV2Feature) {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Log "PowerShell v2 feature disabled." "APPLIED"
    } else { Write-Log "PowerShell v2 feature not present. Skipping." "OK" }

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -Value "RemoteSigned" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableModuleLogging" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableTranscripting" -Value 1

    foreach ($proto in @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    )) {
        Set-RegistryValue -Path $proto -Name "Enabled" -Value 0
    }
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0

    try { Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop }
    catch { Write-Log "Set-SmbServerConfiguration (Signing) failed: $_" "WARN" }

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "WasEnabledBy" -Value 1

    Write-Log "Core OS hardening applied" "APPLIED"
} else {
    Write-Log "Kernel hardening would be applied" "AUDIT"
}

# ===========================================================================
# 5. Windows Update manual mode
# ===========================================================================
Write-Log "--- 5. Disabling Automatic Windows Updates (Manual Mode) ---" "INFO"

if ($Mode -eq 'Apply') {
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }

    Set-RegistryValue -Path $wuPath -Name "NoAutoUpdate" -Value 1
    Set-RegistryValue -Path $wuPath -Name "AUOptions" -Value 2
    Set-RegistryValue -Path $wuPath -Name "AllowMUUpdateService" -Value 0

    # FIX v3.4: non-blocking stop, avoids infinite "Waiting for service..." loop
    Stop-ServiceSafe -Name wuauserv
    Set-ServiceStartupType -Name wuauserv -StartupType 'demand'

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0
    Stop-ServiceSafe -Name "DoSvc"          # FIX v3.4
    Set-ServiceStartupType -Name "DoSvc" -StartupType 'demand'

    try {
        Stop-ServiceSafe -Name "WaaSMedicSvc"   # FIX v3.4
        Set-ServiceStartupType -Name "WaaSMedicSvc" -StartupType disabled
        Write-Log "WaaSMedicSvc set to disabled (if permissions allowed)" "APPLIED"
    } catch {
        Write-Log "Could not fully disable WaaSMedicSvc (protected service): $_" "WARN"
    }

    $UpdateTaskPaths = @(
        "\Microsoft\Windows\WindowsUpdate\",
        "\Microsoft\Windows\UpdateOrchestrator\",
        "\Microsoft\Windows\WaaSMedic\",
        "\Microsoft\Windows\InstallService\"
    )

    foreach ($taskFolder in @(
        "$env:SystemRoot\System32\Tasks\Microsoft\Windows\UpdateOrchestrator",
        "$env:SystemRoot\System32\Tasks\Microsoft\Windows\WindowsUpdate",
        "$env:SystemRoot\System32\Tasks\Microsoft\Windows\WaaSMedic",
        "$env:SystemRoot\System32\Tasks\Microsoft\Windows\InstallService"
    )) {
        if (Test-Path -LiteralPath $taskFolder) {
            try {
                & takeown.exe /F $taskFolder /A /R 2>$null | Out-Null
                & icacls.exe $taskFolder /grant "Administrators:F" /T 2>$null | Out-Null
            } catch {
                Write-Log "Could not adjust permissions on ${taskFolder}: $_" "WARN"
            }
        }
    }

    foreach ($taskPath in $UpdateTaskPaths) {
        $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
        if (-not $tasks) { Write-Log "No tasks found in path: $taskPath" "OK"; continue }
        foreach ($task in $tasks) {
            $fullName = "$($task.TaskPath)$($task.TaskName)"
            try {
                if ($task.State -ne 'Disabled') {
                    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
                    Write-Log "Disabled scheduled task: $fullName" "APPLIED"
                }
            } catch {
                $msg = ("$_").Trim()
                if ($msg -match 'not found|0x80070490|0x80070002') {
                    # Task was removed between enumeration and disable — ignore.
                    continue
                }
                # Fallback: schtasks.exe can bypass ACLs that block the ScheduledTasks module.
                & schtasks.exe /Change /TN $fullName /DISABLE 2>$null | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Disabled scheduled task (schtasks fallback): $fullName" "APPLIED"
                } else {
                    Write-Log "Could not disable protected task (left as-is): $fullName : $msg" "WARN"
                }
            }
        }
    }
    Write-Log "Windows Update set to fully manual mode." "APPLIED"
} else {
    Write-Log "Windows Update auto-update would be disabled." "AUDIT"
}

# ===========================================================================
# 6. Network hardening & DoH
# ===========================================================================
Write-Log "--- 6. Reducing External Network Activity & Enabling DoH ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
        Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null
    }

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1

    foreach ($srv in @("SSDPSRV","upnphost","fdPHost","FDResPub","Spooler")) {
        Stop-ServiceSafe -Name $srv          # FIX v3.4
        Set-ServiceStartupType -Name $srv -StartupType disabled
    }

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2

    try {
        if (Get-Command Add-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
            $dohServers = @(
                @{ Address = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query" },
                @{ Address = "1.0.0.1"; Template = "https://cloudflare-dns.com/dns-query" }
            )
            foreach ($srv in $dohServers) {
                $existing = Get-DnsClientDohServerAddress -ServerAddress $srv.Address -ErrorAction SilentlyContinue
                if ($existing) {
                    Set-DnsClientDohServerAddress -ServerAddress $srv.Address -DohTemplate $srv.Template `
                        -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
                } else {
                    Add-DnsClientDohServerAddress -ServerAddress $srv.Address -DohTemplate $srv.Template `
                        -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
                }
            }

            # Registering DoH templates alone does not change the resolver.
            # Actively point all "Up" physical adapters at the DoH servers so the
            # policy actually takes effect. (WARNING: replaces DHCP-supplied DNS;
            # adjust if this host must use a domain controller / Pi-hole.)
            $dohIpv4 = @($dohServers | ForEach-Object { $_.Address })
            $dohApplied = 0
            Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
                    try {
                        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $dohIpv4 -ErrorAction Stop
                        $dohApplied++
                    } catch {
                        Write-Log "Could not set DoH DNS on $($_.Name): $_" "WARN"
                    }
                }
            Write-Log "DoH registered for Cloudflare; DNS set on $dohApplied adapter(s) (UDP fallback disabled)" "APPLIED"
        } else {
            Write-Log "DoH cmdlets not available. Skipping." "WARN"
        }
    } catch { Write-Log "DoH setup failed: $_" "WARN" }

    Write-Log "LLMNR, NetBIOS, WPAD, SSDP, UPnP, Discovery, Spooler disabled & DoH enabled" "APPLIED"
} else {
    Write-Log "Network hardening would be applied" "AUDIT"
}

# ===========================================================================
# 7. Firewall Lockdown
# ===========================================================================
Write-Log "--- 7. Firewall Hardening ---" "INFO"
if ($Mode -eq 'Apply') {
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Log "Firewall: DefaultInbound = Block on all profiles" "APPLIED"
} else { Write-Log "Firewall default inbound would be set to Block" "AUDIT" }

# ===========================================================================
# 8. OpenSSH Hardening
# ===========================================================================
Write-Log "--- 8. OpenSSH Server Hardening ---" "INFO"

$OpenSSHServer = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }
if ($OpenSSHServer.State -ne 'Installed') {
    if ($Mode -eq 'Apply') {
        Write-Log "Installing OpenSSH.Server..." "APPLIED"
        Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" | Out-Null
    } else { Write-Log "OpenSSH.Server is not installed (would be installed)" "AUDIT" }
}

if ($Mode -eq 'Apply') {
    Set-ServiceStartupType -Name sshd -StartupType auto
    Start-Service sshd -ErrorAction SilentlyContinue

    $SSHDConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $SSHDConfigPath) {
        try {
            $ConfigContent = Get-Content $SSHDConfigPath -Raw -ErrorAction Stop
            $ConfigContent = $ConfigContent -replace '(?m)^#?Port\s+\d+', "Port $SSHPort"
            $ConfigContent = $ConfigContent -replace '(?m)^#?PasswordAuthentication\s+\w+', "PasswordAuthentication no"
            $ConfigContent = $ConfigContent -replace '(?m)^#?PermitEmptyPasswords\s+\w+', "PermitEmptyPasswords no"
            $ConfigContent = $ConfigContent -replace '(?m)^#?PubkeyAuthentication\s+\w+', "PubkeyAuthentication yes"
            Set-Content -Path $SSHDConfigPath -Value $ConfigContent -Force -ErrorAction Stop
            Restart-Service sshd -ErrorAction Stop
            Write-Log "sshd_config hardened: Port=$SSHPort, PasswordAuthentication=no" "APPLIED"
        } catch {
            Write-Log "Failed to harden sshd_config: $_" "FAIL"
        }
    } else {
        Write-Log "sshd_config not found at $SSHDConfigPath" "WARN"
    }

        Get-NetFirewallRule -DisplayName "SSH-Custom-Port-Local" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "SSH-Custom-Port-Local" -Direction Inbound -Protocol TCP `
        -LocalPort $SSHPort -RemoteAddress $AllowedLocalSubnet -Action Allow -Profile Any -Confirm:$false | Out-Null
    Write-Log "Firewall rule: SSH $SSHPort only from $AllowedLocalSubnet" "APPLIED"

    # --- 8.1. Auto-import SSH public keys from script folder (admin-aware) ---
    $ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }

    $KeySources = @(
        (Join-Path $ScriptDir 'id_rsa.pub'),
        (Join-Path $ScriptDir 'authorized_keys')
    ) | Where-Object { Test-Path -LiteralPath $_ }

    $IncomingKeys = @()
    foreach ($src in $KeySources) {
        foreach ($line in (Get-Content -LiteralPath $src -ErrorAction SilentlyContinue)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            $p = $t -split '\s+', 3
            if ($p.Count -ge 2 -and $p[0] -match '^(ssh-|ecdsa-|sk-)') {
                $IncomingKeys += [pscustomobject]@{ Raw = $t; KeyId = "$($p[0]) $($p[1])" }
            }
        }
    }

    if ($IncomingKeys.Count -gt 0) {
        # Определяем, является ли текущий пользователь администратором
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        $TargetFiles = if ($isAdmin) {
            @("$env:ProgramData\ssh\administrators_authorized_keys")
        } else {
            @("$env:USERPROFILE\.ssh\authorized_keys")
        }

        # Собираем уже существующие ключи ТОЛЬКО из целевых файлов
        $ExistingKeyIds = @{}
        foreach ($tf in $TargetFiles) {
            if (Test-Path -LiteralPath $tf) {
                foreach ($line in (Get-Content -LiteralPath $tf -ErrorAction SilentlyContinue)) {
                    $t = $line.Trim()
                    if (-not $t -or $t.StartsWith('#')) { continue }
                    $p = $t -split '\s+', 3
                    if ($p.Count -ge 2) { $ExistingKeyIds["$($p[0]) $($p[1])"] = $true }
                }
            }
        }

        $NewKeys = @($IncomingKeys | Where-Object { -not $ExistingKeyIds.ContainsKey($_.KeyId) } | Sort-Object KeyId -Unique)

        if ($NewKeys.Count -eq 0) {
            Write-Log "SSH: all keys from script folder are already authorized in $($TargetFiles -join ', ')." "OK"
        } else {
            foreach ($tf in $TargetFiles) {
                $dir = Split-Path -Parent $tf
                if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
                $existing = @(Get-Content -LiteralPath $tf -ErrorAction SilentlyContinue)
                $addLines = @($NewKeys | ForEach-Object { $_.Raw })
                $content  = ((@($existing) + $addLines) -join "`r`n").TrimEnd() + "`r`n"
                [System.IO.File]::WriteAllText($tf, $content, [System.Text.UTF8Encoding]::new($false))
                Write-Log "SSH: added $($NewKeys.Count) key(s) to $tf" "APPLIED"
            }
            # Если писали в административный файл — сразу чиним ACL
            $AdmKeys = "$env:ProgramData\ssh\administrators_authorized_keys"
            if ($TargetFiles -contains $AdmKeys -and (Test-Path -LiteralPath $AdmKeys)) {
                & icacls.exe $AdmKeys /inheritance:r 2>$null | Out-Null
                & icacls.exe $AdmKeys /grant "*S-1-5-32-544:F" "*S-1-5-18:F" 2>$null | Out-Null
                & icacls.exe $AdmKeys /remove "*S-1-5-32-545" "*S-1-5-11" "*S-1-1-0" 2>$null | Out-Null
            }
        }
    } else {
        Write-Log "SSH: no id_rsa.pub / authorized_keys next to script. Skipping key import." "OK"
    }
} else {
    Write-Log "OpenSSH would be configured on port $SSHPort" "AUDIT"
}

# ===========================================================================
# 9. Additional unused services
# ===========================================================================
Write-Log "--- 9. Disabling Additional Unused Services ---" "INFO"

foreach ($srv in @(
    "WSearch","SysMain","RemoteRegistry","XblAuthManager","XblGameSave",
    "XboxNetApiSvc","XboxGipSvc","lfsvc","MapsBroker","SharedAccess",
    "WMPNetworkSvc","icssvc","CDPSvc","CDPUserSvc","PimIndexMaintenanceSvc",
    "UnistoreSvc","UserDataSvc"
)) {
    $serviceObj = Get-Service -Name $srv -ErrorAction SilentlyContinue
    if ($serviceObj) {
        if ($Mode -eq 'Apply') {
            Stop-ServiceSafe -Name $srv          # FIX v3.4
            Set-ServiceStartupType -Name $srv -StartupType disabled
            Write-Log "Disabled service: $srv" "APPLIED"
        } else {
            Write-Log "Service $srv = $($serviceObj.Status) / $($serviceObj.StartType)" "AUDIT"
        }
    }
}

# ===========================================================================
# 9.5. Additional Privacy Hardening
# ===========================================================================
Write-Log "--- 9.5. Additional Privacy Hardening ---" "INFO"

if ($Mode -eq 'Apply') {
    $onedrive = "$env:SystemRoot\System32\OneDriveSetup.exe"
    if (Test-Path $onedrive) { & $onedrive /uninstall 2>$null; Write-Log "OneDrive uninstalled via setup" "APPLIED" }
    Remove-Item -Path "$env:UserProfile\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LocalAppData\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0
    Write-Log "OneDrive, Spotlight, Consumer Features, Start suggestions disabled" "APPLIED"
} else {
    Write-Log "Additional privacy features would be hardened" "AUDIT"
}

# ===========================================================================
# 10. Wi-Fi MAC Randomization
# ===========================================================================
Write-Log "--- 10. Enabling Wi-Fi MAC Randomization ---" "INFO"
if ($Mode -eq 'Apply') {
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wi-?Fi|Wireless|WLAN" -and $_.Status -ne "Disabled" }
    foreach ($adapter in $wifiAdapters) {
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Random Hardware Addresses" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
            Write-Log "MAC randomization enabled for adapter: $($adapter.Name)" "APPLIED"
        } catch {
            Write-Log "Could not force MAC randomization on $($adapter.Name) : $_" "WARN"
        }
    }
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\Tethering" -Name "RandomMacState" -Value 1 -Optional
    Write-Log "Wi-Fi MAC randomization preference applied" "APPLIED"
} else { Write-Log "Wi-Fi MAC randomization would be enabled" "AUDIT" }

# ===========================================================================
# 11. Defender ASR Rules & CFA
# ===========================================================================
Write-Log "--- 11. Configuring Microsoft Defender ASR Rules ---" "INFO"

if ($Mode -eq 'Apply') {
    $asrRules = @{
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
        "3B576869-A4EC-4529-8536-B80A7769E899" = 1
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
        "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1
        "01443614-CD74-433A-B99E-2ECDC07BFC25" = 1
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1
    }
    $asrRuleIds = $asrRules.Keys -join ','
    $asrRuleActions = ($asrRules.Values | ForEach-Object { 'Enabled' }) -join ','
    try {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleIds `
                         -AttackSurfaceReductionRules_Actions $asrRuleActions -ErrorAction SilentlyContinue
        Write-Log "ASR rules enabled ($($asrRules.Count) rules)" "APPLIED"
    } catch { Write-Log "Failed to set ASR rules: $_" "WARN" }

    foreach ($pref in @(
        @{ Name = "ControlledFolderAccess"; Cmd = "Set-MpPreference -EnableControlledFolderAccess Enabled" },
        @{ Name = "NetworkProtection";     Cmd = "Set-MpPreference -EnableNetworkProtection Enabled" },
        @{ Name = "CloudProtection";       Cmd = "Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -SubmitSamplesConsent SendSafeSamples" },
        @{ Name = "PUAProtection";         Cmd = "Set-MpPreference -PUAProtection Enabled" }
    )) {
        try { Invoke-Expression $pref.Cmd -ErrorAction SilentlyContinue; Write-Log "$($pref.Name) enabled" "APPLIED" }
        catch { Write-Log "Failed to enable $($pref.Name): $_" "WARN" }
    }
} else {
    Write-Log "Defender hardening would be configured" "AUDIT"
}

# ===========================================================================
# 12. RDP Hardening
# ===========================================================================
Write-Log "--- 12. RDP Hardening ---" "INFO"
if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
    Write-Log "RDP hardening applied (NLA required, TLS layer)" "APPLIED"
} else { Write-Log "RDP would be hardened (NLA, TLS)" "AUDIT" }

# ===========================================================================
# 13. Print Spooler Hardening
# ===========================================================================
Write-Log "--- 13. Print Spooler Hardening ---" "INFO"
if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0
    Write-Log "Print Spooler hardening applied" "APPLIED"
} else { Write-Log "Print Spooler hardening would be applied" "AUDIT" }

# ===========================================================================
# 14. Default User Experience Adjustments
# ===========================================================================
Write-Log "--- 14. Applying Default UX Settings ---" "INFO"

if ($Mode -eq 'Apply') {

    # --- 14.1. Power plan: High Performance ---
    # Активируем схему "High performance" (если отсутствует — создаём)
    $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    $existingPlan = & powercfg.exe /list 2>$null | Select-String -Pattern $highPerfGuid -Quiet
    if (-not $existingPlan) {
        & powercfg.exe -duplicatescheme $highPerfGuid 2>$null | Out-Null
    }
    & powercfg.exe /setactive $highPerfGuid 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Power plan switched to High Performance ($highPerfGuid)" "APPLIED"
    } else {
        Write-Log "Could not switch power plan to High Performance." "WARN"
    }

    # --- 14.2. Disable lock screen, sleep and hibernate ---
    # Отключаем автоматическую блокировку (политика)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -Name "ScreenSaveActive" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -Name "InactivityTimeoutSecs" -Value 0

    # Отключаем хранитель экрана для текущего пользователя
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0" -Type String
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "0" -Type String

    # Отключаем отключение дисплея и переход в сон (от сети и от батареи)
    & powercfg.exe /change monitor-timeout-ac 0 2>$null | Out-Null
    & powercfg.exe /change monitor-timeout-dc 0 2>$null | Out-Null
    & powercfg.exe /change standby-timeout-ac 0 2>$null | Out-Null
    & powercfg.exe /change standby-timeout-dc 0 2>$null | Out-Null
    & powercfg.exe /change hibernate-timeout-ac 0 2>$null | Out-Null
    & powercfg.exe /change hibernate-timeout-dc 0 2>$null | Out-Null

    # Полностью отключаем гибернацию (освобождает место и убирает hiberfil.sys)
    & powercfg.exe /hibernate off 2>$null | Out-Null

    Write-Log "Lock screen, sleep and hibernate timeouts disabled." "APPLIED"

    # --- 14.3. Hide search box on taskbar ---
    # Основной ключ + кэш (без второго значения Windows может сбросить настройку)
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" `
        -Name "SearchboxTaskbarMode" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" `
        -Name "SearchboxTaskbarModeCache" -Value 0

    Write-Log "Taskbar search box hidden." "APPLIED"

    # --- 14.4. Принудительная установка сплошного чёрного фона ---
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" `
        -Name "WallPaper" -Value "" -Type String
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" `
        -Name "BackgroundType" -Value 0
    Set-RegistryValue -Path "HKCU:\Control Panel\Colors" `
        -Name "Background" -Value "0 0 0" -Type String
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" `
        -Name "WallpaperStyle" -Value "0" -Type String -Optional
    Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" `
        -Name "TileWallpaper" -Value "0" -Type String -Optional

    $transcodedPath = "$env:APPDATA\Microsoft\Windows\Themes\TranscodedWallpaper"
    if (Test-Path -LiteralPath $transcodedPath) {
        Remove-Item -LiteralPath $transcodedPath -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Enforced application of desktop settings" "INFO"
    $signature = @'
    using System;
    using System.Runtime.InteropServices;
    public class Wallpaper {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    }
'@
    try {
        Add-Type -TypeDefinition $signature -ErrorAction Stop
        # SPI_SETDESKWALLPAPER = 0x0014, SPIF_UPDATEINIFILE = 0x01, SPIF_SENDCHANGE = 0x02
        [Wallpaper]::SystemParametersInfo(0x0014, 0, "", 0x01 -bor 0x02) | Out-Null
        Write-Log "The desktop has been forcibly refreshed via SystemParametersInfo." "APPLIED"
    } catch {
        Write-Log "Failed to call SystemParametersInfo: $_" "WARN"
    }

    Write-Log "Desktop background set to solid black (#000000)." "APPLIED"

    # --- 14.5. Hide Task View button ---
    # Убирает кнопку переключения виртуальных рабочих столов с панели задач
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
        -Name "ShowTaskViewButton" -Value 0 -Optional
    Write-Log "Task View button hidden." "APPLIED"

    # --- 14.6. Hide Resume button on Taskbar ---
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
        -Name "TaskbarResumeApp" -Value 0 -Optional
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
        -Name "IsEnabled" -Value 0 -Optional
    Write-Log "Taskbar Resume button disabled." "APPLIED"

    Write-Log "Desktop background set to solid black (#000000). Restart Explorer or reboot to apply." "APPLIED"

    # --- 14.7. Принудительное включение тёмной темы ---
    $AdvancedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $PersonalizePath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-RegistryValue -Path $PersonalizePath -Name "EnableTransparency" -Value 1
    Set-RegistryValue -Path $AdvancedPath -Name "TaskbarAcrylicOpacity" -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "ColorPrevalence" -Value 0
    Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
        -Name "UseOLEDTaskbarTransparency" -Value 1 -Optional

    Write-Log "Transparency and Acrylic settings adjusted for Dark Mode." "APPLIED"

} else {
    Write-Log "Default UX adjustments would be applied (power plan, disable lock/sleep, hide search, black wallpaper)" "AUDIT"
}

# ===========================================================================
# Final
# ===========================================================================
Write-Log "=== Hardening Process Completed ===" "OK"
if ($Mode -eq 'Apply') {
    Write-Log "Log saved to: $LogFile" "INFO"
    Write-Log "IMPORTANT: Restart the computer to fully apply IPv6 disablement, kernel / VBS / feature changes." "WARN"
    Write-Log "After reboot verify Memory Integrity is On in Windows Security -> Device security." "WARN"
} else {
    Write-Log "Audit finished. Re-run with -Mode Apply to enforce changes." "INFO"
}
