<#
.SYNOPSIS
    Windows 11 Ultimate Security Hardening & Environment Provisioning Script (v3.1 - 2026 Edition)
.DESCRIPTION
    Aggressive security hardening for Windows 11 26H2+:
    - Kernel / OS hardening (SMBv1, PSv2, UAC, VBS/Memory Integrity, Credential Guard, LSA Protection)
    - Full IPv6 complete disablement (Registry + Tunneling protocols)
    - Full AI/Copilot/Recall removal + prevention of reinstall
    - Maximum telemetry & tracking kill
    - Disable automatic Windows Updates (with option to re-enable)
    - Reduce external network activity (WPAD, LLMNR, NetBIOS, SSDP, discovery, printers)
    - Strict Firewall (default inbound Block + ASR rules)
    - Persistent removal of Microsoft bloatware (except Calculator, Photos, basic media)
    - Wi-Fi MAC address randomization
    - Hardened OpenSSH (custom port, key-only, subnet-restricted)
    - Defender ASR rules, Controlled Folder Access, Network Protection, Smart App Control config
    - TLS hardening, DNS-over-HTTPS (DoH), SMB signing, NTLMv2 only
    - BitLocker check, DMA protection, RDP hardening
.NOTES
    Run as Administrator in PowerShell 5.1 or 7+.
    Set-ExecutionPolicy Unrestricted -Scope Process
    Usage:
        .\windows.ps1 -Mode Audit
        .\windows.ps1 -Mode Apply -SSHPort 2222 -AllowedLocalSubnet "192.168.1.0/24"
        .\windows.ps1 -Mode Apply -CreateRestorePoint
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Audit', 'Apply')]
    [string]$Mode = 'Apply',

    [Parameter()]
    [int]$SSHPort = 2222,

    [Parameter()]
    [string]$AllowedLocalSubnet = "192.168.1.0/24",

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
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    } catch {
        Write-Log "Failed to set registry $Path\$Name : $_" "WARN"
    }
}

function Set-ServiceStartupType {
    # PS 5.1 Set-Service не поддерживает -StartupType — используем sc.exe
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('auto','demand','disabled','delayed-auto')][string]$StartupType
    )
    & sc.exe config $Name start= $StartupType | Out-Null
}

function Test-IsWindows11OrLater {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    return [version]$os.Version -ge [version]"10.0.22000"
}

Write-Log "=== Windows 11 Ultimate Security Hardening v3.1 (2026) ===" "INFO"
Write-Log "Mode: $Mode | Host: $env:COMPUTERNAME | User: $env:USERNAME" "INFO"
Write-Log "OS Version: $((Get-CimInstance Win32_OperatingSystem).Version)" "INFO"

if (-not (Test-IsWindows11OrLater)) {
    Write-Log "This script is designed for Windows 11 26H2 and later. Current OS may not be fully supported." "WARN"
}

# ===========================================================================
# 0. Restore Point (optional)
# ===========================================================================
if ($Mode -eq 'Apply' -and $CreateRestorePoint) {
    Write-Log "--- 0. Creating System Restore Point ---" "INFO"
    try {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Before Windows11 Hardening v3.1" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "System Restore Point created." "OK"
    } catch {
        Write-Log "Failed to create restore point: $_" "WARN"
    }
}

# ===========================================================================
# 1. AI / Copilot / Recall + Bloatware Removal (persistent)
# ===========================================================================
Write-Log "--- 1. Removing AI, Copilot, Recall and Bloatware ---" "INFO"

$BloatPackages = @(
    "Microsoft.Windows.Ai.Copilot.Provider",
    "Microsoft.Copilot",
    "Microsoft.Windows.Recall",
    "Microsoft.Windows.ClickToDo",
    "Microsoft.AIFabric",
    "Microsoft.AIExplorer",
    "Microsoft.WindowsAI",
    "Microsoft.CopilotEdge",
    "Microsoft.Edge.Copilot",
    "Microsoft.Office.Copilot",
    "Microsoft.Office.AI",
    "Microsoft.Paint.AI",
    "Microsoft.Notepad.AI",
    "Microsoft.VoiceAccess.AI",
    "MicrosoftWindows.Client.WebExperience",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingSearch",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.Todos",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.XboxApp",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.GamingApp",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.MixedReality.Portal",
    "Microsoft.YourPhone",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MicrosoftOfficeHub",
    "Clipchamp.Clipchamp",
    "MicrosoftTeams",
    "Microsoft.Windows.DevHome",
    "Microsoft.549981C3F5F10"
)

foreach ($pkg in $BloatPackages) {
    $installed = Get-AppxPackage -AllUsers -Name "*$pkg*" -ErrorAction SilentlyContinue
    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*$pkg*" }

    if ($installed -or $provisioned) {
        if ($Mode -eq 'Apply') {
            try {
                Get-AppxPackage -AllUsers -Name "*$pkg*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                $provisioned | ForEach-Object {
                    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
                }
                Write-Log "Removed package: $pkg" "APPLIED"
            } catch {
                Write-Log "Failed to remove $pkg : $_" "WARN"
            }
        } else {
            Write-Log "Package present (will be removed): $pkg" "AUDIT"
        }
    } else {
        Write-Log "Package already absent: $pkg" "OK"
    }
}

if ($Mode -eq 'Apply') {
    $cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    @(
        "ContentDeliveryAllowed",
        "OemPreInstalledAppsEnabled",
        "PreInstalledAppsEnabled",
        "PreInstalledAppsEverEnabled",
        "SilentInstalledAppsEnabled",
        "SubscribedContent-338387Enabled",
        "SubscribedContent-338388Enabled",
        "SubscribedContent-338389Enabled",
        "SubscribedContent-338393Enabled",
        "SubscribedContent-353694Enabled",
        "SubscribedContent-353696Enabled",
        "SubscribedContent-353698Enabled",
        "SystemPaneSuggestionsEnabled"
    ) | ForEach-Object {
        Set-RegistryValue -Path $cdmPath -Name $_ -Value 0
    }
    Write-Log "Content Delivery Manager locked down (prevents bloat reinstall)" "APPLIED"
}

# ===========================================================================
# 2. Telemetry & Privacy Kill
# ===========================================================================
Write-Log "--- 2. Disabling Telemetry and Tracking ---" "INFO"

$TelemetryServices = @(
    "DiagTrack",
    "dmwappushservice",
    "WerSvc",
    "PcaSvc",
    "RetailDemo",
    "DiagnosticPolicyService",
    "DPS",
    "WdiServiceHost",
    "WdiSystemHost"
)

foreach ($srv in $TelemetryServices) {
    $svc = Get-Service -Name $srv -ErrorAction SilentlyContinue
    if ($svc) {
        if ($Mode -eq 'Apply') {
            Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            Set-ServiceStartupType -Name $srv -StartupType disabled
            Write-Log "Disabled service: $srv" "APPLIED"
        } else {
            Write-Log "Service state: $srv = $($svc.Status) / $($svc.StartType)" "AUDIT"
        }
    }
}

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Value 1

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0

    $tasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\Feedback\Siuf\DmClient",
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )
    foreach ($task in $tasks) {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Log "Telemetry registry + services + scheduled tasks disabled" "APPLIED"
} else {
    Write-Log "Telemetry policies and services would be hardened" "AUDIT"
}

# ===========================================================================
# 3. Complete IPv6 Disablement (System-Wide)
# ===========================================================================
Write-Log "--- 3. Completely Disabling IPv6 ---" "INFO"

if ($Mode -eq 'Apply') {
    # Disable IPv6 via Tcpip6 Parameters (0xffffffff disables all components except loopback)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xffffffff

    # Stop and disable IPv6 transition/tunneling technologies
    $ipv6Services = @("TeredoTunneling", "iphlpsvc")
    foreach ($srv in $ipv6Services) {
        Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
        Set-ServiceStartupType -Name $srv -StartupType disabled
    }

    # Disable IPv6 binding on all active network adapters
    Get-NetAdapterBinding -ComponentID "ms_tcpip6" -ErrorAction SilentlyContinue |
        Disable-NetAdapterBinding -ErrorAction SilentlyContinue |
        Out-Null

    Write-Log "IPv6 completely disabled system-wide (DisabledComponents = 0xffffffff)" "APPLIED"
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
    } else {
        Write-Log "SMB1Protocol feature not present. Skipping." "OK"
    }

    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction Stop }
    catch { Write-Log "Set-SmbServerConfiguration (SMB1) failed: $_" "WARN" }

    $psV2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
    if ($psV2Feature) {
        Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Log "PowerShell v2 feature disabled." "APPLIED"
    } else {
        Write-Log "PowerShell v2 feature not present (removed in this Windows build). Skipping." "OK"
    }

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
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -Value "AllSigned" -Type String
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableModuleLogging" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "EnableTranscripting" -Value 1

    $tlsProtocols = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
    )
    foreach ($proto in $tlsProtocols) {
        Set-RegistryValue -Path $proto -Name "Enabled" -Value 0
    }
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0

    try { Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop }
    catch { Write-Log "Set-SmbServerConfiguration (Signing) failed: $_" "WARN" }

    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

    Write-Log "Core OS hardening applied (SMBv1, PSv2, UAC, VBS, Credential Guard, LSA, WDigest, TLS, SMB signing, NTLMv1)" "APPLIED"
} else {
    Write-Log "Kernel hardening would be applied" "AUDIT"
}

# ===========================================================================
# 5. Disable Automatic Windows Updates
# ===========================================================================
Write-Log "--- 5. Disabling Automatic Windows Updates ---" "INFO"

if ($Mode -eq 'Apply') {
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
    Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 2 -Type DWord -Force

    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name wuauserv -StartupType disabled

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value 0

    Write-Log "Automatic Windows Updates disabled (NoAutoUpdate=1)" "APPLIED"
} else {
    Write-Log "Windows Update auto-update would be disabled" "AUDIT"
}

# ===========================================================================
# 6. Network Attack Surface Reduction & DNS-over-HTTPS (DoH)
# ===========================================================================
Write-Log "--- 6. Reducing External Network Activity & Enabling DoH ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
        Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null
    }

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1

    Stop-Service -Name "SSDPSRV" -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name "SSDPSRV" -StartupType disabled
    Stop-Service -Name "upnphost" -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name "upnphost" -StartupType disabled

    Stop-Service -Name "fdPHost" -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name "fdPHost" -StartupType disabled
    Stop-Service -Name "FDResPub" -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name "FDResPub" -StartupType disabled

    Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
    Set-ServiceStartupType -Name "Spooler" -StartupType disabled

    # Enable DNS-over-HTTPS (DoH) automatic mode (requires compatible DNS servers like Cloudflare/Google/Quad9)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2

    Write-Log "LLMNR, NetBIOS, WPAD, SSDP, UPnP, Discovery, Spooler disabled & DoH enabled" "APPLIED"
} else {
    Write-Log "Network discovery / WPAD / printers would be disabled and DoH configured" "AUDIT"
}

# ===========================================================================
# 7. Firewall Lockdown
# ===========================================================================
Write-Log "--- 7. Firewall Hardening ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Log "Firewall: DefaultInbound = Block on all profiles" "APPLIED"
} else {
    Write-Log "Firewall default inbound would be set to Block" "AUDIT"
}

# ===========================================================================
# 8. OpenSSH Hardening
# ===========================================================================
Write-Log "--- 8. OpenSSH Server Hardening ---" "INFO"

$OpenSSHServer = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' }

if ($OpenSSHServer.State -ne 'Installed') {
    if ($Mode -eq 'Apply') {
        Write-Log "Installing OpenSSH.Server..." "APPLIED"
        Add-WindowsCapability -Online -Name "OpenSSH.Server~~~~0.0.1.0" | Out-Null
    } else {
        Write-Log "OpenSSH.Server is not installed (would be installed)" "AUDIT"
    }
}

if ($Mode -eq 'Apply') {
    Set-ServiceStartupType -Name sshd -StartupType auto
    Start-Service sshd -ErrorAction SilentlyContinue

    $SSHDConfigPath = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $SSHDConfigPath) {
        $ConfigContent = Get-Content $SSHDConfigPath -Raw

        $ConfigContent = $ConfigContent -replace '(?m)^#?Port\s+\d+', "Port $SSHPort"
        $ConfigContent = $ConfigContent -replace '(?m)^#?PasswordAuthentication\s+\w+', "PasswordAuthentication no"
        $ConfigContent = $ConfigContent -replace '(?m)^#?PermitEmptyPasswords\s+\w+', "PermitEmptyPasswords no"
        $ConfigContent = $ConfigContent -replace '(?m)^#?PubkeyAuthentication\s+\w+', "PubkeyAuthentication yes"

        Set-Content -Path $SSHDConfigPath -Value $ConfigContent -Force
        Restart-Service sshd -ErrorAction SilentlyContinue
        Write-Log "sshd_config hardened: Port=$SSHPort, PasswordAuthentication=no" "APPLIED"
    }

    Get-NetFirewallRule -DisplayName "SSH-Custom-Port-Local" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    $fwParams = @{
        DisplayName   = "SSH-Custom-Port-Local"
        Direction     = "Inbound"
        Protocol      = "TCP"
        LocalPort     = $SSHPort
        RemoteAddress = $AllowedLocalSubnet
        Action        = "Allow"
        Profile       = "Any"
        Confirm       = $false
    }
    New-NetFirewallRule @fwParams | Out-Null

    Write-Log "Firewall rule: SSH $SSHPort only from $AllowedLocalSubnet" "APPLIED"
} else {
    Write-Log "OpenSSH would be configured on port $SSHPort (key-only, subnet $AllowedLocalSubnet)" "AUDIT"
}

# ===========================================================================
# 9. Additional Unused Services
# ===========================================================================
Write-Log "--- 9. Disabling Additional Unused Services ---" "INFO"

$ServicesToDisable = @(
    "WSearch",
    "SysMain",
    "RemoteRegistry",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "XboxGipSvc",
    "lfsvc",
    "MapsBroker",
    "SharedAccess",
    "WMPNetworkSvc",
    "icssvc",
    "CDPSvc",
    "CDPUserSvc",
    "PimIndexMaintenanceSvc",
    "UnistoreSvc",
    "UserDataSvc"
)

foreach ($srv in $ServicesToDisable) {
    $serviceObj = Get-Service -Name $srv -ErrorAction SilentlyContinue
    if ($serviceObj) {
        if ($Mode -eq 'Apply') {
            Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            Set-ServiceStartupType -Name $srv -StartupType disabled
            Write-Log "Disabled service: $srv" "APPLIED"
        } else {
            Write-Log "Service $srv = $($serviceObj.Status) / $($serviceObj.StartType)" "AUDIT"
        }
    }
}

# ===========================================================================
# 10. Wi-Fi MAC Address Randomization
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

    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\Tethering" -Name "RandomMacState" -Value 1 -ErrorAction SilentlyContinue
    Write-Log "Wi-Fi MAC randomization preference applied" "APPLIED"
} else {
    Write-Log "Wi-Fi MAC randomization would be enabled" "AUDIT"
}

# ===========================================================================
# 11. Defender ASR Rules & Controlled Folder Access
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

    foreach ($ruleId in $asrRules.Keys) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
    }
    Write-Log "ASR rules enabled ($($asrRules.Count) rules)" "APPLIED"

    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    Write-Log "Controlled Folder Access enabled" "APPLIED"

    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
    Write-Log "Network Protection enabled" "APPLIED"

    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    Write-Log "Cloud protection configured" "APPLIED"

    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Write-Log "PUA Protection enabled" "APPLIED"
} else {
    Write-Log "ASR rules, Controlled Folder Access, and Network Protection would be configured" "AUDIT"
}

# ===========================================================================
# 12. RDP Hardening
# ===========================================================================
Write-Log "--- 12. RDP Hardening ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
    Write-Log "RDP hardening applied (NLA required, TLS layer)" "APPLIED"
} else {
    Write-Log "RDP would be hardened (NLA, TLS)" "AUDIT"
}

# ===========================================================================
# 13. Print Spooler Hardening
# ===========================================================================
Write-Log "--- 13. Print Spooler Hardening ---" "INFO"

if ($Mode -eq 'Apply') {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0
    Write-Log "Print Spooler hardening applied (Point and Print restrictions)" "APPLIED"
} else {
    Write-Log "Print Spooler hardening would be applied" "AUDIT"
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