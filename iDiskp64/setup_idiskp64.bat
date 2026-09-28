@echo off
:: ============================================================================
:: iDiskp64 - Proper PnP Upper Disk Filter Setup Script
:: Run as Administrator on the target VM
:: ============================================================================

echo [*] Setting up iDiskp64 as a PnP upper disk filter...
echo.

:: Step 1: Ensure the driver binary is in the proper location
echo [1] Checking driver binary location...
if not exist "%SystemRoot%\System32\drivers\iDiskp64.sys" (
    echo     ERROR: iDiskp64.sys not found in %SystemRoot%\System32\drivers\
    echo     Please copy the driver binary there first.
    pause
    exit /b 1
)
echo     OK: Driver binary found.
echo.

:: Step 2: Delete the old legacy service entry (created by sc.exe create)
echo [2] Removing old legacy service entry...
sc stop iDiskp64 >nul 2>&1
sc delete iDiskp64 >nul 2>&1
echo     Done.
echo.

:: Step 3: Create proper service entry with boot-start type
:: Type=1  (SERVICE_KERNEL_DRIVER)
:: Start=0 (SERVICE_BOOT_START) - required for disk class upper filters
:: ErrorControl=1 (SERVICE_ERROR_NORMAL)
:: Group=Filter - loads in the "Filter" driver group
echo [3] Creating proper service entry (boot-start, kernel driver)...
sc create iDiskp64 type= kernel start= boot error= normal group= Filter binPath= System32\drivers\iDiskp64.sys
if %errorlevel% neq 0 (
    echo     ERROR: Failed to create service entry.
    pause
    exit /b 1
)
echo     OK: Service entry created.
echo.

:: Step 4: Add iDiskp64 to the DiskDrive class UpperFilters
:: DiskDrive class GUID: {4d36e967-e325-11ce-bfc1-08002be10318}
:: UpperFilters is a REG_MULTI_SZ value
echo [4] Registering as disk class upper filter...

:: First, read the existing UpperFilters value (if any)
:: We need to append iDiskp64 to the existing list, not replace it
:: Using reg.exe to query first, then add

:: Use PowerShell for reliable REG_MULTI_SZ handling (avoids cmd.exe delayed expansion bugs)
echo     Using PowerShell to update UpperFilters...
powershell -Command ^
    "$path='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}';" ^
    "$cur=(Get-ItemProperty -Path $path -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters;" ^
    "if($cur -and ($cur -contains 'iDiskp64')){" ^
    "  Write-Host '    iDiskp64 is already in UpperFilters. Skipping.'" ^
    "}elseif($cur){" ^
    "  $cur+='iDiskp64';" ^
    "  Set-ItemProperty -Path $path -Name UpperFilters -Value $cur -Type MultiString;" ^
    "  Write-Host '    OK: iDiskp64 appended to UpperFilters.'" ^
    "}else{" ^
    "  Set-ItemProperty -Path $path -Name UpperFilters -Value @('partmgr','iDiskp64') -Type MultiString;" ^
    "  Write-Host '    OK: UpperFilters created with partmgr + iDiskp64.'" ^
    "}"
echo.

:step5
:: Step 5: Also disable TRIM/DeleteNotification if needed (driver checks this)
:: The driver reads DisableDeleteNotification from FileSystem key
echo [5] Checking DisableDeleteNotification registry value...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v DisableDeleteNotification >nul 2>&1
if %errorlevel% neq 0 (
    echo     Setting DisableDeleteNotification=1 (as driver expects)...
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v DisableDeleteNotification /t REG_DWORD /d 1 /f
) else (
    echo     DisableDeleteNotification already set.
)
echo.

:: Step 6: Summary
echo ============================================================================
echo [*] Setup complete. Summary:
echo.
echo     Service:      iDiskp64
echo     Type:         Kernel Driver
echo     Start:        Boot (0)
echo     Group:        Filter
echo     Binary:       %%SystemRoot%%\System32\drivers\iDiskp64.sys
echo     Class Filter: DiskDrive UpperFilters
echo.
echo     IMPORTANT:
echo     - The driver skips USB (USBSTOR, UASPStor) and SD (sdbus) devices
echo     - It will only attach to SATA/NVMe/SCSI disk device stacks
echo     - The driver looks for magic value 0x6d6f64 on disk at a specific LBA
echo       to activate its protection features
echo.
echo     A REBOOT IS REQUIRED for the filter to attach to disk device stacks.
echo ============================================================================
echo.

set /p REBOOT="Reboot now? (Y/N): "
if /i "%REBOOT%"=="Y" (
    echo Rebooting in 5 seconds...
    shutdown /r /t 5
)
