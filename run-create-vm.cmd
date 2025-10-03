@echo off
setlocal

REM ===========================
REM Required auth and project
REM ===========================
set "X_AUTH_TOKEN="
set "OS_PROJECT_ID="

REM Optionally override Nova base URL (otherwise derived from OS_AUTH_URL)
set "NOVA_BASE_URL=https://infra.mail.ru:8774"

REM ===========================
REM Required VM parameters
REM ===========================
REM CIDRs filter for target IP ranges (comma-separated). Example:
set "CIDRS=xxx.xxx.xxx.0/zz,yyy.yyy.yyy.0/zz"
REM TODO: укажите реальные значения ресурсов перед запуском
set "IMAGE_ID=56c64967-c1f2-40e3-8fd5-21c8c65af69f"
REM Either set FLAVOR_ID
set "FLAVOR_ID=9cdbca68-5e15-4c54-979d-9952785ba33e"
REM Set root disk size to boot from volume (in GB). Example: 10
set "ROOT_DISK_SIZE_GB=10"
REM Optionally specify Cinder volume type (e.g., high-iops-ha, high-iops, ceph-ssd, ceph-hdd)
set "VOLUME_TYPE=ceph-hdd"

REM Availability Zone examples:
REM set "AZ=GZ1"

REM ===========================
REM Optional parameters
REM ===========================
set "KEY_NAME="
set "SECURITY_GROUPS="
set "USER_DATA_B64="
set "NETWORK_ID="
set "SERVER_NAME_PREFIX=vm"
set "MAX_RETRIES=50"
set "POLL_INTERVAL_MS=4000"
set "MAX_POLL_MS=600000"
set "NOVA_MICROVERSION=2.1"
REM set "DELETE_ON_FAIL=false"

echo.
echo Running create-vm with configured environment...
node "%~dp0src\create-vm.js"
set ERR=%ERRORLEVEL%
echo.
if not "%ERR%"=="0" (
  echo Script failed with exit code %ERR%
  endlocal & exit /b %ERR%
) else (
  echo Finished successfully.
)
endlocal
