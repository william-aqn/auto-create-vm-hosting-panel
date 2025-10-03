#!/usr/bin/env bash
set -euo pipefail

# ===========================
# Required auth and project
# ===========================
# TODO: укажите реальные значения перед запуском
export X_AUTH_TOKEN=""
export OS_PROJECT_ID=""

# Optionally override Nova base URL
export NOVA_BASE_URL="https://infra.mail.ru:8774"

# ===========================
# Required VM parameters
# ===========================
# CIDRs filter for target IP ranges (comma-separated). Example:
export CIDRS="xxx.xxx.xxx.0/zz,yyy.yyy.yyy.0/zz"

# TODO: укажите реальные значения ресурсов перед запуском
export IMAGE_ID="56c64967-c1f2-40e3-8fd5-21c8c65af69f"
# Either set FLAVOR_ID
export FLAVOR_ID="9cdbca68-5e15-4c54-979d-9952785ba33e"

# Set root disk size to boot from volume (in GB). Example: 10
export ROOT_DISK_SIZE_GB="10"
# Optionally specify Cinder volume type (e.g., high-iops-ha, high-iops, ceph-ssd, ceph-hdd)
export VOLUME_TYPE="ceph-hdd"

# Availability Zone examples:
# export AZ="GZ1"

# ===========================
# Optional parameters
# ===========================
export KEY_NAME=""
export SECURITY_GROUPS=""        # comma-separated names
export USER_DATA_B64=""          # base64-encoded cloud-init
export NETWORK_ID=""             # optional; leave empty to auto-allocate or project default
export SERVER_NAME_PREFIX="vm"
export MAX_RETRIES="50"
export POLL_INTERVAL_MS="4000"
export MAX_POLL_MS="600000"
export NOVA_MICROVERSION="2.1"
# export DELETE_ON_FAIL="false"

echo
echo "Running create-vm with configured environment..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "${SCRIPT_DIR}/src/create-vm.js"
ERR=$?
echo
if [[ "$ERR" != "0" ]]; then
  echo "Script failed with exit code ${ERR}"
  exit "$ERR"
else
  echo "Finished successfully."
fi
