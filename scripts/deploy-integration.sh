#!/bin/bash
# Install the custom-ai Wazuh integration on the Wazuh Manager.
# Run as root on the manager host:  sudo bash scripts/deploy-integration.sh
#
# Backs up any existing wrapper, installs the corrected one, verifies the
# bundled interpreter has `requests`, then restarts wazuh-manager.

set -euo pipefail

OSSEC_DIR="/var/ossec"
INT_DIR="${OSSEC_DIR}/integrations"
WPYTHON="${OSSEC_DIR}/framework/python/bin/python3"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root." >&2
    exit 1
fi

if [ ! -d "${INT_DIR}" ]; then
    echo "ERROR: ${INT_DIR} not found. Is the Wazuh Manager installed here?" >&2
    exit 1
fi

echo "==> Verifying bundled interpreter has requests"
if ! "${WPYTHON}" -c "import requests" 2>/dev/null; then
    echo "ERROR: ${WPYTHON} cannot import requests." >&2
    echo "       Install it, or point the wrapper at an interpreter that has it." >&2
    exit 1
fi
echo "    requests $("${WPYTHON}" -c 'import requests; print(requests.__version__)')"

echo "==> Backing up existing wrapper"
if [ -f "${INT_DIR}/custom-ai" ]; then
    BACKUP="${INT_DIR}/custom-ai.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "${INT_DIR}/custom-ai" "${BACKUP}"
    echo "    saved ${BACKUP}"
else
    echo "    none present"
fi

echo "==> Installing wrapper and integration script"
install -o root -g wazuh -m 750 "${REPO_DIR}/integration/custom-ai"    "${INT_DIR}/custom-ai"
install -o root -g wazuh -m 750 "${REPO_DIR}/integration/custom-ai.py" "${INT_DIR}/custom-ai.py"
ls -la "${INT_DIR}/custom-ai" "${INT_DIR}/custom-ai.py"

echo "==> Checking ossec.conf for the custom-ai integration block"
if grep -q "<name>custom-ai</name>" "${OSSEC_DIR}/etc/ossec.conf"; then
    echo "    present"
else
    cat >&2 <<'MSG'
    WARNING: no <integration><name>custom-ai</name> block found in ossec.conf.
    Add this inside <ossec_config> before the integration will ever fire:

      <integration>
        <name>custom-ai</name>
        <hook_url>http://localhost:5000/analyze</hook_url>
        <level>3</level>
        <alert_format>json</alert_format>
      </integration>
MSG
fi

echo "==> Restarting wazuh-manager"
systemctl restart wazuh-manager
sleep 12
systemctl is-active wazuh-manager
"${OSSEC_DIR}/bin/wazuh-control" status | grep -E "integratord|analysisd"

echo
echo "Done. Verify with: sudo bash scripts/test-integration.sh"
