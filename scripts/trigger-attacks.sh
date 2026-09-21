#!/bin/bash
# Generate alerts against a Wazuh agent to exercise the detection pipeline.
#
#   bash scripts/trigger-attacks.sh <AGENT_IP> [scenario]
#
# Scenarios: ssh (default) | web | scan | all
#
# AUTHORIZATION: run only against hosts you own. This is written for the
# project's own Azure lab agent. Azure additionally requires notification
# before any volumetric or penetration testing, so no flood scenario is
# included here.

set -uo pipefail

TARGET="${1:-}"
SCENARIO="${2:-ssh}"

if [ -z "${TARGET}" ]; then
    echo "usage: $0 <AGENT_IP> [ssh|web|scan|all]" >&2
    exit 1
fi

echo "Target: ${TARGET}   Scenario: ${SCENARIO}"
echo "Watch on the manager:  sudo tail -f /var/ossec/logs/integrations.log"
echo

trigger_ssh() {
    echo "==> SSH username enumeration (expect rules 5710, 5716, 5503)"
    for u in ghostuser1 ghostuser2 ghostuser3 admin_test root_test; do
        ssh -o BatchMode=yes \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            "${u}@${TARGET}" true 2>&1 | head -1
    done
}

trigger_web() {
    echo "==> Web probing against nginx (expect rules 31101, 31103, 31104)"
    for path in /.env /admin /wp-login.php "/?id=1' OR '1'='1" /../../etc/passwd; do
        curl -s -o /dev/null -w "  %{http_code} ${path}\n" \
             -m 5 "http://${TARGET}${path}"
    done
}

trigger_scan() {
    echo "==> Port scan (expect Suricata signatures 2000537, 2001219)"
    if command -v nmap >/dev/null 2>&1; then
        nmap -sS -T4 -p 1-1000 "${TARGET}" | tail -15
    else
        echo "  nmap not installed; falling back to a connect sweep"
        for p in 21 22 23 25 80 443 3306 5432 8080; do
            timeout 1 bash -c "echo > /dev/tcp/${TARGET}/${p}" 2>/dev/null \
                && echo "  ${p} open" || echo "  ${p} closed"
        done
    fi
}

case "${SCENARIO}" in
    ssh)  trigger_ssh ;;
    web)  trigger_web ;;
    scan) trigger_scan ;;
    all)  trigger_ssh; echo; trigger_web; echo; trigger_scan ;;
    *)    echo "unknown scenario: ${SCENARIO}" >&2; exit 1 ;;
esac

echo
echo "Done. Verdicts should appear within ~10 seconds. On the manager:"
echo "  sudo grep -c 'AI response' /var/ossec/logs/integrations.log"
echo "  sudo tail -20 /var/ossec/logs/integrations.log"
