#!/bin/bash
# Four-layer verification of the custom-ai integration.
# Run as root on the Wazuh Manager:  sudo bash scripts/test-integration.sh
#
# Layers run cheapest-first so a failure isolates the broken component:
#   1. classifier liveness        (/health)
#   2. classifier inference       (POST /analyze)
#   3. Wazuh wrapper contract     (correct argument order)
#   4. live alert end-to-end      (requires an agent to generate one)

set -uo pipefail

ENDPOINT="http://localhost:5000"
LOGFILE="/var/ossec/logs/integrations.log"
WRAPPER="/var/ossec/integrations/custom-ai"
ALERT="/tmp/test-alert.json"
FAILED=0

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; FAILED=1; }

cat > "${ALERT}" <<'EOF'
{"timestamp":"2026-09-21T05:00:00.000+0000","id":"1234567890.12345",
 "rule":{"id":"5710","level":5,"description":"sshd: Attempt to login using a non-existent user"},
 "agent":{"name":"test-agent"},"full_log":"Invalid user ghostuser from 203.0.113.10 port 51234"}
EOF

echo "=== Layer 1: classifier liveness ==="
HEALTH=$(curl -sS -m 5 "${ENDPOINT}/health" 2>&1)
if echo "${HEALTH}" | grep -q '"status"'; then
    pass "GET /health -> ${HEALTH}"
else
    fail "GET /health -> ${HEALTH}"
    echo "  Hint: systemctl status ai-classifier"
fi

echo
echo "=== Layer 2: classifier inference ==="
VERDICT=$(curl -sS -m 10 -X POST "${ENDPOINT}/analyze" \
               -H 'Content-Type: application/json' -d @"${ALERT}" 2>&1)
if echo "${VERDICT}" | grep -q '"action"'; then
    pass "POST /analyze -> ${VERDICT}"
else
    fail "POST /analyze -> ${VERDICT}"
    echo "  Hint: journalctl -u ai-classifier -n 50"
fi

echo
echo "=== Layer 3: Wazuh wrapper contract ==="
# Argument order matters: $1 alert file, $2 API key (EMPTY), $3 hook URL.
# Testing without the empty second argument would pass against a broken wrapper.
MARK=$(wc -l < "${LOGFILE}" 2>/dev/null || echo 0)
"${WRAPPER}" "${ALERT}" "" "${ENDPOINT}/analyze"
RC=$?
if [ "${RC}" -eq 0 ]; then
    pass "wrapper exit 0"
else
    fail "wrapper exit ${RC} (exit 3 = curl URL malformed, i.e. wrong argument index)"
fi

NEWLINES=$(tail -n +$((MARK + 1)) "${LOGFILE}" 2>/dev/null)
if echo "${NEWLINES}" | grep -q "# AI response"; then
    pass "verdict written to ${LOGFILE}"
    echo "${NEWLINES}" | sed 's/^/    /'
else
    fail "no '# AI response' line appended to ${LOGFILE}"
    echo "  Hint: the wrapper is probably not invoking custom-ai.py"
fi

echo
echo "=== Layer 4: live alert end-to-end ==="
echo "  Trigger alerts from an agent, e.g.:"
echo "    bash scripts/trigger-attacks.sh <AGENT_IP>"
echo "  Then watch:"
echo "    sudo tail -f ${LOGFILE}"
echo
BEFORE=$(grep -c "AI response" "${LOGFILE}" 2>/dev/null || echo 0)
echo "  Current verdict count: ${BEFORE}"
echo "  Recent integrator errors:"
grep -i integrat /var/ossec/logs/ossec.log 2>/dev/null | tail -5 | sed 's/^/    /' \
    || echo "    none"
echo "  (Ignore lines containing 'Skipping rule' — those come from shuffle.py.)"

echo
if [ "${FAILED}" -eq 0 ]; then
    echo "RESULT: layers 1-3 passed."
    exit 0
else
    echo "RESULT: failures above. See docs/06-troubleshooting.md"
    exit 1
fi
