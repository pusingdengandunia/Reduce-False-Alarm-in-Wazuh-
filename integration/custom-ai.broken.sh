#!/bin/bash
# ===========================================================================
# BROKEN — DO NOT DEPLOY. Preserved for the incident write-up only.
# See docs/06-troubleshooting.md
#
# This was the original /var/ossec/integrations/custom-ai (129 bytes).
# It contains two defects:
#
#   1. HOOK_URL=$2 reads the API key, not the hook URL.
#      wazuh-integratord passes:  $1 alert file
#                                 $2 API key (EMPTY, we set no <api_key>)
#                                 $3 hook URL
#      Result: curl receives an empty URL and exits 3 (URL malformed).
#      Because of -s the error goes to stderr and stdout stays empty, so
#      nothing appears in integrations.log.
#
#   2. custom-ai.py is never executed.
#      The verdict line "# AI response: ..." is written by custom-ai.py.
#      This wrapper never invokes it, so that line could never appear even
#      with defect 1 fixed.
#
# The working replacement is ./custom-ai
# ===========================================================================

ALERT_FILE=$1
HOOK_URL=$2

curl -s -X POST "$HOOK_URL" \
  -H "Content-Type: application/json" \
  -d @"$ALERT_FILE"
