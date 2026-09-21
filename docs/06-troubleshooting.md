# 6. Incident Write-up: Silent Integration Failure

A field report of a real outage in this deployment. Kept because the diagnostic path
generalizes to any Wazuh integration.

## 6.1 Symptom

`integrations.log` showed activity from the `shuffle` integration but never a single line from
`custom-ai`:

```bash
sudo tail -f /var/ossec/logs/integrations.log
```

```
/tmp/shuffle-1789967231--117765664.alert  http://<SOAR_IP>:5001/api/v1/hooks/webhook_<ID>
/tmp/shuffle-1789966927-55579325.alert    http://<SOAR_IP>:5001/api/v1/hooks/webhook_<ID>
```

Expected, and absent:

```
# AI response: {"action":"escalate","alert_id":"...","confidence":0.87,"is_false_positive":false}
```

Misleading signals that cost time:

- `wazuh-control status` reported `wazuh-integratord is running...`
- `grep -icE "error|traceback|refused|timeout" integrations.log` returned `0`
- The classifier answered `curl` correctly when tested by hand
- `ss -lntp` confirmed `127.0.0.1:5000` was listening

Every component looked healthy in isolation.

## 6.2 Diagnostic path

### Step 1 — check the daemon's own log, not the integration's

`integrations.log` is written *by the integration scripts themselves*. If a script never runs,
or dies before its first write, that file stays silent. The daemon's errors go elsewhere:

```bash
sudo grep -i integrat /var/ossec/logs/ossec.log | tail -20
```

```
wazuh-integratord: ERROR: While running custom-ai -> integrations. Output: Skipping rule 5710
wazuh-integratord: ERROR: Exit status was: 3
wazuh-integratord: ERROR: Unable to run integration for custom-ai -> integrations
```

**Lesson:** an empty `integrations.log` is not evidence of no errors. Always check `ossec.log`.

### Step 2 — discard the misleading part of the error

`Output: Skipping rule 5710` looks like the cause. It is not. That string is in the stock
Shuffle integration:

```bash
sudo grep -rn "Skipping rule" /var/ossec/integrations/
```

```
/var/ossec/integrations/shuffle.py:189:    print('Skipping rule %s' % alert['rule']['id'])
```

`custom-ai` does not contain that text. `wazuh-integratord` attributed output from one
integration to another. The reliable part of the message is `Exit status was: 3`.

### Step 3 — reproduce with the exact argument order

This is the decisive step. Invoke the wrapper the way the daemon does, with the empty API-key
argument in position 2:

```bash
cat > /tmp/t.alert <<'EOF'
{"timestamp":"2026-09-21T05:00:00.000+0000","rule":{"id":"5710","level":5,
 "description":"sshd: Attempt to login using a non-existent user"},
 "agent":{"name":"test"},"full_log":"test log"}
EOF

sudo /var/ossec/integrations/custom-ai /tmp/t.alert "" http://localhost:5000/analyze
echo "EXIT=$?"
```

```
EXIT=3
```

No output, exit 3. Reproduced outside the daemon.

### Step 4 — isolate the layer

The classifier itself was fine:

```bash
curl -s -X POST http://localhost:5000/analyze \
     -H 'Content-Type: application/json' -d @/tmp/t.alert
```

```
{"action":"suppress","alert_id":"","confidence":0.0,"is_false_positive":true}
```

HTTP 200. So the fault was between `wazuh-integratord` and the classifier — in the wrapper.

### Step 5 — read the wrapper

```sh
#!/bin/bash
ALERT_FILE=$1
HOOK_URL=$2

curl -s -X POST "$HOOK_URL" \
  -H "Content-Type: application/json" \
  -d @"$ALERT_FILE"
```

`HOOK_URL=$2`. The daemon passes the hook URL in **`$3`**; `$2` is the API key, which is an
empty string because `<api_key>` is not set in `ossec.conf`.

So `curl` was called with an empty URL. `curl` exit code 3 is `URL malformed`. `-s` suppressed
the progress meter, the error went to stderr, and stdout stayed empty — hence no trace
anywhere an operator would normally look.

## 6.3 Root cause

Two independent defects in one file.

**Defect 1 — wrong argument index.** `HOOK_URL=$2` should be `$3`. Every invocation produced an
empty URL and exit 3.

**Defect 2 — the Python script was never executed.** The wrapper is a hand-written `curl`
command. It never calls `custom-ai.py`. But `custom-ai.py` is what writes the verdict line:

```python
f.write(f'# AI response: {res.text}\n')
```

Even with Defect 1 fixed, `# AI response:` could never have appeared. The `curl` body would go
to stdout, where `wazuh-integratord` captures it into `ossec.log` as error text.

Comparison with the stock wrapper makes the omission obvious. `/var/ossec/integrations/shuffle`
is 1045 bytes and ends:

```sh
${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```

The hand-written `custom-ai` was 129 bytes and had no equivalent line.

## 6.4 Fix

Replace the wrapper with one that follows the Wazuh convention — forward all arguments to the
Python script, using the interpreter Wazuh bundles.

```bash
sudo cp -a /var/ossec/integrations/custom-ai \
           /var/ossec/integrations/custom-ai.bak.$(date +%Y%m%d%H%M%S)

sudo tee /var/ossec/integrations/custom-ai > /dev/null <<'EOF'
#!/bin/sh
DIR_NAME="$(cd "$(dirname "$0")"; pwd -P)"
WAZUH_PATH="$(cd "${DIR_NAME}/.."; pwd)"
"${WAZUH_PATH}/framework/python/bin/python3" "${DIR_NAME}/custom-ai.py" "$@"
EOF

sudo chown root:wazuh /var/ossec/integrations/custom-ai
sudo chmod 750       /var/ossec/integrations/custom-ai
sudo systemctl restart wazuh-manager
```

Automated as `scripts/deploy-integration.sh`.

`requests` availability in the bundled interpreter was confirmed before switching:

```bash
sudo /var/ossec/framework/python/bin/python3 -c "import requests; print(requests.__version__)"
# 2.32.2
```

## 6.5 Verification

### Manual invocation

```
EXIT=0
/tmp/t.alert  http://localhost:5000/analyze 
# AI response: {"action":"suppress","alert_id":"","confidence":0.0,"is_false_positive":true}
```

### End to end

Three failed SSH logins against the agent:

```bash
for u in ghostuser1 ghostuser2 ghostuser3; do
  ssh -o ConnectTimeout=5 "$u@<AGENT_IP>" true
done
```

Within ten seconds:

```
/tmp/custom-ai-1789967663-890578119.alert  http://localhost:5000/analyze 
# AI response: {"action":"suppress","alert_id":"1789967652.435830","confidence":0.0,"is_false_positive":true}
```

`alert_id` is now populated — it was empty in the synthetic test because the hand-made alert
file had no `id` field. Real alerts carry one.

### Final state

| Check | Before | After |
|---|---|---|
| Wrapper exit status | 3 | 0 |
| `# AI response` lines | 0 | 19 |
| `alert_id` in verdicts | — | populated |
| Integration errors in `ossec.log` | one per alert | none |
| `wazuh-manager` | active | active |

## 6.6 Takeaways

1. **`integrations.log` cannot report a script that never ran.** Check `ossec.log` first.
2. **`wazuh-integratord` may attribute output to the wrong integration.** Trust the exit
   status; verify the text against the scripts on disk.
3. **Reproduce with the daemon's exact argument order.** The empty `$2` is the trap — testing
   with `custom-ai /tmp/t.alert http://localhost:5000/analyze` would have "passed" against the
   broken wrapper and hidden the bug.
4. **Follow the stock wrapper pattern.** It exists to get the argument forwarding and
   interpreter selection right.
5. **An integration should exit 0 even when its work fails**, and record the failure in its own
   log. Non-zero exits produce one `ossec.log` error per alert, which buries the signal.
6. **`curl -s` hides errors.** Use `-sS` in integration scripts so stderr survives.
