# 3. Wazuh Integration

## 3.1 How `wazuh-integratord` works

When `wazuh-analysisd` produces an alert that matches an `<integration>` block's filter,
`wazuh-integratord` does three things:

1. Writes the alert as JSON to a temporary file, `/tmp/<name>-<timestamp>-<nonce>.alert`.
2. Executes `/var/ossec/integrations/<name>` — the file named exactly as the integration, with
   no extension.
3. Captures the child's stdout and exit status. **A non-zero exit is logged as an error in
   `/var/ossec/logs/ossec.log`, once per alert.**

The argument contract is fixed and is the single most important detail in this document:

```
$1  alert file path
$2  API key   (empty string when <api_key> is absent from ossec.conf)
$3  hook URL  (from <hook_url>)
$4  options   (optional; "debug" enables verbose logging)
```

`$2` is an empty string in our deployment because we do not set `<api_key>`. Reading the hook
URL from `$2` instead of `$3` is a silent failure mode — it produces an empty URL, and the
resulting `curl` error appears nowhere in `integrations.log`. That is exactly the bug we hit;
see [06-troubleshooting.md](06-troubleshooting.md).

By Wazuh convention the extensionless file is a thin shell wrapper whose only job is to invoke
`<name>.py` with the bundled Python interpreter, forwarding all arguments untouched.

## 3.2 Configured integrations

From `config/manager/ossec.conf`:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://SOAR_IP_PLACEHOLDER:5001/api/v1/hooks/webhook_REPLACE_WITH_YOUR_WEBHOOK_ID</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>custom-ai</name>
  <hook_url>http://localhost:5000/analyze</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

| Integration | Threshold | Destination | Role |
|---|---|---|---|
| `shuffle` | level ≥ 5 | SOAR webhook | Response. Stock Wazuh integration, unmodified |
| `custom-ai` | level ≥ 3 | Local classifier | Annotation. Written for this project |

The classifier threshold is deliberately two levels lower than the SOAR threshold. False
positives concentrate in the low-severity band, so restricting the model to level 5 and above
would exclude most of the noise it is meant to triage. The trade-off is volume: level 3
captures nearly every alert the manager produces, so `integrations.log` grows quickly. If log
volume becomes a constraint, raise `custom-ai` to level 4 rather than 5.

## 3.3 The wrapper — `integration/custom-ai`

```sh
#!/bin/sh
DIR_NAME="$(cd "$(dirname "$0")"; pwd -P)"
WAZUH_PATH="$(cd "${DIR_NAME}/.."; pwd)"
"${WAZUH_PATH}/framework/python/bin/python3" "${DIR_NAME}/custom-ai.py" "$@"
```

Three properties matter:

- **`"$@"` forwards arguments unmodified**, so `custom-ai.py` receives the alert file at
  `argv[1]` and the hook URL at `argv[3]`, matching the constants declared in that script.
- **It uses Wazuh's embedded interpreter**, `/var/ossec/framework/python/bin/python3`, which
  ships `requests` 2.32.2. This avoids depending on a virtualenv in a user's home directory
  that the `wazuh` user may not be able to read.
- **Paths are derived from `$0`**, so the script works regardless of the working directory
  `wazuh-integratord` happens to use.

Required ownership and permissions — the manager refuses to execute an integration that is
group- or world-writable:

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-ai
sudo chmod 750       /var/ossec/integrations/custom-ai
```

`integration/custom-ai.broken.sh` preserves the original faulty wrapper for the write-up.

## 3.4 The integration logic — `integration/custom-ai.py`

```python
ALERT_INDEX   = 1
WEBHOOK_INDEX = 3
```

Flow:

1. Append the invocation arguments to `/var/ossec/logs/integrations.log` as an audit trail.
2. Load and parse the alert file. Exit 6 if missing, exit 7 if the JSON is malformed.
3. `POST` the alert to the hook URL with a 10-second timeout.
4. Append `# AI response: <body>` to `integrations.log`.
5. On a request exception, append `# AI request failed: <error>` instead.

Step 5 is what makes the integration observable. A network failure or a classifier crash
leaves an explicit line in the log rather than silence, and — importantly — the script still
exits 0, so `wazuh-integratord` does not spam `ossec.log` with one error per alert.

### Resulting log format

```
/tmp/custom-ai-1789967663-890578119.alert  http://localhost:5000/analyze 
# AI response: {"action":"suppress","alert_id":"1789967652.435830","confidence":0.0,"is_false_positive":true}
```

The first line is the audit trail, the second is the verdict. This is the analyst-facing
surface of the whole system.

## 3.5 SOAR path

Shuffle runs on Docker Swarm on the SOAR VM. Relevant services from
`config/soar/docker-compose.yml`:

| Container | Image | Published port |
|---|---|---|
| `shuffle-backend` | `ghcr.io/shuffle/shuffle-backend:latest` | 5001 |
| `shuffle-frontend` | `ghcr.io/shuffle/shuffle-frontend:latest` | 3001, 3443 |
| `shuffle-opensearch` | `opensearchproject/opensearch:3.2.0` | 9200 |
| `shuffle-orborus` | `ghcr.io/shuffle/shuffle-orborus:latest` | — |
| `shuffle-workers` | `ghcr.io/shuffle/shuffle-worker:latest` | — |
| `tenzir-node` | `tenzir/tenzir:main` | 1514, 5160 |

Alerts arrive at the webhook trigger on `shuffle-backend:5001`, which starts a workflow. The
OpenSearch instance stores workflow executions and alert context.

The OpenSearch admin password is supplied through `${SHUFFLE_OPENSEARCH_PASSWORD}` from a
git-ignored `.env` file, so no credential is committed here.

### A note on stock `shuffle.py`

`/var/ossec/integrations/shuffle.py` contains a skip list. When an alert matches it, the script
prints and exits non-zero:

```python
print('Skipping rule %s' % alert['rule']['id'])
```

`wazuh-integratord` then emits, misleadingly:

```
wazuh-integratord: ERROR: While running custom-ai -> integrations. Output: Skipping rule 5710
wazuh-integratord: ERROR: Exit status was: 3
```

The integration name in that message is not reliable. The `Skipping rule` text originates in
`shuffle.py`, not in `custom-ai`. Do not use it to diagnose the AI integration.

## 3.6 Verification

`scripts/test-integration.sh` checks four layers in order, so a failure isolates the broken
one immediately:

| Layer | Check | Expected |
|---|---|---|
| 1 | `GET /health` | `{"status": "ok"}` |
| 2 | `POST /analyze` directly with `curl` | A verdict JSON object |
| 3 | Wrapper invoked with the real argument order | Exit 0 and a new `# AI response` line |
| 4 | Live alert triggered from the agent | `# AI response` appears within ~10 s |

Layer 3 is the one that catches argument-contract bugs, and it is the layer that was failing.
Invoke it exactly as the manager does, with an empty second argument:

```bash
sudo /var/ossec/integrations/custom-ai /tmp/t.alert "" http://localhost:5000/analyze
echo "EXIT=$?"
```
