# 5. Analysis of Results

## 5.1 Summary

| Objective | Status | Evidence |
|---|---|---|
| Three-tier architecture on Azure | **Met** | Manager, agent, and SOAR VMs all running Wazuh 4.9.2 / Shuffle |
| AI model integrated into Wazuh | **Met** | `custom-ai` integration returns a verdict per alert, 0 errors |
| Self-developed model, no third-party API | **Met** | RandomForest trained by us, served on `127.0.0.1:5000` |
| SOAR proves response capability | **Met** | Independent webhook path at level ≥ 5, unaffected by the model |
| False-alarm criteria defined from Wazuh data | **Met** | 738 alerts labeled against documented criteria |
| **False alarms actually reduced** | **Not met** | Model learned a lookup table, not a decision function |

The engineering is sound. The machine learning is not. This section documents why, in enough
detail to reproduce and to fix.

## 5.2 Primary finding: label leakage

### What we observed

Five-fold cross-validation returned accuracy, weighted F1, and macro recall all at exactly
`1.0000`, with a train/test gap of `0.0000` and standard deviation `0.0000` across folds.

A perfect score is not a good sign on a real security dataset. Security telemetry is ambiguous
by nature — the same rule fires on an administrator's typo and on an attacker's first probe.
A model that never errs has almost always been handed the answer.

### The mechanism

The labels were generated from a rule catalog. In the notebook, `tp_rules` is a list of tuples:

```python
tp_rules = [
    ("CUSTOM Possible TCP SYN Flood", 10, "100001", "2010001"),
    ("SSH Brute Force",               10, "5712",   "2010010"),
    ("SQL Injection",                 12, "31101",  "2010040"),
    ...
]
```

Each entry is `(description, level, rule.id, signature_id)`. A row is labeled 1 when its rule
appears in this list. So:

```
label := f(rule.id)
```

The feature vector then includes `rule.id` at index 5 and `data.alert.signature_id` at index 6.
The model is asked to predict `f(rule.id)` while being given `rule.id`. It is a lookup table
with extra steps.

Confirmed on the real data: **15 distinct `rule.id` values, zero of them carrying both
labels.** Reproduction in [04-benchmarks.md](04-benchmarks.md#44-leakage-diagnostic).

### Why this defeats the project's purpose

A false positive is not a property of a rule. It is a property of *a rule firing in a
particular context*. Rule 5710 firing once from a developer's laptop at 14:00 is noise; the
same rule firing 400 times from an unfamiliar ASN at 03:00 is an attack in progress.

By labeling per rule rather than per alert, the dataset asserts that a rule is *always* benign
or *always* malicious. Under that assumption the correct implementation is a static allowlist
in `local_rules.xml` — no machine learning is required, and none is being performed. The model
cannot outperform the rule list it was derived from.

### How it manifests in production

Rule 5710, `sshd: Attempt to login using a non-existent user`:

| Source | Verdict |
|---|---|
| `data/wazuh_real_flat.csv` | `label = 1` — true positive, username enumeration |
| `tp_rules` in the notebook | absent — the list has 5712, 5713, 5503, but not 5710 |
| Synthetic training set | `label = 0` |
| **Deployed model** | `{"action": "suppress", "confidence": 0.0, "is_false_positive": true}` |

Our own labeling calls 5710 an attack. The deployed model suppresses it with maximum certainty.
Live SSH reconnaissance against `agent-vm-1` is recommended for dismissal.

The alert is still written to `alerts.json` and, at level 5+, still reaches SOAR — the advisory
architecture contains the damage. But the model's advice is actively wrong, and an analyst who
trusted it would be misled.

### Fix

1. **Label per alert, not per rule.** The same `rule.id` must appear with both labels. If a
   rule never produces a false positive, it contributes nothing to training — drop it.
2. **Remove the leaking features.** Take `rule.id`, `rule.description`, and
   `data.alert.signature_id` out of the feature set while labels are derived from them.
3. **Replace them with contextual features**, which is where the real signal lives:

   | Feature | Captures |
   |---|---|
   | `rule.firedtimes` | How often this rule has fired recently — already in our CSV, unused |
   | Alert count for this rule/agent in a 5-minute window | Burst behavior |
   | Distinct source IPs for this rule in the window | Distributed versus single-source |
   | First time this source IP has been seen | Novelty |
   | Deviation of `hour` from this rule's historical mean | Off-schedule activity |
   | Shannon entropy of `full_log` | Payload obfuscation |
   | Alert count per `location` | Which log source is noisy right now |

4. **Add a leakage gate to the pipeline.** Abort training if any input feature perfectly
   determines the label.

## 5.3 Gap 2: silent encoder fallback

`app.py` encodes unseen categories as 0:

```python
try:
    sig_id_enc = le_sig.transform([sig_id_raw])[0]
except:
    sig_id_enc = 0
```

Native Wazuh alerts — sshd, syscheck, rootcheck — have no `data.alert.severity` or
`data.alert.signature_id`. Those fields come from Suricata's `eve.json`. For an sshd alert,
`sig_id_raw` becomes the string `'0'`, and we verified that `'0'` is **not** among the 84
classes in `le_signature_id.pkl`. The `except` branch fires and substitutes index 0, which
decodes to `le_sig.classes_[0]` — a real but entirely unrelated Suricata signature.

So every native Wazuh alert is scored as though it carried one specific arbitrary Suricata
signature. Two of seven features are corrupted on a large fraction of production traffic, and
nothing in the logs indicates it.

The bare `except:` also swallows `KeyboardInterrupt` and `SystemExit`.

Fix:

```python
KNOWN_SIGS = set(le_sig.classes_)

sig_present = sig_id_raw in KNOWN_SIGS
sig_id_enc  = le_sig.transform([sig_id_raw])[0] if sig_present else -1
```

Use `-1` as an explicit "absent" sentinel rather than colliding with a valid class, train the
model with that sentinel present so it learns what absence means, and count fallbacks in a
metric so the rate is visible.

## 5.4 Gap 3: custom rules exist only in the training set

`tp_rules` references rule IDs `100001`–`100204` with descriptions such as
`CUSTOM Possible TCP SYN Flood`, `CUSTOM TEST TCP SYN`, and `Port Scan`.

`config/manager/local_rules.xml` on the live manager is the stock Wazuh template. Its only rule
is the shipped example, `100001`, which matches sshd failures from the literal address
`1.1.1.1` — nothing to do with SYN floods.

Consequently `le_rule_id.pkl` holds 79 classes, but only 15 of them ever appear in production.
Roughly 80% of the encoder's vocabulary corresponds to alerts that cannot occur, and the DDoS
scenario has no detection rule backing it at all.

Fix: write the custom rules into `local_rules.xml` and validate them before training, so the
training vocabulary and the production vocabulary agree.

## 5.5 Gap 4: scikit-learn version mismatch

Artifacts were pickled under 1.6.1 and are loaded under 1.9.1:

```
InconsistentVersionWarning: Trying to unpickle estimator RandomForestClassifier
from version 1.6.1 when using version 1.9.1. This might lead to breaking code
or invalid results.
```

Raised for `LabelEncoder`, `DecisionTreeClassifier`, `RandomForestClassifier`, and `Pipeline`.
Unpickling across a minor-version gap is not guaranteed to preserve behavior, and the failure
mode is silent numerical drift rather than an exception.

Fix: pin the version in `requirements.txt`, train inside the same environment that serves, and
record `sklearn.__version__` in `model_config.json` so `app.py` can refuse to start on a
mismatch.

## 5.6 Gap 5: feature/array contract

`app.py` builds a bare `numpy` array:

```python
features = np.array([[rule_level, severity, hour, day_of_week, is_weekend,
                      rule_id_enc, sig_id_enc]])
```

The estimator was fitted on a `pandas.DataFrame` and carries:

```
feature_names_in_: ['rule.level' 'data.alert.severity' 'hour' 'day_of_week'
                    'is_weekend' 'rule.id' 'data.alert.signature_id']
```

Passing a nameless array works positionally, and we verified the order matches both
`feature_names_in_` and `model_config.json`. But it is an unchecked invariant: reordering
`num_cols + cat_cols` in the notebook would silently mis-score every alert in production, with
no error anywhere.

Fix — pass a named DataFrame so scikit-learn validates the contract:

```python
features = pd.DataFrame([[...]], columns=config['features'])
```

## 5.7 What went right

Worth stating plainly, because the defects above are all in the model layer.

- **The advisory architecture did its job.** A model that suppresses real attacks with
  confidence 1.0 caused no loss of detection capability, because it was never in the alert
  path. Had the design filtered alerts before analysts or SOAR saw them, this bug would have
  been a live blind spot instead of a bad recommendation in a log file.
- **The integration is observable.** `custom-ai.py` writes both successes and failures to
  `integrations.log` and always exits 0, which is what allowed the outage in
  [06-troubleshooting.md](06-troubleshooting.md) to be traced to a single argument index.
- **The model config is externalized.** Threshold and feature order live in JSON, so retuning
  does not require a redeploy.
- **The classifier is not exposed.** Binding to `127.0.0.1` means a model with known defects is
  not reachable from the internet.

## 5.8 Prioritized remediation

| # | Action | Effort | Impact |
|---|---|---|---|
| 1 | Relabel per alert so rules carry both labels | High | Blocking — nothing else matters until this is done |
| 2 | Drop leaking features, add contextual ones (§5.2) | Medium | Blocking |
| 3 | Fix the `nan` scorer, rerun the grid search | Low | Makes tuning real |
| 4 | Add a leakage gate to the training pipeline | Low | Prevents regression |
| 5 | Replace the silent encoder fallback with `-1` (§5.3) | Low | Fixes corrupted features in production |
| 6 | Write the custom rules into `local_rules.xml` (§5.4) | Medium | Aligns training and production vocabulary |
| 7 | Pin scikit-learn, train and serve in one environment | Low | Removes silent drift |
| 8 | Pass a named DataFrame at inference (§5.6) | Low | Turns a silent failure into a loud one |
| 9 | Switch to time-based validation (`TimeSeriesSplit`) | Low | Random K-fold leaks future into past |
| 10 | Add an analyst feedback loop | High | Produces honest labels; closes the collaboration loop |

Item 10 is the one that turns this from a static classifier into the Human-AI collaboration
model the project asks for: analyst agreement or disagreement with each verdict becomes the
label for the next training round, and the labels stop being derived from rule IDs entirely.

## 5.9 Conclusion

We built a working SOC pipeline and a model that does not yet reduce false alarms. The
architectural decision to keep the AI advisory is what makes that an acceptable outcome rather
than a dangerous one: the system's detection capability is exactly what Wazuh and Suricata
provide, and the model can only add or withhold a recommendation.

The central lesson is methodological. The failure was not in the algorithm, the
hyperparameters, or the infrastructure — all of those worked. It was in the labeling strategy,
decided before any model was trained. Labels derived from the same signal the model is given as
input cannot teach it anything, and the resulting 100% accuracy looks like success right up
until the model suppresses a real intrusion.
