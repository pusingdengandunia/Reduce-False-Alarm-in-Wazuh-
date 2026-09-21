# Dataset

## `wazuh_real_flat.csv`

738 alerts exported from the running Wazuh deployment and labeled by hand.

| Property | Value |
|---|---|
| Rows | 738 |
| Label 0 (false positive) | 499 |
| Label 1 (true positive) | 239 |
| Imbalance | 2.1 : 1 |
| Distinct `rule.id` | 15 |
| Distinct `rule.description` | 25 |

### Schema

| Column | Type | Notes |
|---|---|---|
| `timestamp` | ISO 8601 | e.g. `2025-03-05T00:00:34.390+0000` |
| `rule.level` | int | Wazuh severity, 0–15 |
| `rule.id` | int | Wazuh rule identifier |
| `rule.description` | string | Human-readable rule name; may be empty |
| `rule.firedtimes` | float | Times this rule fired in the current window — **unused as a feature, and a strong candidate for the retrained model** |
| `rule.groups` | string | Comma-separated rule taxonomy |
| `rule.mail` | bool | Whether the rule triggers mail alerting |
| `decoder` | string | Decoder that parsed the event |
| `location` | string | Log source |
| `agent.name` | string | **Anonymized to `xxx`** |
| `full_log` | string | Raw log line |
| `label` | int | 0 = false positive, 1 = true positive |

### Labeling criteria

See [../docs/02-ai-model.md](../docs/02-ai-model.md#22-defining-false-alarm). In short:
routine housekeeping, expected administrative action, and level-3 informational rules are 0;
username enumeration, probing bursts, crontab modification, and unexplained connection resets
from external sources are 1.

### Known defect — read before training on this

**Every `rule.id` maps to exactly one label. Zero rules carry both.**

```python
import pandas as pd
d = pd.read_csv('wazuh_real_flat.csv')
g = d.groupby('rule.id')['label'].nunique()
print('distinct rule.id:', len(g), '| mixed-label:', (g > 1).sum())
# distinct rule.id: 15 | mixed-label: 0
```

Any model that receives `rule.id`, `rule.description`, or `data.alert.signature_id` as a
feature will score near-perfectly on this data by memorizing a 15-entry lookup table, without
learning anything about false positives. This is what happened to the deployed model; the full
analysis is in [../docs/05-results-analysis.md](../docs/05-results-analysis.md).

For this dataset to support learning, the same rule must appear with both labels — which means
labeling per alert and per context, not per rule.

## Artifacts not in this repository

| File | Why excluded |
|---|---|
| `wazuh_alerts_labeled(2).csv` | 2000-row augmented training set, mostly synthetic. Regenerate from `../notebooks/labellingFalsePositive.ipynb`. |
| `wazuh_fp_model.pkl` | Serialized model, 292 KB. Excluded by `.gitignore`. |
| `le_rule_id.pkl` | LabelEncoder, 79 classes. Excluded. |
| `le_signature_id.pkl` | LabelEncoder, 84 classes. Excluded. |
| `wazuh_formatted_alerts.json` | 2.9 MB raw export; the CSV is the flattened form. |

`*.pkl` files are excluded deliberately. `joblib.load` executes arbitrary code during
deserialization, so a pickle from an untrusted source is remote code execution. Distribute
model artifacts through a channel where provenance can be verified, and regenerate them from
the notebook wherever possible.
