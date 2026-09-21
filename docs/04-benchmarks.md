# 4. Benchmark Metrics

## 4.1 Which metrics, and why

Accuracy alone is misleading on imbalanced data: always predicting the majority class scores
70% on our 2.1:1 split while catching zero attacks. We therefore report four metrics.

| Metric | Why it is here |
|---|---|
| **Accuracy** | Baseline readability. Reported, never relied on. |
| **Weighted F1** | Balances precision and recall, weighted by class support. |
| **Macro recall** | Averages recall across both classes with equal weight. This is the metric that detects the "suppress everything" failure mode — it collapses toward 0.5 when one class is ignored. |
| **Average precision (PR-AUC)** | Area under the precision/recall curve. The right summary metric for imbalanced binary detection, and threshold-independent. |

Explicitly **not** used: ROC-AUC. It is optimistic under class imbalance because the large
true-negative count inflates the score.

### The metric that matters operationally

In a SOC, the two errors are not symmetric.

- A **false negative** here means the model marks a real attack as a false alarm. The alert is
  still logged and still forwarded to SOAR at level 5+, so it is a triage-priority error rather
  than a missed detection — but it is the error that erodes analyst trust fastest.
- A **false positive** here means the model escalates benign noise. Cost: the analyst's time,
  which is the resource this project exists to conserve.

We therefore optimize **average precision** and treat macro recall as a guardrail.

## 4.2 Validation protocol

`StratifiedKFold(n_splits=5, shuffle=True, random_state=42)` with `cross_validate` and
`return_train_score=True`, so train and test scores can be compared fold by fold. A
train-minus-test gap above 0.05 is flagged as overfitting.

## 4.3 Results as measured

### Hyperparameter search

```
Best Params: {'rf__class_weight': {0: 1, 1: 3}, 'rf__max_depth': 12,
              'rf__min_samples_leaf': 10, 'rf__n_estimators': 300}
Best CV Avg Precision: nan
```

### Cross-validation

| Metric | Train | Test | Gap | Flag |
|---|---|---|---|---|
| Accuracy | 1.0000 | 1.0000 | 0.0000 | — |
| Weighted F1 | 1.0000 | 1.0000 | 0.0000 | — |
| Macro recall | 1.0000 | 1.0000 | 0.0000 | — |
| Average precision | nan | nan | nan | invalid |

Final test scores: accuracy `1.0000 ± 0.0000`, weighted F1 `1.0000 ± 0.0000`, macro recall
`1.0000 ± 0.0000`.

**These numbers are not evidence of a good model.** Perfect scores with zero variance across
five folds and a zero train/test gap is the signature of label leakage, not of learning. The
diagnosis is in [05-results-analysis.md](05-results-analysis.md).

### The `nan` scorer defect

`avg_precision` is `nan` in every fold because of how the scorer was constructed:

```python
make_scorer(average_precision_score, response_method='predict_proba')
```

`predict_proba` returns an array of shape `(n_samples, 2)`. `average_precision_score` expects
a one-dimensional score for the positive class. The shape mismatch yields `nan`.

Two consequences, both serious:

1. `GridSearchCV` was scoring on average precision. Every candidate scored `nan`, so the search
   ranked nothing and `best_params_` was effectively arbitrary. **The reported hyperparameters
   were not selected on merit.**
2. The overfitting check printed `✅ OK` for that row, because `nan > 0.05` evaluates to
   `False`. The guardrail silently passed a metric it had never computed.

Fix — use the built-in scorer string, which handles the column selection internally:

```python
scoring = {
    'accuracy':      'accuracy',
    'f1_weighted':   'f1_weighted',
    'avg_precision': 'average_precision',
    'recall_macro':  'recall_macro',
}
```

And make the guardrail fail loudly on a missing metric:

```python
if np.isnan(gap):
    status = "❌ METRIC FAILED TO COMPUTE"
elif gap > 0.05:
    status = "⚠️ OVERFITTING"
else:
    status = "✅ OK"
```

## 4.4 Leakage diagnostic

Run against the real data, `data/wazuh_real_flat.csv`:

```python
import pandas as pd
d = pd.read_csv('data/wazuh_real_flat.csv')
g = d.groupby('rule.id')['label'].nunique()
print('distinct rule.id:', len(g), '| mixed-label:', (g > 1).sum())
g2 = d.groupby('rule.description')['label'].nunique()
print('distinct descriptions:', len(g2), '| mixed-label:', (g2 > 1).sum())
```

Output:

```
distinct rule.id: 15 | mixed-label: 0
distinct descriptions: 25 | mixed-label: 0
```

**Zero rules carry both labels.** Every `rule.id` maps to exactly one label, so `label` is a
deterministic function of `rule.id` — and `rule.id` is feature index 5. The classifier needs
only to memorize a 15-entry lookup table to score perfectly.

This diagnostic should be a gate in the training pipeline. If `mixed-label` is 0 for any
feature that is also an input, the dataset cannot support learning and training should abort.

## 4.5 Operational benchmarks

Measured on the live deployment, and independent of model quality.

| Measurement | Value | How obtained |
|---|---|---|
| Classifier response to direct `curl` | HTTP 200, exit 0 | `curl -X POST localhost:5000/analyze` |
| Wrapper exit status after fix | `EXIT=0` | invoked with the real argument order |
| Wrapper exit status before fix | `EXIT=3` (`curl` URL malformed) | same invocation |
| End-to-end latency, alert to verdict | under 10 s | `tail -f` during `trigger-attacks.sh` |
| Verdicts written during verification | 19 `# AI response` lines | `grep -c "AI response" integrations.log` |
| Alerts generated by 3 SSH attempts | 3 | `grep -c ghostuser alerts.json` |
| Integration errors after fix | 0 | `grep -i integrat ossec.log` |
| Request timeout | 10 s | `requests.post(..., timeout=10)` |

The pipeline meets its operational requirement: every alert at level 3 and above receives a
verdict, well inside the timeout, with no error spam.

## 4.6 Metrics to report once leakage is fixed

The current numbers cannot be compared against anything. After retraining on properly labeled
data, report:

| Metric | Target | Meaning |
|---|---|---|
| PR-AUC on a held-out time window | 0.65 – 0.85 | Anything near 1.0 means leakage remains |
| Recall on class 1 | ≥ 0.95 | Attacks suppressed — the error that must stay near zero |
| Precision on class 0 | ≥ 0.90 | Confidence that a suppression is safe |
| Alert volume reduction | measured, not targeted | Fraction routed to the low-priority queue |
| Analyst agreement rate | ≥ 0.80 | Share of verdicts a human accepts on review |

The last row is the metric that makes this a Human-AI collaboration system rather than an
automated filter, and it is only obtainable once analysts have reviewed a batch of verdicts.
