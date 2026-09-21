# Architecture Diagrams

Mermaid source for the diagrams referenced in the report. GitHub renders these natively.

## D1 — Deployment topology

```mermaid
flowchart TB
    subgraph AZ["Azure Virtual Network"]
        direction TB

        subgraph V1["agent-vm-1 &nbsp;·&nbsp; Ubuntu 24.04.4"]
            NGINX["nginx :80"]
            SURI["Suricata IDS<br/>eve.json"]
            SSHD["OpenSSH :22"]
            AUD["auditd + dpkg"]
            WAG["wazuh-agent 4.9.2"]
            NGINX --> WAG
            SURI  --> WAG
            SSHD  --> WAG
            AUD   --> WAG
        end

        subgraph V2["WazuhManager &nbsp;·&nbsp; Ubuntu 24.04.4"]
            REM["wazuh-remoted :1514"]
            ANA["wazuh-analysisd"]
            INTG["wazuh-integratord"]
            API["wazuh-apid :55000"]
            CLF["ai-classifier<br/>Flask 127.0.0.1:5000"]
            REM --> ANA --> INTG
            INTG <--> CLF
        end

        subgraph V3["soar-vm &nbsp;·&nbsp; Ubuntu 24.04.4"]
            SBE["shuffle-backend :5001"]
            SFE["shuffle-frontend :3001/:3443"]
            SOS[("shuffle-opensearch :9200")]
            SOR["shuffle-orborus + workers"]
            SBE --- SOS
            SBE --- SOR
            SFE --- SBE
        end

        WAG -->|"1514/tcp encrypted<br/>private 10.0.0.6"| REM
        INTG -->|"webhook, level ≥ 5"| SBE
    end

    ANALYST(["SOC Analyst"])
    SFE --> ANALYST
    INTG -->|"integrations.log"| ANALYST
```

## D2 — Alert lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant AG as agent-vm-1
    participant AN as wazuh-analysisd
    participant IN as wazuh-integratord
    participant AI as ai-classifier
    participant SH as Shuffle SOAR
    participant AS as Analyst

    AG->>AN: event (1514/tcp)
    AN->>AN: decode → match rule → assign id + level

    alt level >= 3
        AN->>IN: dispatch to custom-ai
        IN->>IN: write /tmp/custom-ai-<ts>.alert
        IN->>AI: POST /analyze
        AI->>AI: 7 features → predict_proba
        AI-->>IN: {action, confidence, is_false_positive}
        IN->>AS: "# AI response: ..." in integrations.log
    end

    alt level >= 5
        AN->>IN: dispatch to shuffle
        IN->>SH: POST webhook
        SH->>SH: run response workflow
        SH->>AS: case in Shuffle UI
    end

    Note over AS: Analyst decides.<br/>The model advises; it never suppresses.
```

## D3 — Model decision path

```mermaid
flowchart LR
    A["Alert JSON"] --> B{"timestamp<br/>parseable?"}
    B -->|yes| C["hour, day_of_week, is_weekend"]
    B -->|no| D["0, 0, 0"]
    C --> E
    D --> E

    E["rule.level<br/>data.alert.severity"] --> F{"rule.id known<br/>to encoder?"}
    F -->|yes| G["le_id.transform"]
    F -->|no| H["0 &nbsp;— silent fallback"]
    G --> I
    H --> I

    I{"signature_id known?"} -->|yes| J["le_sig.transform"]
    I -->|no| K["0 &nbsp;— silent fallback"]
    J --> L
    K --> L

    L["feature vector, 7 dims"] --> M["RandomForest<br/>predict_proba"]
    M --> N{"proba < 0.491?"}
    N -->|yes| O["suppress<br/>is_false_positive: true"]
    N -->|no| P["escalate<br/>is_false_positive: false"]

    style H fill:#8b2f2f,color:#fff
    style K fill:#8b2f2f,color:#fff
```

The two red nodes are the silent-fallback defect described in
[../05-results-analysis.md](../05-results-analysis.md#53-gap-2-silent-encoder-fallback).
Native Wazuh alerts have no `data.alert.signature_id`, so they always take the right-hand
branch and are scored against an unrelated Suricata signature.

## D4 — Human-AI collaboration loop

```mermaid
flowchart TB
    ALERT["Wazuh alert"] --> MODEL["AI classifier"]
    MODEL -->|suppress| LOW["Low-priority queue"]
    MODEL -->|escalate| HIGH["High-priority queue"]

    LOW  --> ANALYST["SOC Analyst"]
    HIGH --> ANALYST

    ANALYST -->|agrees| ACT["Close or respond"]
    ANALYST -->|disagrees| CORR["Correction"]

    CORR -.->|"NOT YET IMPLEMENTED"| TRAIN["Retraining set"]
    TRAIN -.-> MODEL

    style CORR fill:#7a5a1e,color:#fff
    style TRAIN fill:#7a5a1e,color:#fff
```

Both queues reach the analyst — the model reorders work, it does not discard it. That is what
preserves detection recall regardless of model quality.

The dashed feedback path is the missing piece. Without it the model cannot improve, and the
labels stay derived from rule IDs rather than from observed analyst judgment. It is item 10 in
the remediation list.
