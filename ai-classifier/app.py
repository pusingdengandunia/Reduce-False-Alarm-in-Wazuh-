from flask import Flask, request, jsonify
import joblib, json
import numpy as np
import pandas as pd

app = Flask(__name__)

# Load model & encoders
model = joblib.load('/opt/ai-classifier/wazuh_fp_model.pkl')
le_id = joblib.load('/opt/ai-classifier/le_rule_id.pkl')
le_sig = joblib.load('/opt/ai-classifier/le_signature_id.pkl')

with open('/opt/ai-classifier/model_config.json') as f:
    config = json.load(f)

THRESHOLD = config['threshold']

def extract_features(alert):
    from datetime import datetime

    # Ambil timestamp
    ts_str = alert.get('timestamp', '')
    try:
        ts = pd.to_datetime(ts_str)
        hour = ts.hour
        day_of_week = ts.dayofweek
        is_weekend = 1 if day_of_week in [5, 6] else 0
    except:
        hour = 0
        day_of_week = 0
        is_weekend = 0

    rule = alert.get('rule', {})
    data = alert.get('data', {})
    alert_data = data.get('alert', {})

    rule_level = float(rule.get('level', 0))
    rule_id_raw = str(rule.get('id', '0'))
    severity_raw = alert_data.get('severity', rule_level)
    sig_id_raw = str(alert_data.get('signature_id', '0'))

    # Encode rule.id
    try:
        rule_id_enc = le_id.transform([rule_id_raw])[0]
    except:
        rule_id_enc = 0

    # Encode signature_id
    try:
        sig_id_enc = le_sig.transform([sig_id_raw])[0]
    except:
        sig_id_enc = 0

    try:
        severity = float(severity_raw)
    except:
        severity = rule_level

    # Urutan fitur: num_cols + cat_cols
    # ['rule.level', 'data.alert.severity', 'hour', 'day_of_week', 'is_weekend', 'rule.id', 'data.alert.signature_id']
    features = np.array([[
        rule_level,
        severity,
        hour,
        day_of_week,
        is_weekend,
        rule_id_enc,
        sig_id_enc
    ]])

    return features

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/analyze', methods=['POST'])
def analyze():
    alert = request.json
    if not alert:
        return jsonify({"error": "empty body"}), 400

    features = extract_features(alert)
    proba = model.predict_proba(features)[0][1]
    is_fp = bool(proba < THRESHOLD)

    return jsonify({
        "alert_id": alert.get('id', ''),
        "is_false_positive": is_fp,
        "confidence": round(float(proba), 4),
        "action": "suppress" if is_fp else "escalate"
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
