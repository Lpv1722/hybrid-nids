import pandas as pd
import joblib
from rule_engine import detect_rules
from pathlib import Path

MODEL_PATH = Path("models/isolation_forest.joblib")
DATA_PATH = Path("data/flows.csv")

FEATURES = [
	"packet_count",
	"total_bytes",
	"duration",
	"avg_packet_size",
	"fwd_packets",
	"bwd_packets",
	"fwd_bytes",
	"bwd_bytes",
	"byte_ratio",
	"syn_count",
	"ack_count",
	"fin_count",
	"rst_count",
	"unique_dst_ports",
	"unique_dst_ips",
	"connection_count",
	"syn_only_count"
]

# Load trained model
pipeline = joblib.load(MODEL_PATH)

# Load extracted flows
df = pd.read_csv(DATA_PATH)

if df.empty:
	raise ValueError("No flows to analyze")

X = df[FEATURES].copy()

# Detect anomalies
df["prediction"] = pipeline.predict(X)
df["anomaly_score"] = pipeline.decision_function(X)

df["status"] = df["prediction"].map({
	1: "Normal",
	-1: "Anomaly"
})

# Rule-based detection
df["rule_alert"] = df.apply(detect_rules, axis=1)

# Preserve original ML result
df["ml_status"] = df["status"]

# Hybrid detection
ml_detected = df["ml_status"] == "Anomaly"
rule_detected = df["rule_alert"] != ""

df["detection_source"] = "None"

df.loc[ml_detected, "detection_source"] = "ML"
df.loc[rule_detected, "detection_source"] = "Rule"
df.loc[ml_detected & rule_detected, "detection_source"] = "ML + Rule"

df.loc[ml_detected | rule_detected, "status"] = "Anomaly"

df.to_csv("data/anomalies.csv", index=False)

print("\nResults saved to data/anomalies.csv")
