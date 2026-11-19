import pandas as pd
import joblib

from pathlib import Path
from src.detection.rule_engine import detect_rules
from src.database.database import create_analysis_run, save_flows

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


class AnomalyDetector:
	def __init__(self, model_path=MODEL_PATH):
		self.pipeline = joblib.load(model_path)

	def detect(self, df):
		df = df.copy()

		if df.empty:
			return df

		X = df[FEATURES].copy()

		df["prediction"] = self.pipeline.predict(X)
		df["anomaly_score"] = self.pipeline.decision_function(X)

		df["status"] = df["prediction"].map({
			1: "Normal",
			-1: "Anomaly"
		})

		df["rule_alert"] = df.apply(detect_rules, axis=1)

		df["ml_status"] = df["status"]

		ml_detected = df["ml_status"] == "Anomaly"
		rule_detected = df["rule_alert"] != ""

		df["detection_source"] = "None"

		df.loc[ml_detected, "detection_source"] = "ML"
		df.loc[rule_detected, "detection_source"] = "Rule"
		df.loc[ml_detected & rule_detected, "detection_source"] = "ML + Rule"

		df.loc[ml_detected | rule_detected, "status"] = "Anomaly"

		return df


def main():
	detector = AnomalyDetector()

	df = pd.read_csv(DATA_PATH)

	if df.empty:
		raise ValueError("No flows to analyze")

	results = detector.detect(df)

	results.to_csv("data/anomalies.csv", index=False)

	run_id = create_analysis_run("offline")
	save_flows(results, run_id)

	print("\nResults saved to data/anomalies.csv")


if __name__ == "__main__":
	main()
