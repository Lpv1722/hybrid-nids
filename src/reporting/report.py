import pandas as pd

df = pd.read_csv("data/anomalies.csv")

anomalies = df[df["status"] == "Anomaly"]
normal = df[df["status"] == "Normal"]

total = len(df)
anomaly_rate = len(anomalies) / total * 100 if total else 0

print("\n" + "=" * 60)
print("           NETWORK ANOMALY DETECTION REPORT")
print("=" * 60)

print(f"PCAP files:       {df['pcap_file'].nunique()}")
print(f"Total flows:      {total}")
print(f"Normal flows:     {len(normal)}")
print(f"Anomalous flows:  {len(anomalies)}")
print(f"Anomaly rate:     {anomaly_rate:.2f}%")

print("\nDetection statistics:")
print(anomalies["detection_source"].value_counts().to_string())

print("\nTop 10 anomalies:")
print("-" * 60)

columns = [
	"src_ip",
	"dst_ip",
	"dst_port",
	"packet_count",
	"total_bytes",
	"anomaly_score",
	"detection_source",
	"rule_alert"
]

if anomalies.empty:
	print("No anomalies detected")
else:
	print(
		anomalies.sort_values("anomaly_score")[columns]
		.head(10)
		.to_string(index=False)
	)

print("\nResults: data/anomalies.csv")
print("=" * 60)
