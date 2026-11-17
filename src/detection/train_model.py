
import pandas as pd
import joblib

from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

DATA_PATH = Path("data/training_flows.csv")
MODEL_PATH = Path("models/isolation_forest.joblib")

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

# Load training data
df = pd.read_csv(DATA_PATH)

if df.empty:
    raise ValueError("Training dataset is empty")

# Select features
X = df[FEATURES].copy()

# Create preprocessing and ML pipeline
pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("model", IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=42
    ))
])

# Train the model
pipeline.fit(X)

# Save model
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(pipeline, MODEL_PATH)

print(f"Model trained on {len(X)} flows")
print(f"Model saved to {MODEL_PATH}")
