import argparse
import pandas as pd

from pathlib import Path
from scapy.all import PcapReader
from flow_manager import FlowManager


parser = argparse.ArgumentParser()

parser.add_argument("--input", default="data/pcaps")
parser.add_argument("--output", default="data/flows.csv")

args = parser.parse_args()

pcap_files = sorted(Path(args.input).rglob("*.pcap"))

if not pcap_files:
	raise FileNotFoundError("No PCAP files found")

print(f"Found {len(pcap_files)} PCAP files")

flow_features = []

for pcap_file in pcap_files:
	print(f"Processing: {pcap_file.name}")

	manager = FlowManager(timeout=60)

	with PcapReader(str(pcap_file)) as packets:
		for packet in packets:
			manager.process_packet(packet)

	completed_flows = manager.flush_flows()

	for flow in completed_flows:
		flow["pcap_file"] = pcap_file.name
		flow_features.append(flow)

if not flow_features:
	raise ValueError("No IPv4 flows extracted")

df = pd.DataFrame(flow_features)

Path(args.output).parent.mkdir(
	parents=True,
	exist_ok=True
)

df.to_csv(args.output, index=False)

print(f"\nTotal flows: {len(df)}")
print(f"Flows saved to {args.output}")
