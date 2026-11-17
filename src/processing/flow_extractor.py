import argparse
import pandas as pd

from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP

from collections import defaultdict

WINDOW_SIZE = 60

host_stats = defaultdict(lambda: {
	"dst_ports": set(),
	"dst_ips": set(),
	"connection_count": 0,
	"syn_only_count": 0
})

IDLE_TIMEOUT = 60

parser = argparse.ArgumentParser()

parser.add_argument("--input", default="data/pcaps")
parser.add_argument("--output", default="data/flows.csv")

args = parser.parse_args()

pcap_files = sorted(Path(args.input).rglob("*.pcap"))

if not pcap_files:
	raise FileNotFoundError("No PCAP files found")

print(f"Found {len(pcap_files)} PCAP files")

flow_features = []


def save_flow(flow):
	duration = flow["end_time"] - flow["start_time"]

	flow["duration"] = duration

	flow["avg_packet_size"] = (
		flow["total_bytes"] / flow["packet_count"]
	)

	flow["byte_ratio"] = (
		flow["bwd_bytes"] / max(flow["fwd_bytes"], 1)
	)

	if duration > 0:
		flow["packets_per_second"] = (
			flow["packet_count"] / duration
		)

		flow["bytes_per_second"] = (
			flow["total_bytes"] / duration
		)
	else:
		flow["packets_per_second"] = 0
		flow["bytes_per_second"] = 0

	flow_features.append(flow)


for pcap_file in pcap_files:
	print(f"Processing: {pcap_file.name}")

	flows = {}

	with PcapReader(str(pcap_file)) as packets:
		for packet in packets:
			if IP not in packet:
				continue

			ip = packet[IP]

			src_port = 0
			dst_port = 0

			if TCP in packet:
				src_port = packet[TCP].sport
				dst_port = packet[TCP].dport

			elif UDP in packet:
				src_port = packet[UDP].sport
				dst_port = packet[UDP].dport

			src = (ip.src, src_port)
			dst = (ip.dst, dst_port)

			flow_key = (
				tuple(sorted((src, dst))),
				ip.proto
			)

			timestamp = float(packet.time)

			window = int(timestamp // WINDOW_SIZE)

			if TCP in packet:
				flags = int(packet[TCP].flags)

				if flags & 0x02 and not flags & 0x10:
					host_key = (
						pcap_file.name,
						ip.src,
						window
					)

					host_stats[host_key]["syn_only_count"] += 1
			if flow_key in flows:
				old_flow = flows[flow_key]

				if timestamp - old_flow["end_time"] > IDLE_TIMEOUT:
					save_flow(old_flow)
					del flows[flow_key]

			if flow_key not in flows:
				host_key = (
					pcap_file.name,
					ip.src,
					window
				)

				stats = host_stats[host_key]

				stats["dst_ips"].add(ip.dst)

				if TCP in packet or UDP in packet:
					stats["dst_ports"].add(dst_port)

				stats["connection_count"] += 1
				flows[flow_key] = {
					"pcap_file": pcap_file.name,
					"src_ip": ip.src,
					"dst_ip": ip.dst,
					"src_port": src_port,
					"dst_port": dst_port,
					"protocol": ip.proto,
					"packet_count": 0,
					"total_bytes": 0,
					"start_time": timestamp,
					"end_time": timestamp,
					"fwd_packets": 0,
					"bwd_packets": 0,
					"fwd_bytes": 0,
					"bwd_bytes": 0,
					"syn_count": 0,
					"ack_count": 0,
					"fin_count": 0,
					"rst_count": 0
				}

			flow = flows[flow_key]

			packet_size = len(packet)

			flow["packet_count"] += 1
			flow["total_bytes"] += packet_size

			flow["start_time"] = min(
				flow["start_time"], timestamp
			)

			flow["end_time"] = max(
				flow["end_time"], timestamp
			)

			if src == (flow["src_ip"], flow["src_port"]):
				flow["fwd_packets"] += 1
				flow["fwd_bytes"] += packet_size
			else:
				flow["bwd_packets"] += 1
				flow["bwd_bytes"] += packet_size

			if TCP in packet:
				flags = int(packet[TCP].flags)

				if flags & 0x02:
					flow["syn_count"] += 1

				if flags & 0x10:
					flow["ack_count"] += 1

				if flags & 0x01:
					flow["fin_count"] += 1

				if flags & 0x04:
					flow["rst_count"] += 1

	for flow in flows.values():
		save_flow(flow)

if not flow_features:
	raise ValueError("No IPv4 flows extracted")

df = pd.DataFrame(flow_features)

df["window"] = (
	df["start_time"] // WINDOW_SIZE
).astype(int)

host_features = []

for key, stats in host_stats.items():
	pcap_file, src_ip, window = key

	host_features.append({
		"pcap_file": pcap_file,
		"src_ip": src_ip,
		"window": window,
		"unique_dst_ports": len(stats["dst_ports"]),
		"unique_dst_ips": len(stats["dst_ips"]),
		"connection_count": stats["connection_count"],
		"syn_only_count": stats["syn_only_count"]
	})

host_df = pd.DataFrame(host_features)

df = df.merge(
	host_df,
	on=["pcap_file", "src_ip", "window"],
	how="left"
)

df = df.drop(columns=["window"])

Path(args.output).parent.mkdir(
	parents=True,
	exist_ok=True
)

df.to_csv(args.output, index=False)

print(f"\nTotal flows: {len(df)}")
print(f"Flows saved to {args.output}")
