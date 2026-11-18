
import argparse
import time
import pandas as pd

from scapy.all import sniff

from src.processing.flow_manager import FlowManager
from src.detection.anomaly_detector import AnomalyDetector
from src.reporting.alert_manager import AlertManager
from src.reporting.alert_logger import setup_logger


def main():
	parser = argparse.ArgumentParser()

	parser.add_argument("--interface", required=True)
	parser.add_argument("--timeout", type=int, default=60)

	args = parser.parse_args()

	manager = FlowManager(timeout=args.timeout)
	detector = AnomalyDetector()
	alert_manager = AlertManager()
	logger = setup_logger()

	def process_packet(packet):
		manager.process_packet(packet)

	def process_flows(flows):
		if not flows:
			return

		df = pd.DataFrame(flows)
		results = detector.detect(df)

		for _, flow in results.iterrows():
			if flow["status"] != "Anomaly":
				continue

			if not alert_manager.should_alert(flow):
				continue

			rule = flow["rule_alert"]
			source = flow["detection_source"]

			if rule:
				message = (
					f"[ALERT] {rule}\n"
					f"  Source IP: {flow['src_ip']}\n"
					f"  Unique destination ports: {flow['unique_dst_ports']}\n"
					f"  Detection source: {source}"
				)

				log_message = (
					f"{rule} | "
					f"Source: {flow['src_ip']} | "
					f"Ports: {flow['unique_dst_ports']} | "
					f"Detection: {source}"
				)

			else:
				message = (
					f"[ML ALERT] "
					f"{flow['src_ip']}:{flow['src_port']} -> "
					f"{flow['dst_ip']}:{flow['dst_port']} | "
					f"Score: {flow['anomaly_score']:.4f}"
				)

				log_message = (
					f"ML Anomaly | "
					f"Source: {flow['src_ip']} | "
					f"Destination: {flow['dst_ip']} | "
					f"Score: {flow['anomaly_score']:.4f}"
				)

			print(message, flush=True)
			logger.info(log_message)

	print(f"Starting live NIDS on {args.interface}...")

	try:
		while True:
			sniff(
				iface=args.interface,
				prn=process_packet,
				store=False,
				timeout=1
			)

			now = time.time()

			completed_flows = manager.expire_flows(now)

			process_flows(completed_flows)

			alert_manager.cleanup(now)

	except KeyboardInterrupt:
		print("\nStopping live NIDS...")

	finally:
		process_flows(manager.flush_flows())
		print("Live NIDS stopped.")


if __name__ == "__main__":
	main()
