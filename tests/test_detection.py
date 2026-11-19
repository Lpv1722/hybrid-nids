from scapy.all import IP, TCP

from src.processing.flow_manager import FlowManager
from src.detection.rule_engine import detect_rules


manager = FlowManager()

for i in range(1, 101):
	packet = IP(
		src="192.168.1.10",
		dst=f"192.168.1.{i + 100}"
	) / TCP(
		sport=12345,
		dport=80,
		flags="S"
	)

	packet.time = 1200

	manager.process_packet(packet)

flows = manager.flush_flows()

assert len(flows) == 100
assert flows[0]["unique_dst_ips"] == 100
assert flows[0]["syn_only_count"] == 100
assert detect_rules(flows[0]) == "Possible Host Scan"

print("Host Scan integration test passed!")

manager = FlowManager()

for i in range(1000):
	packet = IP(
		src="192.168.1.10",
		dst="192.168.1.20"
	) / TCP(
		sport=10000 + i,
		dport=80,
		flags="S"
	)

	packet.time = 1200

	manager.process_packet(packet)

flows = manager.flush_flows()

assert len(flows) == 1000
assert flows[0]["unique_dst_ips"] == 1
assert flows[0]["unique_dst_ports"] == 1
assert flows[0]["syn_only_count"] == 1000
assert detect_rules(flows[0]) == "Possible SYN Flood"

print("SYN Flood integration test passed!")
