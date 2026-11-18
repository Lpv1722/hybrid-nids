from scapy.layers.inet import IP, TCP
from src.processing.flow_manager import FlowManager


manager = FlowManager(timeout=60)

packet1 = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
	sport=12345, dport=80, flags="S"
)

packet2 = IP(src="192.168.1.20", dst="192.168.1.10") / TCP(
	sport=80, dport=12345, flags="SA"
)

packet1.time = 1000
packet2.time = 1001

manager.process_packet(packet1)
manager.process_packet(packet2)

flows = manager.expire_flows(1062)

assert len(flows) == 1

flow = flows[0]

assert flow["packet_count"] == 2
assert flow["fwd_packets"] == 1
assert flow["bwd_packets"] == 1
assert flow["duration"] == 1
assert flow["syn_count"] == 2
assert flow["ack_count"] == 1
assert flow["unique_dst_ports"] == 1
assert flow["syn_only_count"] == 1

print("All tests passed!")
