PORT_SCAN_THRESHOLD = 50
HOST_SCAN_THRESHOLD = 20
SYN_THRESHOLD = 50
SYN_FLOOD_THRESHOLD = 500

def detect_rules(flow):
	alerts = []

	# Port Scan
	if (
		flow["unique_dst_ports"] >= PORT_SCAN_THRESHOLD
		and flow["syn_only_count"] >= SYN_THRESHOLD
	):
		alerts.append("Possible Port Scan")

	# Host Scan
	if (
		flow["unique_dst_ips"] >= HOST_SCAN_THRESHOLD
		and flow["syn_only_count"] >= SYN_THRESHOLD
	):
		alerts.append("Possible Host Scan")

	# SYN Flood
	if (
		flow["syn_only_count"] >= SYN_FLOOD_THRESHOLD
		and flow["unique_dst_ips"] == 1
		and flow["unique_dst_ports"] == 1
	):
		alerts.append("Possible SYN Flood")

	return ", ".join(alerts)
