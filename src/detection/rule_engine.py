PORT_SCAN_THRESHOLD = 50
SYN_THRESHOLD = 50


def detect_rules(flow):
	alerts = []

	if (
		flow["unique_dst_ports"] >= PORT_SCAN_THRESHOLD
		and flow["syn_only_count"] >= SYN_THRESHOLD
	):
		alerts.append("Possible Port Scan")

	return ", ".join(alerts)
