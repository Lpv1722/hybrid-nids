from src.detection.rule_engine import detect_rules


assert detect_rules({
	"unique_dst_ports": 100,
	"unique_dst_ips": 1,
	"syn_only_count": 100
}) == "Possible Port Scan"

assert detect_rules({
	"unique_dst_ports": 1,
	"unique_dst_ips": 30,
	"syn_only_count": 60
}) == "Possible Host Scan"

assert detect_rules({
	"unique_dst_ports": 1,
	"unique_dst_ips": 1,
	"syn_only_count": 1000
}) == "Possible SYN Flood"

assert detect_rules({
	"unique_dst_ports": 3,
	"unique_dst_ips": 2,
	"syn_only_count": 5
}) == ""

print("All rule engine tests passed!")
