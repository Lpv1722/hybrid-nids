from scapy.layers.inet import IP, TCP, UDP


class FlowManager:
	def __init__(self, timeout=60):
		self.timeout = timeout
		self.flows = {}
		self.host_stats = {}
		self.window_size = 60
		self.pending_flows = []
	def get_flow_key(self, packet):
		ip = packet[IP]

		src_port = 0
		dst_port = 0

		if TCP in packet:
			src_port = packet[TCP].sport
			dst_port = packet[TCP].dport

		elif UDP in packet:
			src_port = packet[UDP].sport
			dst_port = packet[UDP].dport

		endpoints = tuple(sorted([
			(ip.src, src_port),
			(ip.dst, dst_port)
		]))

		return endpoints, ip.proto
	def create_flow(self, packet):
		ip = packet[IP]
		timestamp = float(packet.time)

		src_port = 0
		dst_port = 0

		if TCP in packet:
			src_port = packet[TCP].sport
			dst_port = packet[TCP].dport

		elif UDP in packet:
			src_port = packet[UDP].sport
			dst_port = packet[UDP].dport

		return {
			"src_ip": ip.src,
			"dst_ip": ip.dst,
			"src_port": src_port,
			"dst_port": dst_port,
			"protocol": ip.proto,
			"start_time": timestamp,
			"end_time": timestamp,
			"packet_count": 0,
			"total_bytes": 0,
			"fwd_packets": 0,
			"bwd_packets": 0,
			"fwd_bytes": 0,
			"bwd_bytes": 0,
			"syn_count": 0,
			"ack_count": 0,
			"fin_count": 0,
			"rst_count": 0
		}
	def update_flow(self, flow, packet):
		ip = packet[IP]
		timestamp = float(packet.time)
		size = len(packet)

		flow["start_time"] = min(flow["start_time"], timestamp)
		flow["end_time"] = max(flow["end_time"], timestamp)
		flow["packet_count"] += 1
		flow["total_bytes"] += size

		src_port = 0

		if TCP in packet:
			src_port = packet[TCP].sport
		elif UDP in packet:
			src_port = packet[UDP].sport

		if (ip.src, src_port) == (flow["src_ip"], flow["src_port"]):
			flow["fwd_packets"] += 1
			flow["fwd_bytes"] += size
		else:
			flow["bwd_packets"] += 1
			flow["bwd_bytes"] += size

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
	def finalize_flow(self, flow):
		duration = flow["end_time"] - flow["start_time"]

		flow["duration"] = duration

		flow["avg_packet_size"] = (
			flow["total_bytes"] / max(flow["packet_count"], 1)
		)

		flow["byte_ratio"] = (
			flow["bwd_bytes"] / max(flow["fwd_bytes"], 1)
		)

		flow["packets_per_second"] = (
			flow["packet_count"] / duration if duration > 0 else 0
		)

		flow["bytes_per_second"] = (
			flow["total_bytes"] / duration if duration > 0 else 0
		)

		return flow
	def process_packet(self, packet):
		if IP not in packet:
			return

		key = self.get_flow_key(packet)
		timestamp = float(packet.time)

		if key in self.flows:
			flow = self.flows[key]

			if timestamp - flow["end_time"] > self.timeout:
				self.pending_flows.append(self.finalize_flow(flow))
				del self.flows[key]

		is_new_flow = key not in self.flows

		if is_new_flow:
			self.flows[key] = self.create_flow(packet)

		self.update_host_stats(packet, is_new_flow)
		self.update_flow(self.flows[key], packet)
		
	def expire_flows(self, current_time):
		for key, flow in list(self.flows.items()):
			if current_time - flow["end_time"] > self.timeout:
				self.pending_flows.append(self.finalize_flow(flow))
				del self.flows[key]

		ready_flows = self.collect_ready_flows(current_time)

		self.cleanup_host_stats(current_time)

		return ready_flows
	def flush_flows(self):
		for flow in self.flows.values():
			self.pending_flows.append(self.finalize_flow(flow))

		self.flows.clear()

		ready_flows = self.collect_ready_flows(0, force=True)

		self.host_stats.clear()

		return ready_flows
	def update_host_stats(self, packet, is_new_flow):
		ip = packet[IP]
		timestamp = float(packet.time)

		window = int(timestamp // self.window_size)
		key = (ip.src, window)

		if key not in self.host_stats:
			self.host_stats[key] = {
				"dst_ports": set(),
				"dst_ips": set(),
				"connection_count": 0,
				"syn_only_count": 0
			}

		stats = self.host_stats[key]

		if is_new_flow:
			stats["connection_count"] += 1
			stats["dst_ips"].add(ip.dst)

			if TCP in packet:
				stats["dst_ports"].add(packet[TCP].dport)
			elif UDP in packet:
				stats["dst_ports"].add(packet[UDP].dport)

		if TCP in packet:
			flags = int(packet[TCP].flags)

			if flags & 0x02 and not flags & 0x10:
				stats["syn_only_count"] += 1
	def add_host_features(self, flow):
		window = int(flow["start_time"] // self.window_size)
		key = (flow["src_ip"], window)

		stats = self.host_stats.get(key, {})

		flow["unique_dst_ports"] = len(stats.get("dst_ports", set()))
		flow["unique_dst_ips"] = len(stats.get("dst_ips", set()))
		flow["connection_count"] = stats.get("connection_count", 0)
		flow["syn_only_count"] = stats.get("syn_only_count", 0)

		return flow
	def collect_ready_flows(self, current_time, force=False):
		current_window = int(current_time // self.window_size)

		ready_flows = []
		pending_flows = []

		for flow in self.pending_flows:
			window = int(flow["start_time"] // self.window_size)

			if window < current_window or force:
				ready_flows.append(self.add_host_features(flow))
			else:
				pending_flows.append(flow)

		self.pending_flows = pending_flows

		return ready_flows
	def cleanup_host_stats(self, current_time):
		current_window = int(current_time // self.window_size)

		active_windows = {
			(flow["src_ip"], int(flow["start_time"] // self.window_size))
			for flow in list(self.flows.values()) + self.pending_flows
		}

		for key in list(self.host_stats):
			if key[1] < current_window and key not in active_windows:
				del self.host_stats[key]
