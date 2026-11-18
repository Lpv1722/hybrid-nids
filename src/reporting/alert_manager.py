class AlertManager:
	def __init__(self, window_size=60):
		self.window_size = window_size
		self.seen_alerts = set()

	def should_alert(self, flow):
		if not flow["rule_alert"]:
			return True

		window = int(flow["start_time"] // self.window_size)

		key = (
			flow["src_ip"],
			flow["rule_alert"],
			window
		)

		if key in self.seen_alerts:
			return flow["ml_status"] == "Anomaly"

		self.seen_alerts.add(key)

		return True

	def cleanup(self, current_time):
		current_window = int(current_time // self.window_size)

		self.seen_alerts = {
			key for key in self.seen_alerts
			if key[2] >= current_window - 2
		}
