
import argparse
import subprocess
import sys


def main():
	parser = argparse.ArgumentParser(
		description="Hybrid Network Intrusion Detection System"
	)

	parser.add_argument(
		"--mode",
		choices=["offline", "live"],
		default="offline"
	)

	parser.add_argument(
		"--interface",
		default=None
	)

	parser.add_argument(
		"--timeout",
		type=int,
		default=60
	)

	args = parser.parse_args()

	if args.mode == "offline":
		modules = [
			"src.processing.flow_extractor",
			"src.detection.anomaly_detector",
			"src.reporting.report"
		]

		print("Starting offline NIDS...", flush=True)

		for module in modules:
			subprocess.run(
				[sys.executable, "-m", module],
				check=True
			)

		print("\nAnalysis completed!")

	elif args.mode == "live":
		if not args.interface:
			parser.error("--interface is required in live mode")

		print("Starting live NIDS...", flush=True)

		subprocess.run(
			[
				sys.executable,
				"-m",
				"src.capture.live_capture",
				"--interface",
				args.interface,
				"--timeout",
				str(args.timeout)
			],
			check=True
		)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\nNIDS stopped by user.")
