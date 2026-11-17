import subprocess
import sys

scripts = [
	"src/processing/flow_extractor.py",
	"src/detection/anomaly_detector.py",
	"src/reporting/report.py"
]

print("Starting NIDS...", flush=True)

for script in scripts:
	subprocess.run(
		[sys.executable, script],
		check=True
	)

print("\nAnalysis completed!")
