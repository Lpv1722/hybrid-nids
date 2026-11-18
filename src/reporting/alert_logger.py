import logging
from pathlib import Path

LOG_PATH = Path("logs/alerts.log")


def setup_logger():
	LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

	logger = logging.getLogger("nids")
	logger.setLevel(logging.INFO)
	logger.propagate = False

	if not logger.handlers:
		handler = logging.FileHandler(LOG_PATH, encoding="utf-8")

		formatter = logging.Formatter(
			"%(asctime)s | %(message)s",
			datefmt="%Y-%m-%d %H:%M:%S"
		)

		handler.setFormatter(formatter)
		logger.addHandler(handler)

	return logger
