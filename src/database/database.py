
import os
import psycopg
import pandas as pd

from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def get_connection():
	return psycopg.connect(
		host="127.0.0.1",
		port=5432,
		dbname="nids_db",
		user="nids",
		password=os.environ["POSTGRES_PASSWORD"]
	)

def create_analysis_run(mode):
	with get_connection() as conn:
		with conn.cursor() as cur:
			cur.execute(
				"""
				INSERT INTO analysis_runs (mode)
				VALUES (%s)
				RETURNING id
				""",
				(mode,)
			)

			return cur.fetchone()[0]


def save_flows(df, run_id):
	with get_connection() as conn:
		with conn.cursor() as cur:
			for _, flow in df.iterrows():
				cur.execute(
					"""
					INSERT INTO network_flows (
						run_id, src_ip, dst_ip,
						src_port, dst_port, protocol,
						packet_count, total_bytes,
						duration, anomaly_score, status
					)
					VALUES (%s, %s, %s, %s, %s, %s,
					        %s, %s, %s, %s, %s)
					RETURNING id
					""",
					(
						run_id,
						flow["src_ip"],
						flow["dst_ip"],
						int(flow["src_port"]),
						int(flow["dst_port"]),
						int(flow["protocol"]),
						int(flow["packet_count"]),
						int(flow["total_bytes"]),
						float(flow["duration"]),
						float(flow["anomaly_score"]),
						flow["status"]
					)
				)

				flow_id = cur.fetchone()[0]

				if flow["status"] == "Anomaly":
					cur.execute(
						"""
						INSERT INTO alerts (
							flow_id, detection_source, rule_alert
						)
						VALUES (%s, %s, %s)
						""",
						(
							flow_id,
							flow["detection_source"],
							flow["rule_alert"] or None
						)
					)

	print(f"Saved {len(df)} flows to PostgreSQL")

def save_live_alert(flow, run_id):
	rule_alert = flow.get("rule_alert")

	if pd.isna(rule_alert) or not rule_alert:
		rule_alert = None

	with get_connection() as conn:
		with conn.cursor() as cur:
			cur.execute(
				"""
				INSERT INTO network_flows (
					run_id, src_ip, dst_ip,
					src_port, dst_port, protocol,
					packet_count, total_bytes,
					duration, anomaly_score, status
				)
				VALUES (%s, %s, %s, %s, %s, %s,
				        %s, %s, %s, %s, %s)
				RETURNING id
				""",
				(
					run_id,
					flow["src_ip"],
					flow["dst_ip"],
					int(flow["src_port"]),
					int(flow["dst_port"]),
					int(flow["protocol"]),
					int(flow["packet_count"]),
					int(flow["total_bytes"]),
					float(flow["duration"]),
					float(flow["anomaly_score"]),
					flow["status"]
				)
			)

			flow_id = cur.fetchone()[0]

			cur.execute(
				"""
				INSERT INTO alerts (
					flow_id, detection_source, rule_alert
				)
				VALUES (%s, %s, %s)
				""",
				(
					flow_id,
					flow["detection_source"],
					rule_alert
				)
			)
