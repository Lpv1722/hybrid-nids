# Hybrid Network Intrusion Detection System

## Overview

An educational network intrusion detection system developed as a
personal portfolio project to demonstrate practical skills in
cybersecurity, network traffic analysis, and machine learning.

Built with Python, Scapy, Pandas, and Scikit-learn, the system combines
Isolation Forest with rule-based detection to identify suspicious
network activity in PCAP files.

## Features

- Automated PCAP analysis
- Bidirectional network flow extraction
- Flow-based and host-based feature extraction
- Machine learning and rule-based detection
- Port scanning detection
- CLI reporting and CSV export

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Model Training

Place benign PCAP files in `data/training/`.

Extract training features:

```bash
python src/processing/flow_extractor.py \
    --input data/training \
    --output data/training_flows.csv
```

Train the model:

```bash
python src/detection/train_model.py
```

The trained model is saved to `models/isolation_forest.joblib`.

## Usage

A pretrained Isolation Forest model is included in the repository.
Model training is optional.

Place PCAP files in `data/pcaps/` and run:

    python main.py

Analysis results are saved to `data/anomalies.csv`.

### Offline Analysis

The system includes a PCAP analyzer that processes captured network traffic and detects potential anomalies using machine learning and rule-based detection.

To analyze PCAP files, place them in `data/pcaps/` and run:

```bash
python main.py --mode offline
```

Analysis results are saved to `data/anomalies.csv`.

## Database Setup

The system uses PostgreSQL to store network flows, alerts,
and analysis history.

Create a configuration file and set your password:

```bash
cp .env.example .env
```

Start PostgreSQL:

```bash
docker compose up -d
```

The database schema is initialized automatically on the first startup.

## Preliminary Results

| Test scenario | Total flows | Flagged flows | Anomaly rate |
|---|---:|---:|---:|
| Personal traffic | 1516 | 196 | 12.93% |
| Traffic analysis exercise | 749 | 6 | 0.80% |
| Laboratory port scan | 1160 | 1138 | 98.10% |

The rule-based engine successfully detected laboratory port scanning
activity that was missed by Isolation Forest.

These results are preliminary and do not represent validated
attack detection accuracy.

## Training Dataset

The model was trained on publicly available network traffic
and locally collected benign traffic.

Public dataset: [Network traffic for machine learning classification](https://data.mendeley.com/datasets/5pmnkshffm/1)

## Limitations

- Offline PCAP analysis only
- IPv4 support only
- Potential false positives
- Limited rule coverage

This project is intended for educational and demonstration purposes
and is not designed for production use.

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for details.
