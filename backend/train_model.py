"""
ML Model Training Script
--------------------------
Trains a RandomForest classifier to detect BENIGN / PortScan / DoS traffic
from flow-level features.

Usage:
    python train_model.py --data /path/to/CICIDS2017.csv
    python train_model.py                      # uses bundled synthetic dataset generator

If you have the real CICIDS2017 dataset (Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv,
Wednesday-workingHours.pcap_ISCX.csv for DoS, etc.), point --data at the merged/cleaned CSV.
Expected label column: 'Label' with values like 'BENIGN', 'PortScan', 'DoS Hulk',
'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'DDoS'.

This script will:
  1. Load data (real or synthetic)
  2. Map fine-grained labels -> {BENIGN, PortScan, DoS}
  3. Select/engineer the feature columns matching flow_extractor.Flow.to_feature_dict()
  4. Train RandomForestClassifier
  5. Print classification report + confusion matrix
  6. Save model + scaler + label encoder to backend/models/
"""

import argparse
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLUMNS = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes", "packets_per_sec", "bytes_per_sec",
    "avg_packet_size", "max_packet_size", "min_packet_size", "avg_iat",
    "syn_count", "ack_count", "fin_count", "rst_count", "psh_count", "urg_count",
    "syn_ack_ratio", "fwd_bwd_ratio",
]


def label_to_class(label: str) -> str:
    label = str(label).strip().upper()
    if label == "BENIGN":
        return "BENIGN"
    if "PORTSCAN" in label or "PORT SCAN" in label:
        return "PortScan"
    if "DOS" in label or "DDOS" in label:
        return "DoS"
    return "BENIGN"  # unknown labels fold into benign to stay conservative


def load_real_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    # CICIDS2017 columns differ slightly by file; try to map common ones onto our schema
    rename_map = {
        "Flow Duration": "flow_duration",
        "Total Fwd Packets": "total_fwd_packets",
        "Total Backward Packets": "total_bwd_packets",
        "Total Length of Fwd Packets": "total_fwd_bytes",
        "Total Length of Bwd Packets": "total_bwd_bytes",
        "Flow Packets/s": "packets_per_sec",
        "Flow Bytes/s": "bytes_per_sec",
        "Average Packet Size": "avg_packet_size",
        "Max Packet Length": "max_packet_size",
        "Min Packet Length": "min_packet_size",
        "Flow IAT Mean": "avg_iat",
        "SYN Flag Count": "syn_count",
        "ACK Flag Count": "ack_count",
        "FIN Flag Count": "fin_count",
        "RST Flag Count": "rst_count",
        "PSH Flag Count": "psh_count",
        "URG Flag Count": "urg_count",
        "Label": "Label",
    }
    df = df.rename(columns=rename_map)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
    df["syn_ack_ratio"] = df["syn_count"] / (df["ack_count"] + 1)
    df["fwd_bwd_ratio"] = df["total_fwd_packets"] / (df["total_bwd_packets"] + 1)
    df["class"] = df["Label"].apply(label_to_class)
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    return df[FEATURE_COLUMNS + ["class"]]


def generate_synthetic_dataset(n_per_class: int = 4000, seed: int = 42) -> pd.DataFrame:
    """
    Generates a synthetic-but-realistic dataset matching CICIDS2017 statistical
    shape, for demo/dev purposes when the real dataset isn't available locally.
    Distributions are hand-tuned to reflect known attack signatures:
      - BENIGN: moderate everything, balanced fwd/bwd, low SYN-only ratio
      - PortScan: many short flows, high syn_ack_ratio, tiny byte counts, many
        distinct-port touches (captured upstream, not a per-flow feature here)
      - DoS: either high pps volumetric (Hulk/GoldenEye) or long-duration
        low-pps (Slowloris) - we generate a mixture
    """
    rng = np.random.default_rng(seed)
    rows = []

    # BENIGN
    for _ in range(n_per_class):
        dur = rng.exponential(5) + 0.1
        fwd_p = rng.poisson(20) + 1
        bwd_p = rng.poisson(18) + 1
        rows.append({
            "flow_duration": dur,
            "total_fwd_packets": fwd_p,
            "total_bwd_packets": bwd_p,
            "total_fwd_bytes": fwd_p * rng.normal(500, 100),
            "total_bwd_bytes": bwd_p * rng.normal(480, 100),
            "packets_per_sec": (fwd_p + bwd_p) / dur,
            "bytes_per_sec": (fwd_p * 500 + bwd_p * 480) / dur,
            "avg_packet_size": rng.normal(500, 80),
            "max_packet_size": rng.normal(1200, 100),
            "min_packet_size": rng.normal(64, 10),
            "avg_iat": rng.exponential(0.2),
            "syn_count": 1,
            "ack_count": fwd_p + bwd_p - 2,
            "fin_count": 1,
            "rst_count": 0,
            "psh_count": rng.poisson(3),
            "urg_count": 0,
            "class": "BENIGN",
        })

    # PORT SCAN — short flows, mostly SYN with no/low ACK, tiny payloads
    for _ in range(n_per_class):
        dur = rng.exponential(0.3) + 0.01
        rows.append({
            "flow_duration": dur,
            "total_fwd_packets": rng.integers(1, 3),
            "total_bwd_packets": rng.integers(0, 2),
            "total_fwd_bytes": rng.normal(60, 10),
            "total_bwd_bytes": rng.normal(20, 10),
            "packets_per_sec": rng.uniform(5, 50),
            "bytes_per_sec": rng.uniform(50, 500),
            "avg_packet_size": rng.normal(50, 10),
            "max_packet_size": rng.normal(60, 10),
            "min_packet_size": rng.normal(40, 5),
            "avg_iat": rng.exponential(0.05),
            "syn_count": 1,
            "ack_count": rng.integers(0, 1),
            "fin_count": 0,
            "rst_count": rng.integers(0, 1),
            "psh_count": 0,
            "urg_count": 0,
            "class": "PortScan",
        })

    # DOS — mixture of volumetric (Hulk/GoldenEye) and slow (Slowloris)
    for i in range(n_per_class):
        if i % 2 == 0:
            # Volumetric
            dur = rng.exponential(2) + 0.1
            fwd_p = rng.integers(200, 2000)
            rows.append({
                "flow_duration": dur,
                "total_fwd_packets": fwd_p,
                "total_bwd_packets": rng.integers(0, 10),
                "total_fwd_bytes": fwd_p * rng.normal(400, 100),
                "total_bwd_bytes": rng.normal(50, 20),
                "packets_per_sec": fwd_p / dur,
                "bytes_per_sec": (fwd_p * 400) / dur,
                "avg_packet_size": rng.normal(400, 60),
                "max_packet_size": rng.normal(1400, 100),
                "min_packet_size": rng.normal(40, 5),
                "avg_iat": rng.exponential(0.01),
                "syn_count": rng.integers(150, 1800),
                "ack_count": rng.integers(0, 20),
                "fin_count": 0,
                "rst_count": rng.integers(0, 5),
                "psh_count": rng.integers(0, 50),
                "urg_count": 0,
                "class": "DoS",
            })
        else:
            # Slow-rate
            dur = rng.uniform(30, 120)
            rows.append({
                "flow_duration": dur,
                "total_fwd_packets": rng.integers(10, 40),
                "total_bwd_packets": rng.integers(0, 5),
                "total_fwd_bytes": rng.normal(300, 50),
                "total_bwd_bytes": rng.normal(20, 10),
                "packets_per_sec": rng.uniform(0.1, 1.5),
                "bytes_per_sec": rng.uniform(2, 20),
                "avg_packet_size": rng.normal(80, 20),
                "max_packet_size": rng.normal(150, 20),
                "min_packet_size": rng.normal(40, 5),
                "avg_iat": rng.uniform(1, 5),
                "syn_count": 1,
                "ack_count": rng.integers(5, 15),
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": rng.integers(8, 30),
                "urg_count": 0,
                "class": "DoS",
            })

    df = pd.DataFrame(rows)
    df["syn_ack_ratio"] = df["syn_count"] / (df["ack_count"] + 1)
    df["fwd_bwd_ratio"] = df["total_fwd_packets"] / (df["total_bwd_packets"] + 1)
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    return df[FEATURE_COLUMNS + ["class"]]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, default=None,
                         help="Path to CICIDS2017 CSV. If omitted, synthetic data is used.")
    parser.add_argument("--n_estimators", type=int, default=200)
    args = parser.parse_args()

    if args.data and os.path.exists(args.data):
        print(f"[+] Loading real dataset from {args.data}")
        df = load_real_dataset(args.data)
    else:
        print("[!] No --data path given (or file not found). Using synthetic dataset "
              "so the pipeline is fully runnable for dev/demo purposes.")
        print("    For your final report, replace this with actual CICIDS2017 CSVs "
              "(Wednesday DoS + Friday PortScan files) via --data.")
        df = generate_synthetic_dataset()

    print(f"[+] Dataset shape: {df.shape}")
    print(df["class"].value_counts())

    X = df[FEATURE_COLUMNS].values
    y = df["class"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.25, random_state=42, stratify=y_enc
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_train_s, y_train)

    y_pred = clf.predict(X_test_s)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[+] Test Accuracy: {acc:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(pd.DataFrame(
        confusion_matrix(y_test, y_pred),
        index=le.classes_, columns=le.classes_,
    ))

    # Feature importance (useful chart for your report)
    importances = pd.Series(clf.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("\nTop feature importances:")
    print(importances.head(10))

    joblib.dump(clf, os.path.join(MODEL_DIR, "rf_model.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.joblib"))
    joblib.dump(FEATURE_COLUMNS, os.path.join(MODEL_DIR, "feature_columns.joblib"))
    print(f"\n[+] Saved model artifacts to {MODEL_DIR}")


if __name__ == "__main__":
    main()
