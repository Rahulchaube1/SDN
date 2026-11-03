"""
Reproducible Synthetic OpenFlow Flow Dataset Generator & Model Trainer
Generates labeled OpenFlow 1.3 flow records representing:
- Normal HTTP/HTTPS web browsing, DNS lookups, SSH sessions, and database queries
- High-throughput legitimate bulk file transfers and flash-crowd micro-bursts (borderline normal)
- Simulated DDoS traffic profiles (TCP SYN flood, UDP volumetric flood, ICMP flood, stealth flow-table exhaustion)
"""
import os
import json
import pickle
import time
from typing import Dict, Any
import numpy as np
import pandas as pd

from .feature_extractor import FEATURE_NAMES
from .ml_detector import PureNumpyRandomForest, PureNumpyIsolationForest


def generate_synthetic_openflow_dataset(n_samples: int = 4000, seed: int = 2026) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_normal = int(n_samples * 0.65)
    n_attack = n_samples - n_normal
    records = []

    # 1. Normal Traffic Flows (including 8% flash-crowd / bulk transfer borderline flows)
    for _ in range(n_normal):
        profile = rng.choice(["web", "api", "bulk_transfer", "flash_crowd"], p=[0.56, 0.26, 0.11, 0.07])
        if profile == "web":
            dur = float(rng.uniform(2.0, 45.0))
            pps = float(rng.gamma(shape=3.0, scale=42.0))
            pkt_size = float(rng.normal(780, 160))
            src_flows = int(rng.integers(1, 14))
            cv = float(rng.uniform(0.12, 0.62))
            syn_ratio = float(rng.uniform(0.01, 0.14))
            proto = 6
        elif profile == "api":
            dur = float(rng.uniform(1.0, 20.0))
            pps = float(rng.gamma(shape=2.5, scale=35.0))
            pkt_size = float(rng.normal(420, 90))
            src_flows = int(rng.integers(2, 18))
            cv = float(rng.uniform(0.15, 0.72))
            syn_ratio = float(rng.uniform(0.02, 0.18))
            proto = int(rng.choice([6, 17]))
        elif profile == "bulk_transfer":
            dur = float(rng.uniform(6.0, 60.0))
            pps = float(rng.normal(1050, 280))
            pkt_size = float(rng.normal(1360, 95))
            src_flows = int(rng.integers(2, 12))
            cv = float(rng.uniform(0.10, 0.50))
            syn_ratio = float(rng.uniform(0.01, 0.08))
            proto = 6
        else:
            # Flash-crowd burst: legitimate surge that mimics low-rate DDoS in several dimensions
            dur = float(rng.uniform(1.0, 6.0))
            pps = float(rng.normal(1320, 340))
            pkt_size = float(rng.normal(280, 110))
            src_flows = int(rng.integers(20, 42))
            cv = float(rng.uniform(0.85, 1.48))
            syn_ratio = float(rng.uniform(0.35, 0.68))
            proto = int(rng.choice([6, 17]))

        pps = max(5.0, pps)
        pkt_size = max(64.0, pkt_size)
        pkt_count = int(max(1, round(pps * dur)))
        byte_count = int(round(pkt_count * pkt_size))
        bps = byte_count / dur

        records.append({
            "packet_count": pkt_count,
            "byte_count": byte_count,
            "flow_duration_sec": round(dur, 4),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "source_flow_count": src_flows,
            "traffic_variation_cv": round(cv, 4),
            "syn_flag_ratio": round(syn_ratio, 4),
            "ip_proto": proto,
            "attack_category": "NORMAL",
            "label": 0,
        })

    # 2. Simulated Abnormal / DDoS Flows
    for _ in range(n_attack):
        atk = rng.choice(["syn_flood", "udp_flood", "icmp_flood", "stealth_slow_flood"], p=[0.36, 0.30, 0.20, 0.14])
        if atk == "syn_flood":
            dur = float(rng.uniform(0.5, 12.0))
            pps = float(rng.normal(2550, 650))
            pkt_size = float(rng.normal(74, 12))
            src_flows = int(rng.integers(36, 125))
            cv = float(rng.uniform(1.15, 2.35))
            syn_ratio = float(rng.uniform(0.74, 0.99))
            proto = 6
        elif atk == "udp_flood":
            dur = float(rng.uniform(0.8, 15.0))
            pps = float(rng.normal(3200, 780))
            pkt_size = float(rng.normal(960, 220))
            src_flows = int(rng.integers(24, 80))
            cv = float(rng.uniform(1.05, 2.15))
            syn_ratio = 0.0
            proto = 17
        elif atk == "icmp_flood":
            dur = float(rng.uniform(0.5, 10.0))
            pps = float(rng.normal(2300, 580))
            pkt_size = float(rng.normal(96, 18))
            src_flows = int(rng.integers(22, 65))
            cv = float(rng.uniform(1.15, 2.40))
            syn_ratio = 0.0
            proto = 1
        else:
            # Stealth low-rate flow-table exhaustion (overlaps with normal flash-crowd traffic)
            dur = float(rng.uniform(1.5, 14.0))
            pps = float(rng.normal(860, 290))
            pkt_size = float(rng.normal(210, 85))
            src_flows = int(rng.integers(22, 52))
            cv = float(rng.uniform(0.78, 1.45))
            syn_ratio = float(rng.uniform(0.38, 0.72))
            proto = 6

        pps = max(60.0, pps)
        pkt_size = max(54.0, pkt_size)
        pkt_count = int(max(10, round(pps * dur)))
        byte_count = int(round(pkt_count * pkt_size))
        bps = byte_count / dur

        records.append({
            "packet_count": pkt_count,
            "byte_count": byte_count,
            "flow_duration_sec": round(dur, 4),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "source_flow_count": src_flows,
            "traffic_variation_cv": round(cv, 4),
            "syn_flag_ratio": round(syn_ratio, 4),
            "ip_proto": proto,
            "attack_category": atk.upper(),
            "label": 1,
        })

    df = pd.DataFrame(records)
    perm = rng.permutation(len(df))
    return df.iloc[perm].reset_index(drop=True)


def preprocess_matrix(df: pd.DataFrame) -> np.ndarray:
    X = df[FEATURE_NAMES].to_numpy(dtype=np.float64)
    X_proc = X.copy()
    for idx in (0, 1, 3, 4):
        X_proc[:, idx] = np.log1p(np.maximum(0.0, X_proc[:, idx]))
    return X_proc


def train_and_save_models(output_dir: str = None, n_samples: int = 4000, seed: int = 2026) -> Dict[str, Any]:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    save_dir = output_dir or os.path.join(base_dir, "saved_models")
    os.makedirs(save_dir, exist_ok=True)

    df = generate_synthetic_openflow_dataset(n_samples=n_samples, seed=seed)
    dataset_csv = os.path.join(save_dir, "synthetic_openflow_dataset.csv")
    df.to_csv(dataset_csv, index=False)

    split_idx = int(len(df) * 0.75)
    train_df = df.iloc[:split_idx].reset_index(drop=True)
    test_df = df.iloc[split_idx:].reset_index(drop=True)

    X_train_raw = preprocess_matrix(train_df)
    y_train = train_df["label"].to_numpy(dtype=int)
    X_test_raw = preprocess_matrix(test_df)
    y_test = test_df["label"].to_numpy(dtype=int)

    mean = np.mean(X_train_raw, axis=0)
    std = np.maximum(1e-6, np.std(X_train_raw, axis=0))
    X_train = (X_train_raw - mean) / std
    X_test = (X_test_raw - mean) / std

    # 1. Train Supervised Random Forest
    t0 = time.perf_counter()
    rf = PureNumpyRandomForest(n_estimators=35, max_depth=7, seed=seed)
    rf.fit(X_train, y_train)
    rf_train_sec = time.perf_counter() - t0

    # 2. Train Isolation Forest on normal baseline traffic (with 6% expected outlier tail)
    t1 = time.perf_counter()
    X_train_normal = X_train[y_train == 0]
    iforest = PureNumpyIsolationForest(n_estimators=65, max_samples=256, contamination=0.06, seed=seed)
    iforest.fit(X_train_normal)
    if_train_sec = time.perf_counter() - t1

    with open(os.path.join(save_dir, "random_forest_model.pkl"), "wb") as f:
        pickle.dump(rf, f, protocol=4)
    with open(os.path.join(save_dir, "isolation_forest_model.pkl"), "wb") as f:
        pickle.dump(iforest, f, protocol=4)
    with open(os.path.join(save_dir, "feature_scaler.pkl"), "wb") as f:
        pickle.dump({"mean": mean.tolist(), "std": std.tolist(), "features": FEATURE_NAMES}, f, protocol=4)

    return {
        "dataset_csv": dataset_csv,
        "n_train": len(train_df),
        "n_test": len(test_df),
        "rf_train_time_sec": round(rf_train_sec, 4),
        "if_train_time_sec": round(if_train_sec, 4),
        "feature_importances": dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in rf.feature_importances_])),
        "test_df": test_df,
        "X_test": X_test,
        "y_test": y_test,
        "rf_model": rf,
        "if_model": iforest,
    }


if __name__ == "__main__":
    info = train_and_save_models()
    print(f"Trained models on {info['n_train']} samples (test={info['n_test']}).")
