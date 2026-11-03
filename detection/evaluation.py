"""
Comparative Evaluation Pipeline:
Benchmarks Rule-Based Threshold Detection, Isolation Forest, and Random Forest Classifier
on the held-out OpenFlow test split, computing confusion matrices, Precision, Recall,
F1-Score, False-Positive Rate (FPR), and single-flow inference latency.
"""
import os
import json
import time
from typing import Dict, Any
import numpy as np
import pandas as pd

from .feature_extractor import FlowFeatureVector
from .rule_detector import RuleBasedDetector, RuleConfig
from .train_model import train_and_save_models


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, latency_ms_per_flow: float) -> Dict[str, Any]:
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2.0 * precision * recall) / max(1e-9, precision + recall)
    accuracy = (tp + tn) / max(1, len(y_true))
    fpr = fp / max(1, fp + tn)

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "inference_latency_ms": round(latency_ms_per_flow, 4),
    }


def run_comparative_evaluation(output_json_path: str = None) -> Dict[str, Any]:
    bundle = train_and_save_models()
    test_df: pd.DataFrame = bundle["test_df"]
    X_test: np.ndarray = bundle["X_test"]
    y_test: np.ndarray = bundle["y_test"]
    rf_model = bundle["rf_model"]
    if_model = bundle["if_model"]

    # 1. Rule-Based Evaluation
    rule_detector = RuleBasedDetector(RuleConfig())
    t0 = time.perf_counter()
    rule_preds = []
    for _, row in test_df.iterrows():
        fv = FlowFeatureVector(
            flow_id="eval",
            dpid=1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.100",
            src_port=12345,
            dst_port=80,
            ip_proto=int(row["ip_proto"]),
            packet_count=int(row["packet_count"]),
            byte_count=int(row["byte_count"]),
            flow_duration_sec=float(row["flow_duration_sec"]),
            packets_per_sec=float(row["packets_per_sec"]),
            bytes_per_sec=float(row["bytes_per_sec"]),
            source_flow_count=int(row["source_flow_count"]),
            traffic_variation_cv=float(row["traffic_variation_cv"]),
            syn_flag_ratio=float(row["syn_flag_ratio"]),
            avg_packet_size=float(row["byte_count"]) / max(1, int(row["packet_count"])),
        )
        res = rule_detector.evaluate(fv)
        rule_preds.append(1 if res["is_anomalous"] else 0)
    rule_lat_ms = ((time.perf_counter() - t0) * 1000.0) / len(test_df)
    rule_metrics = compute_binary_metrics(y_test, np.array(rule_preds), rule_lat_ms)

    # 2. Isolation Forest Evaluation
    t1 = time.perf_counter()
    if_preds = if_model.predict(X_test)
    if_lat_ms = ((time.perf_counter() - t1) * 1000.0) / len(test_df)
    if_metrics = compute_binary_metrics(y_test, if_preds, if_lat_ms)

    # 3. Random Forest Evaluation
    t2 = time.perf_counter()
    rf_preds = rf_model.predict(X_test, threshold=0.55)
    rf_lat_ms = ((time.perf_counter() - t2) * 1000.0) / len(test_df)
    rf_metrics = compute_binary_metrics(y_test, rf_preds, rf_lat_ms)

    # 4. Hybrid Ensemble (Rule + Random Forest)
    t3 = time.perf_counter()
    rf_probs = rf_model.predict_proba(X_test)[:, 1]
    hybrid_preds = ((rf_probs >= 0.52) | ((np.array(rule_preds) == 1) & (rf_probs >= 0.35))).astype(int)
    hybrid_lat_ms = rule_lat_ms + rf_lat_ms
    hybrid_metrics = compute_binary_metrics(y_test, hybrid_preds, hybrid_lat_ms)

    summary = {
        "dataset_type": "SYNTHETIC_OPENFLOW_FLOW_DATASET",
        "total_samples": bundle["n_train"] + bundle["n_test"],
        "train_samples": bundle["n_train"],
        "test_samples": bundle["n_test"],
        "feature_importances": bundle["feature_importances"],
        "models": {
            "Rule-Based Threshold": rule_metrics,
            "Isolation Forest (Unsupervised)": if_metrics,
            "Random Forest (Supervised)": rf_metrics,
            "Hybrid Guardian (Rule + RF)": hybrid_metrics,
        },
    }

    if output_json_path:
        os.makedirs(os.path.dirname(output_json_path), exist_ok=True)
        with open(output_json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

    return summary


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(base, "saved_models", "evaluation_metrics.json")
    res = run_comparative_evaluation(out_file)
    print(json.dumps(res, indent=2))
