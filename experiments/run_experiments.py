"""
Master Experiment Runner (`run_experiments.py`)
Executes:
1. Synthetic OpenFlow dataset generation & ML model training (Random Forest & Isolation Forest)
2. Multi-model classification evaluation (Precision, Recall, F1-Score, FPR, Inference Latency)
3. Three-way network architecture benchmark (Traditional vs SDN Monitoring Only vs AI-Powered SDN Guardian)
Saves all measured outputs to `experiments/results/`.
"""
import os
import json
import pandas as pd

from detection.evaluation import run_comparative_evaluation
from experiments.benchmark import run_three_way_network_comparison


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results")
    os.makedirs(results_dir, exist_ok=True)

    print("[1/2] Running ML & Rule-Based Anomaly Detection Evaluation...")
    eval_json_path = os.path.join(results_dir, "classification_metrics.json")
    ml_results = run_comparative_evaluation(eval_json_path)

    print("[2/2] Running 3-Way Network Performance Benchmark...")
    net_results = run_three_way_network_comparison()
    net_json_path = os.path.join(results_dir, "network_benchmark_summary.json")
    with open(net_json_path, "w", encoding="utf-8") as f:
        json.dump(net_results, f, indent=2)

    ts_csv_path = os.path.join(results_dir, "network_timeseries_benchmark.csv")
    pd.DataFrame(net_results["timeseries"]).to_csv(ts_csv_path, index=False)

    combined_report = {
        "classification_evaluation": ml_results,
        "network_performance_evaluation": {
            "evaluation_label": net_results["evaluation_label"],
            "scenarios": net_results["scenarios"],
        },
    }
    master_path = os.path.join(results_dir, "complete_experiment_results.json")
    with open(master_path, "w", encoding="utf-8") as f:
        json.dump(combined_report, f, indent=2)

    print("Saved experiment outputs to:", results_dir)
    print(json.dumps(combined_report, indent=2))
    return combined_report


if __name__ == "__main__":
    main()
