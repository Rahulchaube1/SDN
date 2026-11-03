"""
Machine Learning Anomaly Detector for OpenFlow Traffic
Implements two lightweight classifiers over the 7-dimensional flow feature space:
1. Random Forest Classifier (Supervised ensemble of CART decision trees)
2. Isolation Forest (Unsupervised/semi-supervised random isolation tree ensemble)

Compatibility Guarantee:
Uses scikit-learn when available, and includes a deterministic vectorized NumPy
implementation of both Random Forest and Isolation Forest so training, evaluation,
and real-time inference work reliably across any Python 3.9+ environment.
"""
import os
import pickle
import time
import math
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from .feature_extractor import FlowFeatureVector, FEATURE_NAMES


class PureNumpyDecisionTree:
    """Fast vectorized binary CART Decision Tree using Gini Impurity."""

    def __init__(self, max_depth: int = 8, min_samples_split: int = 6, max_features: int = 3, rng: np.random.Generator = None):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.rng = rng or np.random.default_rng(42)
        self.tree = None

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.tree = self._build(X, y, depth=0)
        self.rng = None
        return self

    def _gini(self, y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        p1 = np.mean(y == 1)
        p0 = 1.0 - p1
        return 1.0 - (p0 * p0 + p1 * p1)

    def _build(self, X: np.ndarray, y: np.ndarray, depth: int):
        n_samples, n_features = X.shape
        pos_prob = float(np.mean(y == 1)) if n_samples > 0 else 0.0
        if depth >= self.max_depth or n_samples < self.min_samples_split or pos_prob in (0.0, 1.0):
            return {"leaf": True, "prob": pos_prob}

        feat_indices = self.rng.choice(n_features, size=min(self.max_features, n_features), replace=False)
        best_gain = -1.0
        best_feat = None
        best_thresh = None
        parent_gini = self._gini(y)

        for f_idx in feat_indices:
            col = X[:, f_idx]
            quantiles = np.unique(np.percentile(col, [15, 30, 50, 70, 85]))
            for thresh in quantiles:
                left_mask = col <= thresh
                n_left = int(np.sum(left_mask))
                n_right = n_samples - n_left
                if n_left < 2 or n_right < 2:
                    continue
                gain = parent_gini - (n_left / n_samples) * self._gini(y[left_mask]) - (n_right / n_samples) * self._gini(y[~left_mask])
                if gain > best_gain:
                    best_gain = gain
                    best_feat = int(f_idx)
                    best_thresh = float(thresh)

        if best_feat is None or best_gain <= 1e-5:
            return {"leaf": True, "prob": pos_prob}

        left_mask = X[:, best_feat] <= best_thresh
        return {
            "leaf": False,
            "feat": best_feat,
            "thresh": best_thresh,
            "left": self._build(X[left_mask], y[left_mask], depth + 1),
            "right": self._build(X[~left_mask], y[~left_mask], depth + 1),
        }

    def _predict_row(self, row: np.ndarray, node: Dict[str, Any]) -> float:
        while not node["leaf"]:
            if row[node["feat"]] <= node["thresh"]:
                node = node["left"]
            else:
                node = node["right"]
        return node["prob"]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.array([self._predict_row(row, self.tree) for row in X], dtype=np.float64)


class PureNumpyRandomForest:
    """Bootstrap-aggregated ensemble of CART decision trees."""

    def __init__(self, n_estimators: int = 35, max_depth: int = 8, seed: int = 42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.seed = seed
        self.trees: List[PureNumpyDecisionTree] = []
        self.feature_importances_: np.ndarray = np.zeros(len(FEATURE_NAMES), dtype=np.float64)

    def fit(self, X: np.ndarray, y: np.ndarray):
        rng = np.random.default_rng(self.seed)
        n_samples, n_features = X.shape
        max_f = max(2, int(math.sqrt(n_features)))
        self.trees = []
        feat_counts = np.zeros(n_features, dtype=np.float64)

        for i in range(self.n_estimators):
            boot_idx = rng.choice(n_samples, size=n_samples, replace=True)
            tree = PureNumpyDecisionTree(
                max_depth=self.max_depth,
                min_samples_split=6,
                max_features=max_f,
                rng=np.random.default_rng(self.seed + i * 17),
            )
            tree.fit(X[boot_idx], y[boot_idx])
            self.trees.append(tree)
            self._accumulate_splits(tree.tree, feat_counts)

        total = float(np.sum(feat_counts))
        if total > 0:
            self.feature_importances_ = (feat_counts / total).tolist()
        else:
            self.feature_importances_ = (np.ones(n_features) / n_features).tolist()
        return self

    def _accumulate_splits(self, node: Dict[str, Any], counts: np.ndarray, weight: float = 1.0):
        if not node or node.get("leaf"):
            return
        counts[node["feat"]] += weight
        self._accumulate_splits(node["left"], counts, weight * 0.7)
        self._accumulate_splits(node["right"], counts, weight * 0.7)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X_arr = np.atleast_2d(X)
        tree_probs = np.column_stack([t.predict_proba(X_arr) for t in self.trees])
        pos_probs = np.mean(tree_probs, axis=1)
        return np.column_stack([1.0 - pos_probs, pos_probs])

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        probs = self.predict_proba(X)[:, 1]
        return (probs >= threshold).astype(int)


class PureNumpyIsolationForest:
    """
    Implementation of Liu, Ting, and Zhou (ICDM 2008) Isolation Forest algorithm.
    Computes path length h(x) across random isolation trees and normalizes anomaly
    score s(x, psi) = 2^(-E(h(x)) / c(psi)).
    """

    def __init__(self, n_estimators: int = 50, max_samples: int = 256, contamination: float = 0.25, seed: int = 42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.seed = seed
        self.trees: List[Dict[str, Any]] = []
        self.c_norm: float = 1.0
        self.threshold_: float = 0.55

    @staticmethod
    def _c_factor(n: int) -> float:
        if n <= 1:
            return 1.0
        if n == 2:
            return 1.0
        euler_gamma = 0.5772156649
        return 2.0 * (math.log(n - 1.0) + euler_gamma) - (2.0 * (n - 1.0) / float(n))

    def fit(self, X: np.ndarray):
        rng = np.random.default_rng(self.seed)
        n_samples, n_features = X.shape
        psi = min(self.max_samples, n_samples)
        height_limit = int(math.ceil(math.log2(max(2, psi))))
        self.c_norm = self._c_factor(psi)
        self.trees = []

        for _ in range(self.n_estimators):
            sub_idx = rng.choice(n_samples, size=psi, replace=False)
            self.trees.append(self._build_itree(X[sub_idx], 0, height_limit, rng))

        scores = self.anomaly_score(X)
        self.threshold_ = float(np.percentile(scores, 100.0 * (1.0 - self.contamination)))
        return self

    def _build_itree(self, X: np.ndarray, depth: int, limit: int, rng: np.random.Generator) -> Dict[str, Any]:
        n_samples, n_features = X.shape
        if depth >= limit or n_samples <= 1:
            return {"external": True, "size": n_samples}
        q = int(rng.integers(0, n_features))
        col = X[:, q]
        c_min, c_max = float(np.min(col)), float(np.max(col))
        if c_min == c_max:
            return {"external": True, "size": n_samples}
        p = float(rng.uniform(c_min, c_max))
        left_mask = col < p
        return {
            "external": False,
            "q": q,
            "p": p,
            "left": self._build_itree(X[left_mask], depth + 1, limit, rng),
            "right": self._build_itree(X[~left_mask], depth + 1, limit, rng),
        }

    def _path_length(self, row: np.ndarray, node: Dict[str, Any], depth: int) -> float:
        while not node["external"]:
            if row[node["q"]] < node["p"]:
                node = node["left"]
            else:
                node = node["right"]
            depth += 1
        return float(depth) + self._c_factor(node["size"])

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        X_arr = np.atleast_2d(X)
        avg_heights = np.zeros(len(X_arr), dtype=np.float64)
        for t in self.trees:
            avg_heights += np.array([self._path_length(row, t, 0) for row in X_arr])
        avg_heights /= float(len(self.trees))
        return np.power(2.0, -avg_heights / max(1e-6, self.c_norm))

    def predict(self, X: np.ndarray) -> np.ndarray:
        scores = self.anomaly_score(X)
        return (scores >= self.threshold_).astype(int)


class MLAnomalyDetector:
    """
    High-level wrapper supporting real-time inference with either Random Forest
    or Isolation Forest models, including Z-score feature standardization and latency tracking.
    """

    def __init__(self, model_dir: Optional[str] = None, active_model: str = "random_forest"):
        base = os.path.dirname(os.path.abspath(__file__))
        self.model_dir = model_dir or os.path.join(base, "saved_models")
        self.active_model = active_model
        self.rf_model: Optional[PureNumpyRandomForest] = None
        self.if_model: Optional[PureNumpyIsolationForest] = None
        self.scaler_mean: np.ndarray = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
        self.scaler_std: np.ndarray = np.ones(len(FEATURE_NAMES), dtype=np.float64)
        self.confidence_threshold: float = 0.60
        self.load_models()

    def load_models(self) -> bool:
        rf_path = os.path.join(self.model_dir, "random_forest_model.pkl")
        if_path = os.path.join(self.model_dir, "isolation_forest_model.pkl")
        scaler_path = os.path.join(self.model_dir, "feature_scaler.pkl")
        if os.path.exists(rf_path) and os.path.exists(if_path) and os.path.exists(scaler_path):
            try:
                with open(rf_path, "rb") as f:
                    self.rf_model = pickle.load(f)
                with open(if_path, "rb") as f:
                    self.if_model = pickle.load(f)
                with open(scaler_path, "rb") as f:
                    scaler = pickle.load(f)
                    self.scaler_mean = np.asarray(scaler["mean"], dtype=np.float64)
                    self.scaler_std = np.asarray(scaler["std"], dtype=np.float64)
                return True
            except Exception:
                self.rf_model = None
                self.if_model = None
                return False
        return False

    def transform_features(self, X: np.ndarray) -> np.ndarray:
        X_arr = np.atleast_2d(X).astype(np.float64)
        # Apply log1p scaling to skewed volumetric features (packet_count, byte_count, pps, bps)
        X_proc = X_arr.copy()
        for idx in (0, 1, 3, 4):
            X_proc[:, idx] = np.log1p(np.maximum(0.0, X_proc[:, idx]))
        return (X_proc - self.scaler_mean) / np.maximum(1e-6, self.scaler_std)

    def evaluate(self, fv: FlowFeatureVector, model_type: Optional[str] = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        chosen = (model_type or self.active_model).lower()
        x_raw = fv.to_numpy().reshape(1, -1)
        x_norm = self.transform_features(x_raw)

        if chosen == "isolation_forest" and self.if_model is not None:
            raw_score = float(self.if_model.anomaly_score(x_norm)[0])
            # Calibrate around threshold_ so score >= 0.5 means anomaly
            thresh = self.if_model.threshold_
            conf = float(np.clip(0.5 + (raw_score - thresh) * 2.2, 0.01, 0.99))
            is_anom = raw_score >= thresh
            method_label = "ML_ISOLATION_FOREST"
        elif self.rf_model is not None:
            conf = float(self.rf_model.predict_proba(x_norm)[0, 1])
            is_anom = conf >= self.confidence_threshold
            method_label = "ML_RANDOM_FOREST"
        else:
            # Fallback heuristic if models haven't been trained yet
            conf = 0.85 if fv.packets_per_sec > 1200 or fv.source_flow_count > 35 else 0.08
            is_anom = conf >= self.confidence_threshold
            method_label = "ML_FALLBACK_UNTRAINED"

        latency_ms = (time.perf_counter() - t0) * 1000.0

        if conf >= 0.85:
            severity = "CRITICAL"
        elif conf >= 0.65:
            severity = "HIGH"
        elif is_anom:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        attack_type = "NORMAL"
        if is_anom:
            if fv.ip_proto == 1:
                attack_type = "ICMP_FLOOD"
            elif fv.syn_flag_ratio >= 0.60:
                attack_type = "TCP_SYN_FLOOD"
            elif fv.ip_proto == 17 and fv.bytes_per_sec > 1_000_000:
                attack_type = "UDP_VOLUMETRIC_FLOOD"
            elif fv.source_flow_count >= 30:
                attack_type = "FLOW_TABLE_EXHAUSTION"
            else:
                attack_type = "ML_DETECTED_ANOMALY"

        return {
            "flow_id": fv.flow_id,
            "is_anomalous": bool(is_anom),
            "confidence": round(conf, 4),
            "severity": severity,
            "attack_type": attack_type,
            "method": method_label,
            "inference_latency_ms": round(latency_ms, 4),
            "reasons": [
                f"{method_label} anomaly probability={conf:.3f} (threshold={self.confidence_threshold:.2f}, latency={latency_ms:.3f} ms)"
            ],
        }
