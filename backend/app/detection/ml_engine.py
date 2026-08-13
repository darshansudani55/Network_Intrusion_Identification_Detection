"""
ML / Anomaly Detection Engine
--------------------------------
Loads the trained RandomForest model and scores flow feature dicts.
This is the "anomaly-based" half of the hybrid system: it can catch attack
variants that don't cross the rule engine's fixed thresholds.
"""

import os
import joblib
import numpy as np
from dataclasses import dataclass
from typing import Optional

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models")


@dataclass
class MLVerdict:
    triggered: bool
    attack_type: Optional[str]
    confidence: float
    class_probabilities: dict


class MLEngine:
    def __init__(self, model_dir: str = MODEL_DIR, threshold: float = 0.6):
        self.threshold = threshold
        self.loaded = False
        try:
            self.model = joblib.load(os.path.join(model_dir, "rf_model.joblib"))
            self.scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
            self.label_encoder = joblib.load(os.path.join(model_dir, "label_encoder.joblib"))
            self.feature_columns = joblib.load(os.path.join(model_dir, "feature_columns.joblib"))
            self.loaded = True
        except FileNotFoundError:
            print("[!] ML model artifacts not found. Run train_model.py first. "
                  "ML engine will pass through with no detections until trained.")

    def evaluate(self, feature_dict: dict) -> MLVerdict:
        if not self.loaded:
            return MLVerdict(False, None, 0.0, {})

        x = np.array([[feature_dict.get(col, 0.0) for col in self.feature_columns]])
        x_s = self.scaler.transform(x)

        probs = self.model.predict_proba(x_s)[0]
        classes = self.label_encoder.classes_
        prob_map = {cls: float(p) for cls, p in zip(classes, probs)}

        pred_idx = int(np.argmax(probs))
        pred_class = classes[pred_idx]
        pred_conf = float(probs[pred_idx])

        if pred_class != "BENIGN" and pred_conf >= self.threshold:
            return MLVerdict(True, pred_class, pred_conf, prob_map)
        return MLVerdict(False, None, pred_conf, prob_map)
