import logging
import time

import numpy as np

logger = logging.getLogger("edr.ml.ensemble")


class EnsembleDetector:
    def __init__(self, config, isolation_forest, autoencoder):
        ml_config = config.get("ml", {})
        weights = ml_config.get("ensemble", {}).get("weights", {})
        self.weight_if = weights.get("isolation_forest", 0.4)
        self.weight_ae = weights.get("autoencoder", 0.4)
        self.weight_behavioral = weights.get("behavioral", 0.2)

        thresholds = ml_config.get("thresholds", {})
        self.threshold_normal = thresholds.get("normal", 30)
        self.threshold_suspicious = thresholds.get("suspicious", 60)
        self.threshold_malicious = thresholds.get("malicious", 80)
        self.threshold_critical = thresholds.get("critical", 90)

        self.isolation_forest = isolation_forest
        self.autoencoder = autoencoder

        self._recent_scores = []
        self._max_history = 1000

    def predict(self, features, behavioral_score=0.0):
        if_score = 0.0
        ae_score = 0.0

        if self.isolation_forest.is_fitted:
            if_score = self.isolation_forest.predict(features)

        if self.autoencoder.is_fitted:
            ae_score = self.autoencoder.predict(features)

        if self.isolation_forest.is_fitted and self.autoencoder.is_fitted:
            total = (
                self.weight_if * if_score
                + self.weight_ae * ae_score
                + self.weight_behavioral * behavioral_score
            )
        elif self.isolation_forest.is_fitted:
            total = 0.6 * if_score + 0.4 * behavioral_score
        elif self.autoencoder.is_fitted:
            total = 0.6 * ae_score + 0.4 * behavioral_score
        else:
            total = behavioral_score

        total = min(100.0, max(0.0, total))

        self._recent_scores.append({
            "timestamp": time.time(),
            "if_score": if_score,
            "ae_score": ae_score,
            "behavioral_score": behavioral_score,
            "ensemble_score": total,
        })
        if len(self._recent_scores) > self._max_history:
            self._recent_scores = self._recent_scores[-self._max_history:]

        return {
            "threat_score": total,
            "severity": self._classify_severity(total),
            "if_score": if_score,
            "ae_score": ae_score,
            "behavioral_score": behavioral_score,
        }

    def _classify_severity(self, score):
        if score >= self.threshold_critical:
            return "critical"
        elif score >= self.threshold_malicious:
            return "high"
        elif score >= self.threshold_suspicious:
            return "medium"
        elif score >= self.threshold_normal:
            return "low"
        return "info"

    def check_retrain(self, training_data):
        retrained = []
        if training_data is not None and len(training_data) >= 50:
            if self.isolation_forest.needs_retrain() or not self.isolation_forest.is_fitted:
                if self.isolation_forest.fit(training_data):
                    retrained.append("isolation_forest")

            if self.autoencoder.needs_retrain() or not self.autoencoder.is_fitted:
                if self.autoencoder.fit(training_data):
                    retrained.append("autoencoder")

        return retrained

    def get_metrics(self):
        recent = self._recent_scores[-100:] if self._recent_scores else []

        if recent:
            scores = [s["ensemble_score"] for s in recent]
            return {
                "avg_threat_score": float(np.mean(scores)),
                "max_threat_score": float(np.max(scores)),
                "min_threat_score": float(np.min(scores)),
                "std_threat_score": float(np.std(scores)),
                "samples_scored": len(self._recent_scores),
                "isolation_forest": self.isolation_forest.get_params(),
                "autoencoder": self.autoencoder.get_params(),
                "weights": {
                    "isolation_forest": self.weight_if,
                    "autoencoder": self.weight_ae,
                    "behavioral": self.weight_behavioral,
                },
                "severity_distribution": self._severity_distribution(recent),
            }
        return {
            "avg_threat_score": 0,
            "samples_scored": 0,
            "isolation_forest": self.isolation_forest.get_params(),
            "autoencoder": self.autoencoder.get_params(),
        }

    def _severity_distribution(self, scores):
        dist = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for s in scores:
            sev = self._classify_severity(s["ensemble_score"])
            dist[sev] += 1
        return dist
