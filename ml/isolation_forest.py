import logging
import numpy as np
from sklearn.ensemble import IsolationForest as SklearnIF

logger = logging.getLogger("edr.ml.iforest")


class IsolationForestDetector:
    def __init__(self, config):
        ml_config = config.get("ml", {}).get("isolation_forest", {})
        self.n_estimators = ml_config.get("n_estimators", 200)
        self.contamination = ml_config.get("contamination", 0.05)
        self.retrain_interval = ml_config.get("retrain_interval", 1000)

        self.model = None
        self._samples_since_train = 0
        self._is_fitted = False
        self._min_samples = 50

    def fit(self, X):
        if len(X) < self._min_samples:
            logger.info("Not enough samples to train IF (%d < %d)", len(X), self._min_samples)
            return False

        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        self.model = SklearnIF(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        self._is_fitted = True
        self._samples_since_train = 0
        logger.info("Isolation Forest trained on %d samples", len(X))
        return True

    def predict(self, features):
        if not self._is_fitted:
            return 0.0

        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        X = features.reshape(1, -1)

        raw_score = self.model.decision_function(X)[0]
        prediction = self.model.predict(X)[0]

        threat_score = self._score_to_threat(raw_score, prediction)

        self._samples_since_train += 1
        return threat_score

    def needs_retrain(self):
        return self._samples_since_train >= self.retrain_interval

    def _score_to_threat(self, raw_score, prediction):
        # raw_score: negative = more anomalous, positive = more normal
        # prediction: -1 = anomaly, 1 = normal
        if prediction == -1:
            threat = 50 + min(50, abs(raw_score) * 100)
        else:
            threat = max(0, 30 - raw_score * 30)

        return min(100.0, max(0.0, threat))

    @property
    def is_fitted(self):
        return self._is_fitted

    def get_params(self):
        return {
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "is_fitted": self._is_fitted,
            "samples_since_train": self._samples_since_train,
        }
