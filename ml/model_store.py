import logging
import os
import pickle
import time

import torch

logger = logging.getLogger("edr.ml.model_store")


class ModelStore:
    def __init__(self, model_dir="data/models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)

    def save_isolation_forest(self, model):
        if not model.is_fitted:
            return
        path = os.path.join(self.model_dir, "isolation_forest.pkl")
        with open(path, "wb") as f:
            pickle.dump({
                "model": model.model,
                "timestamp": time.time(),
            }, f)
        logger.info("Saved Isolation Forest model to %s", path)

    def load_isolation_forest(self, detector):
        path = os.path.join(self.model_dir, "isolation_forest.pkl")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            detector.model = data["model"]
            detector._is_fitted = True
            logger.info("Loaded Isolation Forest model from %s", path)
            return True
        except Exception as e:
            logger.error("Failed to load IF model: %s", e)
            return False

    def save_autoencoder(self, detector):
        if not detector.is_fitted:
            return
        state = detector.get_state_dict()
        if state:
            path = os.path.join(self.model_dir, "autoencoder.pt")
            torch.save(state, path)
            logger.info("Saved Autoencoder model to %s", path)

    def load_autoencoder(self, detector):
        path = os.path.join(self.model_dir, "autoencoder.pt")
        if not os.path.exists(path):
            return False
        try:
            state = torch.load(path, weights_only=False)
            detector.load_state_dict(state)
            logger.info("Loaded Autoencoder model from %s", path)
            return True
        except Exception as e:
            logger.error("Failed to load autoencoder model: %s", e)
            return False

    def save_all(self, isolation_forest, autoencoder):
        self.save_isolation_forest(isolation_forest)
        self.save_autoencoder(autoencoder)

    def load_all(self, isolation_forest, autoencoder):
        if_loaded = self.load_isolation_forest(isolation_forest)
        ae_loaded = self.load_autoencoder(autoencoder)
        return if_loaded or ae_loaded
