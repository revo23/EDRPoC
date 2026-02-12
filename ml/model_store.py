import hashlib
import hmac
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
        self._signing_key = self._load_or_create_signing_key()

    def _load_or_create_signing_key(self):
        """Load or generate HMAC signing key for model integrity verification."""
        key_path = os.path.join(self.model_dir, ".signing_key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                return f.read()
        key = os.urandom(32)
        with open(key_path, "wb") as f:
            f.write(key)
        os.chmod(key_path, 0o600)
        logger.info("Generated new model signing key")
        return key

    def _sign_data(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 signature for data."""
        return hmac.new(self._signing_key, data, hashlib.sha256).digest()

    def _verify_data(self, data: bytes, signature: bytes) -> bool:
        """Verify HMAC-SHA256 signature for data."""
        expected = hmac.new(self._signing_key, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    def save_isolation_forest(self, model):
        if not model.is_fitted:
            return
        path = os.path.join(self.model_dir, "isolation_forest.pkl")
        sig_path = path + ".sig"
        data = pickle.dumps({
            "model": model.model,
            "timestamp": time.time(),
        })
        with open(path, "wb") as f:
            f.write(data)
        with open(sig_path, "wb") as f:
            f.write(self._sign_data(data))
        logger.info("Saved Isolation Forest model to %s", path)

    def load_isolation_forest(self, detector):
        path = os.path.join(self.model_dir, "isolation_forest.pkl")
        sig_path = path + ".sig"
        if not os.path.exists(path):
            return False
        if not os.path.exists(sig_path):
            logger.error("Missing signature file for %s — refusing to load", path)
            return False
        try:
            with open(path, "rb") as f:
                data = f.read()
            with open(sig_path, "rb") as f:
                signature = f.read()
            if not self._verify_data(data, signature):
                logger.error("Signature verification FAILED for %s — model may be tampered", path)
                return False
            obj = pickle.loads(data)
            detector.model = obj["model"]
            detector._is_fitted = True
            logger.info("Loaded Isolation Forest model from %s (signature verified)", path)
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
            sig_path = path + ".sig"
            torch.save(state, path)
            with open(path, "rb") as f:
                data = f.read()
            with open(sig_path, "wb") as f:
                f.write(self._sign_data(data))
            logger.info("Saved Autoencoder model to %s", path)

    def load_autoencoder(self, detector):
        path = os.path.join(self.model_dir, "autoencoder.pt")
        sig_path = path + ".sig"
        if not os.path.exists(path):
            return False
        if not os.path.exists(sig_path):
            logger.error("Missing signature file for %s — refusing to load", path)
            return False
        try:
            with open(path, "rb") as f:
                data = f.read()
            with open(sig_path, "rb") as f:
                signature = f.read()
            if not self._verify_data(data, signature):
                logger.error("Signature verification FAILED for %s — model may be tampered", path)
                return False
            state = torch.load(path, weights_only=True)
            detector.load_state_dict(state)
            logger.info("Loaded Autoencoder model from %s (signature verified)", path)
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
