import logging
from collections import deque

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

logger = logging.getLogger("edr.ml.autoencoder")


class AutoencoderNetwork(nn.Module):
    def __init__(self, input_dim, hidden_dims=None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [64, 32, 16, 8]

        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        for dim in hidden_dims:
            encoder_layers.extend([nn.Linear(prev_dim, dim), nn.ReLU()])
            prev_dim = dim
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder
        decoder_layers = []
        decoder_dims = list(reversed(hidden_dims[:-1])) + [input_dim]
        prev_dim = hidden_dims[-1]
        for i, dim in enumerate(decoder_dims):
            encoder_layers_list = [nn.Linear(prev_dim, dim)]
            if i < len(decoder_dims) - 1:
                encoder_layers_list.append(nn.ReLU())
            decoder_layers.extend(encoder_layers_list)
            prev_dim = dim
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def encode(self, x):
        return self.encoder(x)


class AutoencoderDetector:
    def __init__(self, config):
        ml_config = config.get("ml", {}).get("autoencoder", {})
        self.hidden_dims = ml_config.get("hidden_dims", [64, 32, 16, 8])
        self.learning_rate = ml_config.get("learning_rate", 0.001)
        self.batch_size = ml_config.get("batch_size", 64)
        self.retrain_interval = ml_config.get("retrain_interval", 500)
        self.buffer_size = ml_config.get("buffer_size", 10000)

        self.model = None
        self.optimizer = None
        self.criterion = nn.MSELoss()
        self.device = torch.device("cpu")

        self._buffer = deque(maxlen=self.buffer_size)
        self._is_fitted = False
        self._samples_since_train = 0
        self._threshold = None
        self._input_dim = None

    def fit(self, X, epochs=50):
        if len(X) < 50:
            logger.info("Not enough samples for autoencoder (%d < 50)", len(X))
            return False

        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        self._input_dim = X.shape[1]

        self.model = AutoencoderNetwork(self._input_dim, self.hidden_dims).to(self.device)
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)

        tensor_X = torch.FloatTensor(X).to(self.device)
        dataset = torch.utils.data.TensorDataset(tensor_X, tensor_X)
        loader = torch.utils.data.DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_x, _ in loader:
                self.optimizer.zero_grad()
                output = self.model(batch_x)
                loss = self.criterion(output, batch_x)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0:
                avg_loss = total_loss / len(loader)
                logger.debug("Autoencoder epoch %d/%d, loss: %.6f", epoch + 1, epochs, avg_loss)

        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(tensor_X)
            errors = torch.mean((tensor_X - reconstructed) ** 2, dim=1).numpy()

        self._threshold = float(np.percentile(errors, 95))
        self._is_fitted = True
        self._samples_since_train = 0
        logger.info(
            "Autoencoder trained on %d samples, threshold: %.6f",
            len(X), self._threshold,
        )
        return True

    def predict(self, features):
        if not self._is_fitted or self.model is None:
            return 0.0

        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)
        tensor_x = torch.FloatTensor(features).unsqueeze(0).to(self.device)

        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(tensor_x)
            error = torch.mean((tensor_x - reconstructed) ** 2).item()

        threat_score = self._error_to_threat(error)

        self._buffer.append(features)
        self._samples_since_train += 1

        return threat_score

    def needs_retrain(self):
        return self._samples_since_train >= self.retrain_interval

    def _error_to_threat(self, error):
        if self._threshold is None or self._threshold == 0:
            return 0.0

        ratio = error / self._threshold
        if ratio <= 0.5:
            return ratio * 20
        elif ratio <= 1.0:
            return 10 + (ratio - 0.5) * 60
        elif ratio <= 2.0:
            return 40 + (ratio - 1.0) * 40
        else:
            return min(100.0, 80 + (ratio - 2.0) * 10)

    @property
    def is_fitted(self):
        return self._is_fitted

    def get_params(self):
        return {
            "hidden_dims": self.hidden_dims,
            "is_fitted": self._is_fitted,
            "threshold": self._threshold,
            "buffer_size": len(self._buffer),
            "samples_since_train": self._samples_since_train,
        }

    def get_state_dict(self):
        if self.model:
            return {
                "model_state": self.model.state_dict(),
                "threshold": self._threshold,
                "input_dim": self._input_dim,
                "hidden_dims": self.hidden_dims,
            }
        return None

    def load_state_dict(self, state):
        self._input_dim = state["input_dim"]
        self.hidden_dims = state["hidden_dims"]
        self._threshold = state["threshold"]
        self.model = AutoencoderNetwork(self._input_dim, self.hidden_dims).to(self.device)
        self.model.load_state_dict(state["model_state"])
        self.model.eval()
        self.optimizer = optim.Adam(self.model.parameters(), lr=self.learning_rate)
        self._is_fitted = True
