import asyncio
import logging
import time
from collections import defaultdict

import numpy as np
from sklearn.preprocessing import StandardScaler

from features.process_features import ProcessFeatureExtractor, PROCESS_FEATURE_NAMES
from features.file_features import FileFeatureExtractor, FILE_FEATURE_NAMES
from features.network_features import NetworkFeatureExtractor, NETWORK_FEATURE_NAMES

logger = logging.getLogger("edr.features.pipeline")

TOTAL_FEATURES = len(PROCESS_FEATURE_NAMES) + len(NETWORK_FEATURE_NAMES)


class FeaturePipeline:
    def __init__(self, config, process_monitor):
        self.config = config.get("features", {})
        self.window_size = self.config.get("window_size", 30)

        self.process_extractor = ProcessFeatureExtractor(process_monitor)
        self.file_extractor = FileFeatureExtractor()
        self.network_extractor = NetworkFeatureExtractor()

        self.scaler = StandardScaler()
        self._scaler_fitted = False
        self._fit_buffer = []
        self._fit_buffer_size = 200

        self.feature_cache = defaultdict(lambda: None)
        self.training_buffer = []
        self.training_buffer_max = 10000

        self.subscribers = []
        self._running = False

    def subscribe(self, callback):
        self.subscribers.append(callback)

    async def process_event(self, event):
        event_type = event.get("type", "")
        data = event.get("data", {})

        if event_type in ("process_create", "process_snapshot"):
            proc_features = self.process_extractor.extract(data)
            pid = data.get("pid", 0)

            net_features = self.network_extractor.extract(data)

            combined = np.concatenate([proc_features, net_features])

            normalized = self._normalize(combined)
            if normalized is None:
                return

            feature_vector = {
                "pid": pid,
                "process_name": data.get("name", ""),
                "timestamp": time.time(),
                "features": normalized,
                "raw_features": combined,
                "feature_names": PROCESS_FEATURE_NAMES + NETWORK_FEATURE_NAMES,
                "event_type": event_type,
                "event_data": data,
            }

            self.feature_cache[pid] = feature_vector

            self.training_buffer.append(normalized)
            if len(self.training_buffer) > self.training_buffer_max:
                self.training_buffer = self.training_buffer[-self.training_buffer_max:]

            for callback in self.subscribers:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(feature_vector)
                    else:
                        callback(feature_vector)
                except Exception as e:
                    logger.error("Feature subscriber error: %s", e)

        elif event_type in ("file_create", "file_modify", "file_delete", "file_rename"):
            file_features = self.file_extractor.extract(data)
            file_vector = {
                "timestamp": time.time(),
                "features": file_features,
                "feature_names": FILE_FEATURE_NAMES,
                "event_type": event_type,
                "event_data": data,
            }
            for callback in self.subscribers:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(file_vector)
                    else:
                        callback(file_vector)
                except Exception as e:
                    logger.error("Feature subscriber error: %s", e)

        elif event_type in ("net_connect", "net_listen"):
            pid = data.get("pid", 0)
            net_features = self.network_extractor.extract(data)
            net_vector = {
                "pid": pid,
                "timestamp": time.time(),
                "features": net_features,
                "feature_names": NETWORK_FEATURE_NAMES,
                "event_type": event_type,
                "event_data": data,
            }
            for callback in self.subscribers:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(net_vector)
                    else:
                        callback(net_vector)
                except Exception as e:
                    logger.error("Feature subscriber error: %s", e)

        elif event_type == "process_terminate":
            pid = data.get("pid", 0)
            self.process_extractor.cleanup(pid)
            self.network_extractor.cleanup(pid)
            self.file_extractor.cleanup(pid)
            self.feature_cache.pop(pid, None)

    def _normalize(self, features):
        features = np.nan_to_num(features, nan=0.0, posinf=1e6, neginf=-1e6)

        if not self._scaler_fitted:
            self._fit_buffer.append(features)
            if len(self._fit_buffer) >= self._fit_buffer_size:
                X = np.array(self._fit_buffer)
                self.scaler.fit(X)
                self._scaler_fitted = True
                logger.info("Feature scaler fitted on %d samples", len(self._fit_buffer))
                self._fit_buffer = []
                return self.scaler.transform(features.reshape(1, -1))[0]
            return features

        return self.scaler.transform(features.reshape(1, -1))[0]

    def get_training_data(self):
        if not self.training_buffer:
            return None
        return np.array(self.training_buffer)

    def get_feature_vector(self, pid):
        return self.feature_cache.get(pid)
