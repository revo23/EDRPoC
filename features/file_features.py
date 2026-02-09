import logging
import time
from collections import defaultdict

import numpy as np

logger = logging.getLogger("edr.features.file")

FILE_FEATURE_NAMES = [
    "file_entropy", "file_size", "is_sensitive_dir", "is_executable",
    "is_hidden", "extension_risk", "write_frequency", "is_temp_dir",
]


class FileFeatureExtractor:
    def __init__(self):
        self.write_history = defaultdict(list)

    def extract(self, event_data):
        now = time.time()

        pid = event_data.get("pid", 0)
        path = event_data.get("path", "")
        if pid:
            self.write_history[pid].append(now)
            cutoff = now - 60
            self.write_history[pid] = [
                t for t in self.write_history[pid] if t > cutoff
            ]

        write_freq = len(self.write_history.get(pid, []))

        entropy = event_data.get("entropy", 0.0)
        file_size = event_data.get("size", 0)
        is_sensitive = 1.0 if event_data.get("is_sensitive_dir", False) else 0.0
        is_executable = 1.0 if event_data.get("is_executable", False) else 0.0
        is_hidden = 1.0 if event_data.get("is_hidden", False) else 0.0
        ext_risk = event_data.get("extension_risk", 0.1)
        is_temp = 1.0 if event_data.get("is_temp_dir", False) else 0.0

        features = np.array([
            float(entropy),
            float(file_size) / (1024 * 1024),
            float(is_sensitive),
            float(is_executable),
            float(is_hidden),
            float(ext_risk),
            float(write_freq),
            float(is_temp),
        ], dtype=np.float32)

        return features

    def cleanup(self, pid):
        self.write_history.pop(pid, None)
