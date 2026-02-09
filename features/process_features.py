import logging
import math
import time
from collections import defaultdict

import numpy as np

logger = logging.getLogger("edr.features.process")

PROCESS_FEATURE_NAMES = [
    "cpu_usage_mean", "cpu_usage_std", "memory_rss", "memory_growth_rate",
    "child_spawn_rate", "thread_count", "open_files_count", "net_connections",
    "cmdline_length", "cmdline_entropy", "is_shell_child", "tree_depth",
    "exe_entropy", "lifetime", "is_unsigned",
]


def shannon_entropy(text):
    if not text:
        return 0.0
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class ProcessFeatureExtractor:
    SHELL_NAMES = {"bash", "zsh", "sh", "fish", "csh", "tcsh", "dash", "ksh"}

    def __init__(self, process_monitor):
        self.process_monitor = process_monitor
        self.cpu_history = defaultdict(list)
        self.memory_history = defaultdict(list)
        self.child_spawn_times = defaultdict(list)

    def extract(self, event_data):
        pid = event_data.get("pid", 0)
        now = time.time()

        cpu = event_data.get("cpu_percent", 0) or 0
        self.cpu_history[pid].append(cpu)
        if len(self.cpu_history[pid]) > 30:
            self.cpu_history[pid] = self.cpu_history[pid][-30:]

        mem_rss = event_data.get("memory_rss", 0) or 0
        self.memory_history[pid].append((now, mem_rss))
        if len(self.memory_history[pid]) > 30:
            self.memory_history[pid] = self.memory_history[pid][-30:]

        ppid = event_data.get("ppid", 0)
        self.child_spawn_times[ppid].append(now)
        cutoff = now - 60
        self.child_spawn_times[ppid] = [
            t for t in self.child_spawn_times[ppid] if t > cutoff
        ]

        cpu_vals = self.cpu_history[pid]
        cpu_mean = np.mean(cpu_vals) if cpu_vals else 0
        cpu_std = np.std(cpu_vals) if len(cpu_vals) > 1 else 0

        mem_entries = self.memory_history[pid]
        if len(mem_entries) >= 2:
            dt = mem_entries[-1][0] - mem_entries[0][0]
            if dt > 0:
                memory_growth = (mem_entries[-1][1] - mem_entries[0][1]) / dt
            else:
                memory_growth = 0
        else:
            memory_growth = 0

        child_spawn_rate = len(self.child_spawn_times.get(pid, []))

        cmdline = event_data.get("cmdline", "")
        cmdline_length = len(cmdline)
        cmdline_ent = shannon_entropy(cmdline)

        parent_name = self.process_monitor.get_parent_name(pid)
        is_shell_child = 1.0 if parent_name.lower() in self.SHELL_NAMES else 0.0

        tree_depth = self.process_monitor.get_tree_depth(pid)

        exe = event_data.get("exe", "")
        exe_ent = 0.0
        if exe:
            try:
                with open(exe, "rb") as f:
                    header = f.read(4096)
                exe_ent = self._byte_entropy(header)
            except (OSError, PermissionError):
                pass

        create_time = event_data.get("create_time", now)
        lifetime = now - create_time if create_time else 0

        is_unsigned = 1.0
        exe_hash = event_data.get("exe_hash", "")
        if exe_hash:
            is_unsigned = 0.5

        features = np.array([
            float(cpu_mean),
            float(cpu_std),
            float(mem_rss) / (1024 * 1024),
            float(memory_growth) / (1024 * 1024),
            float(child_spawn_rate),
            float(event_data.get("num_threads", 0) or 0),
            float(event_data.get("open_files", 0) or 0),
            float(event_data.get("connections", 0) or 0),
            float(cmdline_length),
            float(cmdline_ent),
            float(is_shell_child),
            float(tree_depth),
            float(exe_ent),
            float(lifetime),
            float(is_unsigned),
        ], dtype=np.float32)

        return features

    def _byte_entropy(self, data):
        if not data:
            return 0.0
        counts = np.zeros(256)
        for b in data:
            counts[b] += 1
        probs = counts[counts > 0] / len(data)
        return float(-np.sum(probs * np.log2(probs)))

    def cleanup(self, pid):
        self.cpu_history.pop(pid, None)
        self.memory_history.pop(pid, None)
        self.child_spawn_times.pop(pid, None)
