import logging
import time
from collections import defaultdict

import numpy as np

logger = logging.getLogger("edr.features.network")

NETWORK_FEATURE_NAMES = [
    "unique_destinations", "bytes_sent_rate", "bytes_recv_rate",
    "connection_frequency", "avg_connection_duration", "non_standard_port",
    "is_private_ip", "dns_query_rate", "failed_connections", "unique_ports",
]


class NetworkFeatureExtractor:
    def __init__(self):
        self.connection_history = defaultdict(list)
        self.destinations = defaultdict(set)
        self.ports = defaultdict(set)
        self.dns_queries = defaultdict(list)
        self.failed_conns = defaultdict(int)
        self.bytes_sent = defaultdict(float)
        self.bytes_recv = defaultdict(float)

    def extract(self, event_data):
        now = time.time()
        pid = event_data.get("pid", 0)
        cutoff = now - 60

        remote_addr = event_data.get("remote_addr", "")
        remote_port = event_data.get("remote_port", 0)

        if remote_addr:
            self.destinations[pid].add(remote_addr)
        if remote_port:
            self.ports[pid].add(remote_port)

        self.connection_history[pid].append(now)
        self.connection_history[pid] = [
            t for t in self.connection_history[pid] if t > cutoff
        ]

        status = event_data.get("status", "")
        if status in ("SYN_SENT", "TIME_WAIT"):
            self.failed_conns[pid] += 1

        bytes_sent_rate = event_data.get("bytes_sent_rate", 0)
        bytes_recv_rate = event_data.get("bytes_recv_rate", 0)
        self.bytes_sent[pid] = bytes_sent_rate
        self.bytes_recv[pid] = bytes_recv_rate

        conn_freq = len(self.connection_history.get(pid, []))

        conn_times = self.connection_history.get(pid, [])
        if len(conn_times) >= 2:
            intervals = [conn_times[i+1] - conn_times[i] for i in range(len(conn_times)-1)]
            avg_duration = np.mean(intervals) if intervals else 0
        else:
            avg_duration = 0

        non_standard = 1.0 if event_data.get("non_standard_port", False) else 0.0
        is_private = 1.0 if event_data.get("is_private_ip", True) else 0.0

        dns_rate = len(self.dns_queries.get(pid, []))

        features = np.array([
            float(len(self.destinations.get(pid, set()))),
            float(self.bytes_sent.get(pid, 0)),
            float(self.bytes_recv.get(pid, 0)),
            float(conn_freq),
            float(avg_duration),
            float(non_standard),
            float(is_private),
            float(dns_rate),
            float(self.failed_conns.get(pid, 0)),
            float(len(self.ports.get(pid, set()))),
        ], dtype=np.float32)

        return features

    def record_dns_query(self, pid):
        self.dns_queries[pid].append(time.time())
        cutoff = time.time() - 60
        self.dns_queries[pid] = [t for t in self.dns_queries[pid] if t > cutoff]

    def cleanup(self, pid):
        self.connection_history.pop(pid, None)
        self.destinations.pop(pid, None)
        self.ports.pop(pid, None)
        self.dns_queries.pop(pid, None)
        self.failed_conns.pop(pid, None)
        self.bytes_sent.pop(pid, None)
        self.bytes_recv.pop(pid, None)
