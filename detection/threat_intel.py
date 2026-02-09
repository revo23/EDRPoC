import json
import logging
import os

logger = logging.getLogger("edr.detection.threat_intel")


class ThreatIntelEngine:
    def __init__(self, database):
        self.database = database
        self._hash_cache = set()
        self._ip_cache = set()
        self._domain_cache = set()
        self._load_iocs()

    def _load_iocs(self):
        iocs = self.database.get_all_iocs()
        for ioc in iocs:
            if ioc["ioc_type"] == "sha256":
                self._hash_cache.add(ioc["value"].lower())
            elif ioc["ioc_type"] == "ip":
                self._ip_cache.add(ioc["value"])
            elif ioc["ioc_type"] == "domain":
                self._domain_cache.add(ioc["value"].lower())

        if not iocs:
            self._seed_demo_iocs()

    def _seed_demo_iocs(self):
        demo_iocs = [
            ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "low", "demo", "Empty file hash (SHA256 of empty string)"),
            ("ip", "198.51.100.1", "high", "demo", "Known C2 server (TEST-NET-2)"),
            ("ip", "203.0.113.50", "high", "demo", "Known malware distribution (TEST-NET-3)"),
            ("domain", "evil-c2.example.com", "critical", "demo", "Known C2 domain"),
            ("domain", "malware-download.example.com", "high", "demo", "Malware distribution domain"),
        ]
        for ioc_type, value, severity, source, desc in demo_iocs:
            self.database.add_ioc(ioc_type, value, severity, source, desc)
            if ioc_type == "sha256":
                self._hash_cache.add(value.lower())
            elif ioc_type == "ip":
                self._ip_cache.add(value)
            elif ioc_type == "domain":
                self._domain_cache.add(value.lower())

    def check_hash(self, file_hash):
        if not file_hash:
            return None
        if file_hash.lower() in self._hash_cache:
            return self.database.check_ioc("sha256", file_hash.lower())
        return None

    def check_ip(self, ip):
        if not ip:
            return None
        if ip in self._ip_cache:
            return self.database.check_ioc("ip", ip)
        return None

    def check_domain(self, domain):
        if not domain:
            return None
        if domain.lower() in self._domain_cache:
            return self.database.check_ioc("domain", domain.lower())
        return None

    def check_event(self, event):
        data = event.get("data", {})
        results = []

        exe_hash = data.get("exe_hash", "")
        if exe_hash:
            match = self.check_hash(exe_hash)
            if match:
                results.append({
                    "type": "hash_match",
                    "ioc": match,
                    "value": exe_hash,
                })

        remote_addr = data.get("remote_addr", "")
        if remote_addr:
            match = self.check_ip(remote_addr)
            if match:
                results.append({
                    "type": "ip_match",
                    "ioc": match,
                    "value": remote_addr,
                })

        return results

    def add_ioc(self, ioc_type, value, severity="medium", source="manual", description=""):
        self.database.add_ioc(ioc_type, value, severity, source, description)
        if ioc_type == "sha256":
            self._hash_cache.add(value.lower())
        elif ioc_type == "ip":
            self._ip_cache.add(value)
        elif ioc_type == "domain":
            self._domain_cache.add(value.lower())

    def load_feed(self, feed_path):
        if not os.path.exists(feed_path):
            logger.warning("Feed file not found: %s", feed_path)
            return 0
        try:
            with open(feed_path) as f:
                feed = json.load(f)
            count = 0
            for item in feed.get("indicators", []):
                self.add_ioc(
                    item["type"], item["value"],
                    item.get("severity", "medium"),
                    item.get("source", feed_path),
                    item.get("description", ""),
                )
                count += 1
            logger.info("Loaded %d IOCs from %s", count, feed_path)
            return count
        except Exception as e:
            logger.error("Failed to load feed %s: %s", feed_path, e)
            return 0

    def get_stats(self):
        return {
            "hashes": len(self._hash_cache),
            "ips": len(self._ip_cache),
            "domains": len(self._domain_cache),
            "total": len(self._hash_cache) + len(self._ip_cache) + len(self._domain_cache),
        }
