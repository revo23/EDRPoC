import logging
import time
from collections import defaultdict

from detection.mitre_attack import get_technique

logger = logging.getLogger("edr.detection.alerts")


class AlertManager:
    def __init__(self, config, database):
        self.config = config.get("detection", {})
        self.database = database
        self.dedup_window = self.config.get("alert_dedup_window", 60)
        self.escalation_threshold = self.config.get("escalation_threshold", 3)

        self._recent_alerts = defaultdict(list)
        self._alert_callbacks = []

    def on_alert(self, callback):
        self._alert_callbacks.append(callback)

    def create_alert(self, alert_info):
        pid = alert_info.get("process_pid", 0)
        rule_id = alert_info.get("rule_id", "")

        if self._is_duplicate(pid, rule_id):
            return None

        if "timestamp" not in alert_info:
            alert_info["timestamp"] = time.time()

        technique_id = alert_info.get("mitre_technique", "")
        if technique_id:
            technique = get_technique(technique_id)
            if technique:
                alert_info["mitre_tactic"] = technique["tactic"]

        severity = self._check_escalation(pid, alert_info.get("severity", "medium"))
        alert_info["severity"] = severity

        alert_id = self.database.insert_alert(alert_info)
        alert_info["id"] = alert_id

        dedup_key = (pid, rule_id)
        self._recent_alerts[dedup_key].append(time.time())

        for callback in self._alert_callbacks:
            try:
                callback(alert_info)
            except Exception as e:
                logger.error("Alert callback error: %s", e)

        logger.info(
            "ALERT [%s] %s - PID: %s - %s (MITRE: %s)",
            severity.upper(),
            alert_info.get("rule_id", "ML"),
            pid,
            alert_info.get("description", ""),
            technique_id,
        )

        return alert_info

    def create_ml_alert(self, ml_result, feature_vector):
        severity = ml_result["severity"]
        if severity == "info":
            return None

        alert_info = {
            "severity": severity,
            "threat_score": ml_result["threat_score"],
            "source": "ml_ensemble",
            "rule_id": "ML-ENSEMBLE",
            "process_pid": feature_vector.get("pid"),
            "process_name": feature_vector.get("process_name", ""),
            "process_cmdline": feature_vector.get("event_data", {}).get("cmdline", ""),
            "description": (
                f"ML anomaly detected: score={ml_result['threat_score']:.1f} "
                f"(IF={ml_result['if_score']:.1f}, AE={ml_result['ae_score']:.1f})"
            ),
            "mitre_technique": "",
            "data": {
                "if_score": ml_result["if_score"],
                "ae_score": ml_result["ae_score"],
                "behavioral_score": ml_result["behavioral_score"],
            },
        }
        return self.create_alert(alert_info)

    def create_behavioral_alert(self, rule_result, event):
        data = event.get("data", {})
        alert_info = {
            "severity": rule_result["severity"],
            "threat_score": self._severity_to_score(rule_result["severity"]),
            "source": "behavioral",
            "rule_id": rule_result["rule_id"],
            "mitre_technique": rule_result.get("mitre_technique", ""),
            "mitre_tactic": rule_result.get("mitre_tactic", ""),
            "process_pid": data.get("pid"),
            "process_name": data.get("name", data.get("process_name", "")),
            "process_cmdline": data.get("cmdline", ""),
            "description": f"{rule_result['rule_name']}: {rule_result.get('details', '')}",
            "data": {"event_type": event.get("type"), "rule_details": rule_result.get("details", "")},
        }
        return self.create_alert(alert_info)

    def create_ioc_alert(self, ioc_match, event):
        data = event.get("data", {})
        ioc = ioc_match["ioc"]
        alert_info = {
            "severity": ioc.get("severity", "high"),
            "threat_score": self._severity_to_score(ioc.get("severity", "high")),
            "source": "threat_intel",
            "rule_id": f"IOC-{ioc_match['type'].upper()}",
            "process_pid": data.get("pid"),
            "process_name": data.get("name", data.get("process_name", "")),
            "process_cmdline": data.get("cmdline", ""),
            "description": f"IOC match ({ioc_match['type']}): {ioc_match['value']} - {ioc.get('description', '')}",
            "data": {"ioc_type": ioc_match["type"], "ioc_value": ioc_match["value"]},
        }
        return self.create_alert(alert_info)

    def _is_duplicate(self, pid, rule_id):
        key = (pid, rule_id)
        now = time.time()
        self._recent_alerts[key] = [
            t for t in self._recent_alerts[key] if now - t < self.dedup_window
        ]
        return len(self._recent_alerts[key]) > 0

    def _check_escalation(self, pid, current_severity):
        now = time.time()
        total_recent = 0
        for (p, _), times in self._recent_alerts.items():
            if p == pid:
                total_recent += len([t for t in times if now - t < self.dedup_window * 2])

        if total_recent >= self.escalation_threshold:
            severity_order = ["info", "low", "medium", "high", "critical"]
            idx = severity_order.index(current_severity) if current_severity in severity_order else 0
            if idx < len(severity_order) - 1:
                escalated = severity_order[idx + 1]
                logger.info(
                    "Escalating alert for PID %d: %s -> %s (%d recent alerts)",
                    pid, current_severity, escalated, total_recent,
                )
                return escalated
        return current_severity

    def _severity_to_score(self, severity):
        scores = {"critical": 95, "high": 75, "medium": 55, "low": 35, "info": 15}
        return scores.get(severity, 50)

    def get_open_alerts(self, limit=50):
        return self.database.get_alerts(limit=limit, status="open")

    def acknowledge_alert(self, alert_id):
        self.database.update_alert_status(alert_id, "acknowledged")

    def resolve_alert(self, alert_id, action=None):
        self.database.update_alert_status(alert_id, "resolved", response_action=action)
