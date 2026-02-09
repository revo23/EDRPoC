import logging
import os
import shutil
import signal
import time

import psutil

logger = logging.getLogger("edr.response")


class ResponseEngine:
    def __init__(self, config, database):
        self.config = config.get("response", {})
        self.database = database
        self.auto_respond_threshold = self.config.get("auto_respond_threshold", 80)
        self.quarantine_dir = self.config.get("quarantine_dir", "data/quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._action_log = []

    def handle_alert(self, alert):
        score = alert.get("threat_score", 0)
        if score >= self.auto_respond_threshold:
            pid = alert.get("process_pid")
            if pid:
                self.kill_process(pid, reason=alert.get("description", "Auto-response"))
                self.database.update_alert_status(
                    alert.get("id"), "responded", response_action=f"kill_process:{pid}"
                )
                return {"action": "kill_process", "pid": pid}
        return None

    def kill_process(self, pid, reason="Manual kill"):
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.kill()
            entry = {
                "action": "kill_process",
                "pid": pid,
                "process_name": proc_name,
                "reason": reason,
                "timestamp": time.time(),
                "success": True,
            }
            self._action_log.append(entry)
            self.database.mark_process_terminated(pid)
            logger.info("Killed process %d (%s): %s", pid, proc_name, reason)
            return entry
        except psutil.NoSuchProcess:
            entry = {
                "action": "kill_process",
                "pid": pid,
                "reason": reason,
                "timestamp": time.time(),
                "success": False,
                "error": "Process not found",
            }
            self._action_log.append(entry)
            return entry
        except psutil.AccessDenied:
            entry = {
                "action": "kill_process",
                "pid": pid,
                "reason": reason,
                "timestamp": time.time(),
                "success": False,
                "error": "Access denied",
            }
            self._action_log.append(entry)
            logger.warning("Access denied killing PID %d", pid)
            return entry

    def quarantine_file(self, file_path, reason="Suspicious file"):
        if not os.path.exists(file_path):
            entry = {
                "action": "quarantine_file",
                "path": file_path,
                "reason": reason,
                "timestamp": time.time(),
                "success": False,
                "error": "File not found",
            }
            self._action_log.append(entry)
            return entry

        try:
            filename = os.path.basename(file_path)
            quarantine_name = f"{int(time.time())}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)

            metadata_path = quarantine_path + ".meta"
            with open(metadata_path, "w") as f:
                import json
                json.dump({
                    "original_path": file_path,
                    "quarantine_time": time.time(),
                    "reason": reason,
                    "quarantine_path": quarantine_path,
                }, f, indent=2)

            shutil.move(file_path, quarantine_path)

            entry = {
                "action": "quarantine_file",
                "path": file_path,
                "quarantine_path": quarantine_path,
                "reason": reason,
                "timestamp": time.time(),
                "success": True,
            }
            self._action_log.append(entry)
            logger.info("Quarantined %s -> %s: %s", file_path, quarantine_path, reason)
            return entry
        except Exception as e:
            entry = {
                "action": "quarantine_file",
                "path": file_path,
                "reason": reason,
                "timestamp": time.time(),
                "success": False,
                "error": str(e),
            }
            self._action_log.append(entry)
            logger.error("Failed to quarantine %s: %s", file_path, e)
            return entry

    def suspend_process(self, pid, reason="Suspicious activity"):
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.suspend()
            entry = {
                "action": "suspend_process",
                "pid": pid,
                "process_name": proc_name,
                "reason": reason,
                "timestamp": time.time(),
                "success": True,
            }
            self._action_log.append(entry)
            logger.info("Suspended process %d (%s): %s", pid, proc_name, reason)
            return entry
        except psutil.NoSuchProcess:
            return {"action": "suspend_process", "pid": pid, "success": False, "error": "Not found",
                    "timestamp": time.time()}
        except psutil.AccessDenied:
            return {"action": "suspend_process", "pid": pid, "success": False, "error": "Access denied",
                    "timestamp": time.time()}

    def network_isolate(self, reason="Threat detected"):
        entry = {
            "action": "network_isolate",
            "reason": reason,
            "timestamp": time.time(),
            "success": True,
            "note": "PoC mode: logged only, no actual network isolation performed",
        }
        self._action_log.append(entry)
        logger.warning("NETWORK ISOLATE (PoC - log only): %s", reason)
        return entry

    def get_action_log(self, limit=50):
        return list(reversed(self._action_log[-limit:]))

    def get_stats(self):
        actions = {}
        for entry in self._action_log:
            action = entry.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1
        return {
            "total_actions": len(self._action_log),
            "actions_by_type": actions,
        }
