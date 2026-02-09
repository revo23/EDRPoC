import logging
import re
import time
from collections import defaultdict

logger = logging.getLogger("edr.detection.behavioral")


class BehavioralRuleEngine:
    def __init__(self, process_monitor=None):
        self.process_monitor = process_monitor
        self.command_history = defaultdict(list)
        self.file_write_counts = defaultdict(int)
        self.rules = self._build_rules()

    def _build_rules(self):
        return [
            {
                "id": "IOA-001",
                "name": "Shell spawned from web process",
                "check": self._check_shell_from_web,
                "severity": "high",
                "mitre_technique": "T1059.004",
                "mitre_tactic": "Execution",
            },
            {
                "id": "IOA-002",
                "name": "Reverse shell pattern detected",
                "check": self._check_reverse_shell,
                "severity": "critical",
                "mitre_technique": "T1059.004",
                "mitre_tactic": "Execution",
            },
            {
                "id": "IOA-003",
                "name": "Privilege escalation attempt",
                "check": self._check_privesc,
                "severity": "high",
                "mitre_technique": "T1548.003",
                "mitre_tactic": "Privilege Escalation",
            },
            {
                "id": "IOA-004",
                "name": "Persistence mechanism (LaunchAgent/Daemon)",
                "check": self._check_persistence,
                "severity": "high",
                "mitre_technique": "T1543.001",
                "mitre_tactic": "Persistence",
            },
            {
                "id": "IOA-005",
                "name": "Credential access attempt",
                "check": self._check_credential_access,
                "severity": "high",
                "mitre_technique": "T1555.001",
                "mitre_tactic": "Credential Access",
            },
            {
                "id": "IOA-006",
                "name": "Discovery command sequence",
                "check": self._check_discovery,
                "severity": "medium",
                "mitre_technique": "T1082",
                "mitre_tactic": "Discovery",
            },
            {
                "id": "IOA-007",
                "name": "Data exfiltration pattern",
                "check": self._check_exfiltration,
                "severity": "high",
                "mitre_technique": "T1041",
                "mitre_tactic": "Exfiltration",
            },
            {
                "id": "IOA-008",
                "name": "Encoded command execution",
                "check": self._check_encoded_execution,
                "severity": "high",
                "mitre_technique": "T1140",
                "mitre_tactic": "Defense Evasion",
            },
            {
                "id": "IOA-009",
                "name": "Process injection indicator",
                "check": self._check_process_injection,
                "severity": "critical",
                "mitre_technique": "T1055",
                "mitre_tactic": "Defense Evasion",
            },
            {
                "id": "IOA-010",
                "name": "Unusual parent-child process",
                "check": self._check_unusual_parent_child,
                "severity": "medium",
                "mitre_technique": "T1059",
                "mitre_tactic": "Execution",
            },
            {
                "id": "IOA-011",
                "name": "Cryptocurrency miner pattern",
                "check": self._check_crypto_miner,
                "severity": "medium",
                "mitre_technique": "T1496",
                "mitre_tactic": "Impact",
            },
            {
                "id": "IOA-012",
                "name": "Ransomware indicator",
                "check": self._check_ransomware,
                "severity": "critical",
                "mitre_technique": "T1486",
                "mitre_tactic": "Impact",
            },
            {
                "id": "IOA-013",
                "name": "Non-standard port communication",
                "check": self._check_nonstandard_port,
                "severity": "low",
                "mitre_technique": "T1571",
                "mitre_tactic": "Command and Control",
            },
            {
                "id": "IOA-014",
                "name": "High entropy file creation",
                "check": self._check_high_entropy_file,
                "severity": "medium",
                "mitre_technique": "T1027",
                "mitre_tactic": "Defense Evasion",
            },
            {
                "id": "IOA-015",
                "name": "Sensitive directory modification",
                "check": self._check_sensitive_dir_mod,
                "severity": "medium",
                "mitre_technique": "T1547.011",
                "mitre_tactic": "Persistence",
            },
            {
                "id": "IOA-016",
                "name": "Mass file operations (possible ransomware)",
                "check": self._check_mass_file_ops,
                "severity": "high",
                "mitre_technique": "T1486",
                "mitre_tactic": "Impact",
            },
            {
                "id": "IOA-017",
                "name": "User/group discovery",
                "check": self._check_user_discovery,
                "severity": "low",
                "mitre_technique": "T1033",
                "mitre_tactic": "Discovery",
            },
        ]

    def evaluate(self, event):
        results = []
        for rule in self.rules:
            try:
                match = rule["check"](event)
                if match:
                    results.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "mitre_technique": rule["mitre_technique"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "details": match if isinstance(match, str) else "",
                    })
            except Exception as e:
                logger.debug("Rule %s error: %s", rule["id"], e)
        return results

    def get_behavioral_score(self, event):
        results = self.evaluate(event)
        if not results:
            return 0.0, results

        severity_scores = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}
        max_score = max(severity_scores.get(r["severity"], 0) for r in results)
        return float(max_score), results

    def _check_shell_from_web(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        name = (data.get("name") or "").lower()
        shells = {"bash", "zsh", "sh", "dash", "csh", "fish"}
        if name not in shells:
            return None
        parent_name = ""
        if self.process_monitor:
            parent_name = self.process_monitor.get_parent_name(data.get("pid", 0)).lower()
        web_procs = {"httpd", "nginx", "apache", "node", "python", "ruby", "php", "java"}
        if parent_name in web_procs:
            return f"Shell '{name}' spawned from web process '{parent_name}'"
        return None

    def _check_reverse_shell(self, event):
        data = event.get("data", {})
        cmdline = data.get("cmdline", "")
        patterns = [
            r"bash\s+-i\s+>&\s+/dev/tcp",
            r"nc\s+.*-e\s+/bin/(ba)?sh",
            r"python.*socket.*connect.*exec",
            r"perl.*socket.*exec",
            r"ruby.*TCPSocket.*exec",
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+",
            r"mkfifo.*nc\s+",
            r"bash.*>.*2>&1.*<",
        ]
        for pattern in patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return f"Reverse shell pattern: {pattern}"
        return None

    def _check_privesc(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        cmdline = data.get("cmdline", "")
        name = (data.get("name") or "").lower()
        if name in ("sudo", "su", "dscl"):
            return f"Privilege escalation via {name}: {cmdline[:100]}"
        privesc_patterns = [r"chmod\s+[46]?[0-7]*[sS]", r"chown\s+root"]
        for p in privesc_patterns:
            if re.search(p, cmdline):
                return f"Privilege escalation pattern: {cmdline[:100]}"
        return None

    def _check_persistence(self, event):
        data = event.get("data", {})
        event_type = event.get("type", "")
        if event_type in ("file_create", "file_modify"):
            path = data.get("path", "")
            if "LaunchAgents" in path or "LaunchDaemons" in path:
                if path.endswith(".plist"):
                    return f"Persistence via plist: {path}"
            if "/etc/crontab" in path or "cron.d" in path:
                return f"Persistence via cron: {path}"
        if event_type == "process_create":
            cmdline = data.get("cmdline", "")
            if "launchctl" in cmdline and ("load" in cmdline or "submit" in cmdline):
                return f"Persistence via launchctl: {cmdline[:100]}"
        return None

    def _check_credential_access(self, event):
        data = event.get("data", {})
        cmdline = data.get("cmdline", "")
        patterns = [
            "security find-generic-password",
            "security find-internet-password",
            "security dump-keychain",
            "/etc/shadow",
            "/etc/passwd",
            "keychain",
        ]
        for p in patterns:
            if p in cmdline.lower():
                return f"Credential access: {p}"
        if event.get("type") in ("file_create", "file_modify"):
            path = data.get("path", "")
            if "keychain" in path.lower() or path in ("/etc/shadow", "/etc/passwd"):
                return f"Credential file access: {path}"
        return None

    def _check_discovery(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        name = (data.get("name") or "").lower()
        discovery_cmds = {"whoami", "id", "uname", "ifconfig", "netstat", "ps", "ls", "sw_vers", "hostname"}
        if name in discovery_cmds:
            pid = data.get("pid", 0)
            ppid = data.get("ppid", 0)
            key = ppid if ppid else pid
            now = time.time()
            self.command_history[key].append((now, name))
            self.command_history[key] = [
                (t, c) for t, c in self.command_history[key] if now - t < 30
            ]
            recent = [c for _, c in self.command_history[key]]
            unique_cmds = set(recent)
            if len(unique_cmds) >= 3:
                return f"Discovery sequence: {', '.join(recent[-5:])}"
        return None

    def _check_exfiltration(self, event):
        data = event.get("data", {})
        if event.get("type") == "net_connect":
            bytes_rate = data.get("bytes_sent_rate", 0)
            if bytes_rate > 5_000_000:
                return f"High outbound data rate: {bytes_rate/1e6:.1f} MB/s"
        if event.get("type") == "net_high_traffic":
            return f"High network traffic: {data.get('bytes_sent_rate', 0)/1e6:.1f} MB/s outbound"
        return None

    def _check_encoded_execution(self, event):
        data = event.get("data", {})
        cmdline = data.get("cmdline", "")
        patterns = [
            r"base64\s+(-d|--decode).*\|\s*(ba)?sh",
            r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(-d|--decode)",
            r"python.*base64.*decode.*exec",
            r"eval.*\$\(.*base64",
        ]
        for p in patterns:
            if re.search(p, cmdline, re.IGNORECASE):
                return f"Encoded execution: {cmdline[:100]}"
        return None

    def _check_process_injection(self, event):
        data = event.get("data", {})
        cmdline = data.get("cmdline", "")
        if event.get("type") != "process_create":
            return None
        injection_indicators = [
            "DYLD_INSERT_LIBRARIES",
            "ptrace",
            "task_for_pid",
            "mach_inject",
        ]
        for ind in injection_indicators:
            if ind in cmdline:
                return f"Process injection indicator: {ind}"
        return None

    def _check_unusual_parent_child(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        name = (data.get("name") or "").lower()
        if name not in ("bash", "sh", "zsh", "python", "python3", "perl", "ruby", "curl", "wget"):
            return None
        parent_name = ""
        if self.process_monitor:
            parent_name = self.process_monitor.get_parent_name(data.get("pid", 0)).lower()
        unusual_parents = {
            "microsoft word", "word", "excel", "powerpoint",
            "pages", "numbers", "keynote", "preview", "textedit",
        }
        if parent_name in unusual_parents:
            return f"Unusual parent-child: {parent_name} -> {name}"
        return None

    def _check_crypto_miner(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        cmdline = data.get("cmdline", "").lower()
        indicators = ["stratum+tcp", "xmrig", "minerd", "cpuminer", "cryptonight", "hashrate"]
        for ind in indicators:
            if ind in cmdline:
                return f"Crypto miner indicator: {ind}"
        cpu = data.get("cpu_percent", 0) or 0
        if cpu > 80:
            name = (data.get("name") or "").lower()
            suspicious_names = {"miner", "xmr", "crypto"}
            if any(s in name for s in suspicious_names):
                return f"High CPU process with miner name: {name} ({cpu}% CPU)"
        return None

    def _check_ransomware(self, event):
        data = event.get("data", {})
        if event.get("type") == "file_rename":
            dest = data.get("dest_path", "")
            ransom_exts = {".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".ransom"}
            for ext in ransom_exts:
                if dest.endswith(ext):
                    return f"Ransomware-like rename: {data.get('path', '')} -> {dest}"
        return None

    def _check_nonstandard_port(self, event):
        data = event.get("data", {})
        if event.get("type") != "net_connect":
            return None
        if data.get("non_standard_port") and not data.get("is_private_ip"):
            port = data.get("remote_port", 0)
            addr = data.get("remote_addr", "")
            return f"Non-standard port: {addr}:{port}"
        return None

    def _check_high_entropy_file(self, event):
        data = event.get("data", {})
        if event.get("type") not in ("file_create", "file_modify"):
            return None
        entropy = data.get("entropy", 0)
        if entropy > 7.5:
            return f"High entropy file ({entropy:.2f}): {data.get('path', '')}"
        return None

    def _check_sensitive_dir_mod(self, event):
        data = event.get("data", {})
        if event.get("type") not in ("file_create", "file_modify"):
            return None
        if data.get("is_sensitive_dir") and data.get("is_executable"):
            return f"Executable in sensitive dir: {data.get('path', '')}"
        return None

    def _check_mass_file_ops(self, event):
        data = event.get("data", {})
        if event.get("type") not in ("file_create", "file_modify", "file_rename"):
            return None
        pid = data.get("pid", 0)
        if pid:
            self.file_write_counts[pid] += 1
            if self.file_write_counts[pid] > 50:
                count = self.file_write_counts[pid]
                return f"Mass file operations by PID {pid}: {count} operations"
        return None

    def _check_user_discovery(self, event):
        data = event.get("data", {})
        if event.get("type") != "process_create":
            return None
        name = (data.get("name") or "").lower()
        cmdline = data.get("cmdline", "").lower()
        if name == "dscl" or "dscacheutil" in cmdline:
            return f"User/group discovery: {cmdline[:100]}"
        return None
