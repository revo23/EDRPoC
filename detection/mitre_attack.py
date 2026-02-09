MITRE_TECHNIQUES = {
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shell commands and scripts for execution.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands.",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic.",
    },
    "T1547.011": {
        "name": "Boot or Logon Autostart Execution: Plist Modification",
        "tactic": "Persistence",
        "description": "Adversaries may modify property list files to run a program during system boot or user login.",
    },
    "T1543.004": {
        "name": "Create or Modify System Process: Launch Daemon",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence.",
    },
    "T1543.001": {
        "name": "Create or Modify System Process: Launch Agent",
        "tactic": "Persistence",
        "description": "Adversaries may create or modify Launch Agents to repeatedly execute malicious payloads.",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may abuse sudo or sudo caching to escalate privileges.",
    },
    "T1555.001": {
        "name": "Credentials from Password Stores: Keychain",
        "tactic": "Credential Access",
        "description": "Adversaries may acquire credentials from the macOS Keychain.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system.",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to identify the primary user or current user of a system.",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may look for details about the network configuration of systems.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel.",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may use obfuscated files or information to hide artifacts of an intrusion.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversaries may leverage compute resources for cryptocurrency mining.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes to evade process-based defenses.",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using a protocol and port pairing not commonly associated with it.",
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": "Adversaries may employ an encryption algorithm to conceal C2 traffic.",
    },
}

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact",
]


def get_technique(technique_id):
    return MITRE_TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic):
    return {
        tid: info for tid, info in MITRE_TECHNIQUES.items()
        if info["tactic"] == tactic
    }


def get_all_tactics():
    return TACTIC_ORDER


def get_matrix_data():
    matrix = {}
    for tactic in TACTIC_ORDER:
        matrix[tactic] = []
        for tid, info in MITRE_TECHNIQUES.items():
            if info["tactic"] == tactic:
                matrix[tactic].append({
                    "id": tid,
                    "name": info["name"],
                    "description": info["description"],
                })
    return matrix
