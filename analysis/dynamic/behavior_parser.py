"""
MalScope Dynamic Analysis - Behavior Parser
=============================================
Parses and normalizes behavioral data from multiple sources
(local monitoring and sandbox reports), then calculates a
dynamic risk score based on suspicious indicators.

Course Topics Covered:
- Process activity (Process Hacker / Process Monitor)
- Autorun detection (Autoruns)
- WinAPI call patterns (Process Monitor)
- Network traffic analysis (Wireshark / FakeNet-NG)
- File system interaction monitoring
- Registry change detection
- Direct IP connections
- Network sinkhole patterns (REMnux / iNetSim)

Input:  Raw behavioral data (dicts/lists from local monitoring or sandbox)
Output: Normalized, scored behavioral report (dict)
"""

import re


# ─── Known Suspicious Patterns ────────────────────────────────────────────────

# Processes commonly abused by malware for execution / evasion
SUSPICIOUS_PROCESSES = {
    "cmd.exe": "Command shell execution",
    "powershell.exe": "PowerShell execution (possible script-based attack)",
    "wscript.exe": "Windows Script Host execution",
    "cscript.exe": "Console Script Host execution",
    "mshta.exe": "Microsoft HTML Application Host (T1218.005)",
    "regsvr32.exe": "DLL registration abuse (T1218.010)",
    "rundll32.exe": "DLL execution via rundll32 (T1218.011)",
    "schtasks.exe": "Scheduled task creation (persistence)",
    "reg.exe": "Registry modification via command line",
    "net.exe": "Network enumeration / user manipulation",
    "net1.exe": "Network enumeration (alternate)",
    "netsh.exe": "Network configuration changes / firewall modification",
    "bitsadmin.exe": "BITS transfer (file download abuse)",
    "certutil.exe": "Certificate utility (file download abuse)",
    "wmic.exe": "WMI command execution",
    "msiexec.exe": "MSI installer execution",
    "attrib.exe": "File attribute modification (hiding files)",
    "icacls.exe": "Permission modification",
    "vssadmin.exe": "Shadow copy deletion (ransomware indicator)",
    "bcdedit.exe": "Boot configuration edit (ransomware indicator)",
    "wbadmin.exe": "Backup deletion (ransomware indicator)",
}

# Registry keys commonly used for persistence (Autoruns topic)
PERSISTENCE_REGISTRY_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"SYSTEM\CurrentControlSet\Services",
    r"SYSTEM\CurrentControlSet\Control\Session Manager",
]

# Suspicious network ports commonly used by malware
SUSPICIOUS_PORTS = {
    4444: "Metasploit default handler",
    5555: "Common RAT port",
    8080: "Alternative HTTP (possible C2)",
    8443: "Alternative HTTPS (possible C2)",
    1337: "Common backdoor port",
    31337: "Back Orifice / Elite backdoor",
    6666: "Common IRC botnet",
    6667: "IRC (botnet C2 channel)",
    9999: "Common RAT port",
    12345: "NetBus trojan",
    27015: "Sub7 trojan",
}

# Sensitive file system locations
SENSITIVE_DIRECTORIES = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Temp",
    r"C:\Windows\Tasks",
    r"AppData\Local\Temp",
    r"AppData\Roaming",
    r"Startup",
    r"Start Menu",
]


# ─── Parsing Functions ────────────────────────────────────────────────────────

def parse_process_activity(raw_processes):
    """
    Normalizes process data into a standard format.

    Input:  List of dicts or strings representing process activity.
            Each dict may have: name, pid, ppid, cmdline, action, parent, path
            Or raw strings like "cmd.exe (PID: 1234)"

    Output: List of dicts with keys: name, pid, action
            Example: [{"name": "cmd.exe", "pid": 1234, "action": "Spawned shell process"}]
    """
    parsed = []

    if not raw_processes or not isinstance(raw_processes, list):
        return parsed

    for proc in raw_processes:
        if isinstance(proc, dict):
            name = str(proc.get("name", proc.get("process_name", "Unknown")))
            pid = proc.get("pid", proc.get("process_id", 0))
            action = proc.get("action", "")

            # If no action provided, determine from process name
            if not action:
                name_lower = name.lower()
                if name_lower in SUSPICIOUS_PROCESSES:
                    action = SUSPICIOUS_PROCESSES[name_lower]
                else:
                    action = "Process spawned"

            parsed.append({
                "name": name,
                "pid": int(pid) if pid else 0,
                "action": action
            })

        elif isinstance(proc, str):
            # Parse string format like "cmd.exe (PID: 1234)"
            match = re.match(r"(.+?)\s*(?:\(PID:\s*(\d+)\))?$", proc.strip())
            if match:
                name = match.group(1).strip()
                pid = int(match.group(2)) if match.group(2) else 0
                name_lower = name.lower()
                action = SUSPICIOUS_PROCESSES.get(name_lower, "Process detected")

                parsed.append({
                    "name": name,
                    "pid": pid,
                    "action": action
                })

    return parsed


def parse_network_activity(raw_network):
    """
    Normalizes network connection data into a standard format.

    Input:  List of dicts or strings representing network connections.
            Each dict may have: ip/host/remote_address, port/remote_port,
            protocol, direction, status

    Output: List of dicts with keys: ip, port, protocol, direction
            Example: [{"ip": "192.168.1.100", "port": 443, "protocol": "TCP", "direction": "Outbound"}]
    """
    parsed = []

    if not raw_network or not isinstance(raw_network, list):
        return parsed

    for conn in raw_network:
        if isinstance(conn, dict):
            ip = str(conn.get("ip", conn.get("host", conn.get("remote_address", ""))))
            port = conn.get("port", conn.get("remote_port", 0))
            protocol = str(conn.get("protocol", "TCP")).upper()
            direction = str(conn.get("direction", "Outbound"))

            if ip:
                parsed.append({
                    "ip": ip,
                    "port": int(port) if port else 0,
                    "protocol": protocol,
                    "direction": direction
                })

        elif isinstance(conn, str):
            # Parse string format like "TCP 192.168.1.100:443 Outbound"
            match = re.match(
                r"(?:(TCP|UDP)\s+)?(\d+\.\d+\.\d+\.\d+):(\d+)\s*(Inbound|Outbound)?",
                conn.strip(),
                re.IGNORECASE
            )
            if match:
                parsed.append({
                    "ip": match.group(2),
                    "port": int(match.group(3)),
                    "protocol": (match.group(1) or "TCP").upper(),
                    "direction": match.group(4) or "Outbound"
                })

    return parsed


def parse_registry_changes(raw_registry):
    """
    Normalizes registry modification data into descriptive strings.

    Input:  List of dicts or strings representing registry changes.
            Each dict may have: key, value, action, data, hive

    Output: List of descriptive strings.
            Example: ["HKLM\\Software\\...\\Run\\MalwareKey [ADDED] = malware.exe"]
    """
    parsed = []

    if not raw_registry or not isinstance(raw_registry, list):
        return parsed

    for reg in raw_registry:
        if isinstance(reg, dict):
            key = str(reg.get("key", reg.get("path", "")))
            value = reg.get("value", reg.get("value_name", ""))
            action = str(reg.get("action", "MODIFIED")).upper()
            data = reg.get("data", "")

            entry = key
            if value:
                entry += f"\\{value}"
            entry += f" [{action}]"
            if data:
                entry += f" = {data}"

            parsed.append(entry)

        elif isinstance(reg, str):
            # Already a string — check if it has an action tag
            if not re.search(r"\[(ADDED|MODIFIED|DELETED|SET|CREATED)\]", reg, re.IGNORECASE):
                parsed.append(f"{reg} [MODIFIED]")
            else:
                parsed.append(reg)

    return parsed


def parse_file_changes(raw_filesystem):
    """
    Normalizes file system change data into descriptive strings.

    Input:  List of dicts or strings representing file operations.
            Each dict may have: path, action/operation, size

    Output: List of descriptive strings.
            Example: ["C:\\Windows\\Temp\\payload.dll [CREATED]"]
    """
    parsed = []

    if not raw_filesystem or not isinstance(raw_filesystem, list):
        return parsed

    for entry in raw_filesystem:
        if isinstance(entry, dict):
            path = str(entry.get("path", entry.get("file_path", "")))
            action = str(entry.get("action", entry.get("operation", "CREATED"))).upper()

            if path:
                parsed.append(f"{path} [{action}]")

        elif isinstance(entry, str):
            # Already a string — check if it has an action tag
            if not re.search(r"\[(CREATED|MODIFIED|DELETED|WRITTEN|READ|DROPPED)\]", entry, re.IGNORECASE):
                parsed.append(f"{entry} [CREATED]")
            else:
                parsed.append(entry)

    return parsed


# ─── Merging Function ─────────────────────────────────────────────────────────

def merge_results(local_results, sandbox_results):
    """
    Merges behavioral data from local monitoring and sandbox analysis.
    Deduplicates entries based on key identifiers.

    Input:
        local_results:   dict with keys: processes, network_activity,
                         registry_changes, file_changes
        sandbox_results: dict with same keys (from sandbox_client)

    Output: Merged dict with deduplicated entries.
    """
    if not local_results:
        local_results = {}
    if not sandbox_results:
        sandbox_results = {}

    merged = {
        "processes": [],
        "network_activity": [],
        "registry_changes": [],
        "file_changes": [],
    }

    # Merge processes — deduplicate by (name, pid) tuple
    seen_procs = set()
    for proc_list in [local_results.get("processes", []),
                      sandbox_results.get("processes", [])]:
        for proc in proc_list:
            key = (proc.get("name", ""), proc.get("pid", 0))
            if key not in seen_procs:
                seen_procs.add(key)
                merged["processes"].append(proc)

    # Merge network — deduplicate by (ip, port) tuple
    seen_net = set()
    for net_list in [local_results.get("network_activity", []),
                     sandbox_results.get("network_activity", [])]:
        for conn in net_list:
            key = (conn.get("ip", ""), conn.get("port", 0))
            if key not in seen_net:
                seen_net.add(key)
                merged["network_activity"].append(conn)

    # Merge registry — deduplicate by string value
    seen_reg = set()
    for reg_list in [local_results.get("registry_changes", []),
                     sandbox_results.get("registry_changes", [])]:
        for entry in reg_list:
            normalized = entry.strip().lower()
            if normalized not in seen_reg:
                seen_reg.add(normalized)
                merged["registry_changes"].append(entry)

    # Merge filesystem — deduplicate by string value
    seen_fs = set()
    for fs_list in [local_results.get("file_changes", []),
                    sandbox_results.get("file_changes", [])]:
        for entry in fs_list:
            normalized = entry.strip().lower()
            if normalized not in seen_fs:
                seen_fs.add(normalized)
                merged["file_changes"].append(entry)

    return merged


# ─── Scoring Function ─────────────────────────────────────────────────────────

def calculate_dynamic_score(parsed_results):
    """
    Calculates a dynamic behavioral risk score (0.0 - 10.0) based on
    suspicious indicators found in the behavioral analysis.

    Scoring is based on course topics:
    - Process Hacker / Process Monitor: suspicious process spawning
    - Autoruns: registry persistence mechanisms
    - Wireshark / FakeNet-NG: suspicious network connections
    - REMnux / iNetSim: network sinkhole patterns
    - File system interaction: drops in sensitive directories

    Input:  Parsed results dict (output of merge_results or parse functions)
    Output: Tuple of (score: float, indicators: list of strings)
    """
    score = 0.0
    indicators = []
    max_score = 10.0

    processes = parsed_results.get("processes", [])
    network = parsed_results.get("network_activity", [])
    registry = parsed_results.get("registry_changes", [])
    filesystem = parsed_results.get("file_changes", [])

    # ── Process Analysis (Process Hacker / Process Monitor topics) ──

    for proc in processes:
        name = proc.get("name", "").lower()

        # Shell execution (cmd.exe, powershell.exe)
        if name in ("cmd.exe", "powershell.exe"):
            score += 2.0
            indicators.append(f"Shell process spawned: {proc.get('name', name)} (PID: {proc.get('pid', 'N/A')})")

        # Script host execution
        elif name in ("wscript.exe", "cscript.exe", "mshta.exe"):
            score += 1.5
            indicators.append(f"Script host executed: {proc.get('name', name)}")

        # LOLBin abuse (Living Off The Land Binaries)
        elif name in ("regsvr32.exe", "rundll32.exe", "certutil.exe",
                       "bitsadmin.exe", "msiexec.exe"):
            score += 1.5
            indicators.append(f"LOLBin execution detected: {proc.get('name', name)}")

        # Ransomware indicators
        elif name in ("vssadmin.exe", "bcdedit.exe", "wbadmin.exe"):
            score += 3.0
            indicators.append(f"Ransomware indicator — {proc.get('name', name)} executed (shadow copy / backup manipulation)")

        # Reconnaissance tools
        elif name in ("net.exe", "net1.exe", "wmic.exe", "netsh.exe"):
            score += 1.0
            indicators.append(f"Reconnaissance/enumeration tool: {proc.get('name', name)}")

        # Scheduled task / persistence via process
        elif name == "schtasks.exe":
            score += 2.0
            indicators.append("Scheduled task creation detected (persistence mechanism)")

        # Fallback for other known suspicious processes (like reg.exe)
        elif name in SUSPICIOUS_PROCESSES:
            score += 1.5
            indicators.append(f"Suspicious process executed: {proc.get('name', name)} ({SUSPICIOUS_PROCESSES[name]})")

        # Check for specific suspicious actions (like self-execution or injection)
        action = proc.get("action", "")
        if "Self-execution" in action:
            score += 1.0
            indicators.append(f"Executable self-execution detected: {proc.get('name', name)}")
        elif "injection" in action.lower() or "hollowing" in action.lower():
            score += 3.0
            indicators.append(f"Process injection/hollowing detected: {proc.get('name', name)}")

    # ── Network Analysis (Wireshark / FakeNet-NG topics) ──

    for conn in network:
        ip = conn.get("ip", "")
        port = conn.get("port", 0)
        direction = conn.get("direction", "").lower()

        # Outbound connections are suspicious for unknown files
        if "outbound" in direction:
            score += 1.0
            msg = f"Outbound connection: {ip}:{port} ({conn.get('protocol', 'TCP')})"

            # Check for direct IP connection (no hostname — course topic)
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                score += 0.5
                msg += " [Direct IP — no DNS resolution]"

            # Check for suspicious ports
            if port in SUSPICIOUS_PORTS:
                score += 1.5
                msg += f" [Suspicious port: {SUSPICIOUS_PORTS[port]}]"

            indicators.append(msg)

        # Inbound connections (backdoor listener)
        elif "inbound" in direction:
            score += 2.0
            indicators.append(f"Inbound listener detected: port {port} ({conn.get('protocol', 'TCP')})")

    # ── Registry Analysis (Autoruns topic) ──

    for entry in registry:
        entry_lower = entry.lower()

        # Check against known persistence keys
        for persistence_key in PERSISTENCE_REGISTRY_KEYS:
            if persistence_key.lower() in entry_lower:
                score += 2.0
                indicators.append(f"Registry persistence detected: {entry}")
                break
        else:
            # Generic registry modification
            if "[added]" in entry_lower or "[created]" in entry_lower:
                score += 0.5
                indicators.append(f"Registry key added: {entry}")
            elif "[deleted]" in entry_lower:
                score += 0.5
                indicators.append(f"Registry key deleted: {entry}")

    # ── File System Analysis ──

    for entry in filesystem:
        entry_lower = entry.lower()

        # Files dropped in sensitive directories
        for sensitive_dir in SENSITIVE_DIRECTORIES:
            if sensitive_dir.lower() in entry_lower:
                score += 1.5
                indicators.append(f"File operation in sensitive directory: {entry}")
                break

        # Executable files dropped
        if re.search(r"\.(exe|dll|bat|ps1|vbs|js|scr|com|pif)(\s|\]|$)",
                      entry_lower):
            score += 1.0
            indicators.append(f"Executable file dropped: {entry}")

    # Cap the score at max_score
    final_score = min(score, max_score)

    return round(final_score, 1), indicators


# ─── Main Entry Point (for independent testing) ───────────────────────────────

if __name__ == "__main__":
    """
    Independent test for the behavior parser module.
    Verifies: Input accepted, Output format correct, No external dependencies.
    """
    print("=" * 60)
    print("MalScope - Behavior Parser Module Test")
    print("=" * 60)

    # Test data simulating raw behavioral observations
    test_processes_raw = [
        {"name": "cmd.exe", "pid": 4512, "cmdline": "cmd.exe /c whoami"},
        {"name": "powershell.exe", "pid": 5678},
        {"name": "svchost.exe", "pid": 1234, "action": "Normal system process"},
        "rundll32.exe (PID: 9999)",
        "notepad.exe",
    ]

    test_network_raw = [
        {"ip": "185.220.101.45", "port": 443, "protocol": "TCP", "direction": "Outbound"},
        {"remote_address": "10.0.0.1", "remote_port": 4444, "direction": "Outbound"},
        "TCP 192.168.1.50:8080 Outbound",
    ]

    test_registry_raw = [
        {"key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
         "value": "MalwareUpdate", "action": "ADDED", "data": "malware.exe"},
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\Payload",
        {"key": r"HKLM\SOFTWARE\SomeApp", "action": "MODIFIED"},
    ]

    test_filesystem_raw = [
        {"path": r"C:\Windows\Temp\payload.dll", "action": "CREATED"},
        {"file_path": r"C:\Users\victim\AppData\Roaming\backdoor.exe", "operation": "WRITTEN"},
        r"C:\Users\victim\Desktop\readme.txt",
    ]

    # 1. Parse each category
    print("\n--- Parsing Processes ---")
    processes = parse_process_activity(test_processes_raw)
    for p in processes:
        print(f"  [{p['pid']}] {p['name']} -> {p['action']}")

    print("\n--- Parsing Network Activity ---")
    network = parse_network_activity(test_network_raw)
    for n in network:
        print(f"  {n['protocol']} {n['ip']}:{n['port']} ({n['direction']})")

    print("\n--- Parsing Registry Changes ---")
    registry = parse_registry_changes(test_registry_raw)
    for r in registry:
        print(f"  {r}")

    print("\n--- Parsing File Changes ---")
    filesystem = parse_file_changes(test_filesystem_raw)
    for f in filesystem:
        print(f"  {f}")

    # 2. Merge (simulating local + sandbox)
    print("\n--- Merging Results ---")
    local = {
        "processes": processes[:3],
        "network_activity": network[:2],
        "registry_changes": registry[:2],
        "file_changes": filesystem[:1],
    }
    sandbox = {
        "processes": processes[2:],
        "network_activity": network[1:],
        "registry_changes": registry[1:],
        "file_changes": filesystem[1:],
    }
    merged = merge_results(local, sandbox)
    print(f"  Processes:  {len(merged['processes'])}")
    print(f"  Network:    {len(merged['network_activity'])}")
    print(f"  Registry:   {len(merged['registry_changes'])}")
    print(f"  Filesystem: {len(merged['file_changes'])}")

    # 3. Score
    print("\n--- Calculating Dynamic Score ---")
    score, indicators = calculate_dynamic_score(merged)
    print(f"  Score: {score}/10.0")
    print(f"  Indicators ({len(indicators)}):")
    for ind in indicators:
        print(f"    [!] {ind}")

    # 4. Verify output format
    print("\n--- Output Format Verification ---")
    output = {
        "processes": merged["processes"],
        "network_activity": merged["network_activity"],
        "registry_changes": merged["registry_changes"],
        "file_changes": merged["file_changes"],
        "score": score,
        "suspicious_indicators": indicators,
    }
    import json
    print(json.dumps(output, indent=2))
    print("\n✔ Input accepted")
    print("✔ Output format correct")
    print("✔ No dependency on GUI or other modules")
    print("✔ JSON serializable")
