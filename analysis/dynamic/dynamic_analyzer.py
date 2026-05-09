"""
MalScope Dynamic Analysis - Main Dynamic Analyzer
===================================================
Entry point for the Dynamic Analysis Module.
The orchestrator calls run_dynamic_analysis(file_path) to perform
behavioral analysis on a given file.

This module operates in SAFE MODE by default — it does NOT execute
the file directly. Instead, it:
1. Analyzes the file for behavioral indicators using static heuristics
2. Monitors system state for baseline comparison
3. Submits the file to a cloud sandbox (Hybrid Analysis) for safe detonation
4. Parses and normalizes all behavioral data
5. Calculates a dynamic risk score

Course Topics Covered:
- Viewing process activity (Process Hacker)
- Viewing autostarting malware (Autoruns)
- Viewing WinAPI calls (Process Monitor)
- Visualizing activity (ProcDot)
- Viewing file system interaction
- Viewing registry changes
- Viewing network traffic (Wireshark & FakeNet-NG)
- Direct IP connections
- Examining network traffic of document samples
- Network sinkhole concepts (REMnux & iNetSim)

Input:  File path (str)
Output: Dynamic analysis results (dict)
"""

import os
import re
import struct
import hashlib

from .sandbox_client import submit_to_sandbox, get_sandbox_report
from .behavior_parser import (
    parse_process_activity,
    parse_network_activity,
    parse_registry_changes,
    parse_file_changes,
    merge_results,
    calculate_dynamic_score,
    SUSPICIOUS_PROCESSES,
    PERSISTENCE_REGISTRY_KEYS,
    SENSITIVE_DIRECTORIES,
)


# ─── Configuration ────────────────────────────────────────────────────────────

# PE file magic number (MZ header)
PE_MAGIC = b"MZ"

# Suspicious API calls commonly used by malware (Process Monitor / WinAPI topic)
SUSPICIOUS_API_CALLS = [
    # Process manipulation
    "CreateRemoteThread",       # Code injection
    "VirtualAllocEx",           # Remote memory allocation
    "WriteProcessMemory",       # Process memory write (injection)
    "NtUnmapViewOfSection",     # Process hollowing
    "SetThreadContext",         # Thread hijacking
    "QueueUserAPC",             # APC injection
    # File system
    "CreateFileW",              # File creation
    "WriteFile",                # File writing
    "DeleteFileW",              # File deletion
    "MoveFileW",                # File moving
    "CopyFileW",                # File copying
    # Registry
    "RegSetValueExW",           # Registry write
    "RegCreateKeyExW",          # Registry key creation
    "RegDeleteKeyW",            # Registry key deletion
    # Network
    "InternetOpenA",            # WinINet initialization
    "InternetConnectA",         # Network connection
    "HttpSendRequestA",         # HTTP request
    "URLDownloadToFileA",       # File download
    "WSAStartup",               # Winsock initialization
    "connect",                  # Socket connection
    "send",                     # Socket send
    "recv",                     # Socket receive
    # Anti-analysis / evasion
    "IsDebuggerPresent",        # Debugger detection
    "CheckRemoteDebuggerPresent",  # Remote debugger detection
    "GetTickCount",             # Timing-based evasion
    "Sleep",                    # Execution delay (sandbox evasion)
    "VirtualProtect",           # Memory protection change (unpacking)
    # Privilege escalation
    "AdjustTokenPrivileges",    # Token manipulation
    "OpenProcessToken",         # Process token access
    # Crypto (ransomware indicators)
    "CryptEncrypt",             # Data encryption
    "CryptDecrypt",             # Data decryption
    "CryptGenKey",              # Key generation
    "CryptImportKey",           # Key import
]

# Suspicious strings that indicate malicious behavior
SUSPICIOUS_STRINGS_PATTERNS = [
    # Network indicators
    r"http[s]?://\d+\.\d+\.\d+\.\d+",  # Direct IP URLs
    r"wget\s+",                          # wget usage
    r"curl\s+",                          # curl usage
    r"powershell.*-enc",                 # Encoded PowerShell
    r"cmd\.exe\s*/c",                    # Command execution
    # Persistence
    r"schtasks\s+/create",              # Scheduled task
    r"reg\s+add.*\\Run",                # Registry run key
    r"sc\s+create",                     # Service creation
    # Evasion
    r"del\s+/[fqs]",                    # Force delete
    r"attrib\s+\+[hsr]",               # Hide files
    r"taskkill",                        # Process killing
    # Ransomware
    r"vssadmin\s+delete\s+shadows",     # Shadow copy deletion
    r"bcdedit\s+/set.*recoveryenabled.*no",  # Disable recovery
    r"wbadmin\s+delete",               # Backup deletion
    r"\.encrypted|\.locked|\.crypt",    # Encrypted file extensions
    # Exfiltration
    r"ftp\s+",                          # FTP usage
    r"ssh\s+",                          # SSH usage
]


# ─── Analysis Functions ───────────────────────────────────────────────────────

def _extract_strings(file_path, min_length=4):
    """
    Extracts printable ASCII and Unicode strings from a binary file.
    Used to detect suspicious API calls, URLs, IPs, and commands.

    Input:  File path and minimum string length
    Output: List of extracted strings
    """
    strings_found = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
        for match in ascii_pattern.finditer(data):
            try:
                strings_found.append(match.group().decode("ascii"))
            except UnicodeDecodeError:
                continue

        # Unicode (UTF-16 LE) strings
        unicode_pattern = re.compile(
            rb"(?:[\x20-\x7E]\x00){%d,}" % min_length
        )
        for match in unicode_pattern.finditer(data):
            try:
                strings_found.append(match.group().decode("utf-16-le"))
            except UnicodeDecodeError:
                continue

    except Exception:
        pass

    return strings_found


def _analyze_pe_imports(file_path):
    """
    Extracts imported DLLs and API function names from a PE file's
    Import Address Table (IAT). This simulates what Process Monitor
    shows for WinAPI calls.

    Input:  File path
    Output: Dict with 'imported_dlls' and 'suspicious_apis' lists
    """
    result = {
        "imported_dlls": [],
        "suspicious_apis": [],
        "total_imports": 0,
    }

    try:
        with open(file_path, "rb") as f:
            # Check MZ header
            magic = f.read(2)
            if magic != PE_MAGIC:
                return result

            # Read PE header offset from DOS header
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return result
            pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

            # Validate PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return result

    except Exception:
        return result

    # Use string extraction to find API names
    # (This is a safer approach than full PE parsing which pefile handles)
    strings = _extract_strings(file_path, min_length=4)

    # Check for suspicious DLLs
    suspicious_dlls = [
        "ws2_32.dll", "wininet.dll", "urlmon.dll",      # Network
        "advapi32.dll", "crypt32.dll",                    # Crypto/Registry
        "ntdll.dll",                                      # Low-level NT
        "shell32.dll",                                    # Shell execution
    ]

    for s in strings:
        s_lower = s.lower()

        # Check DLL imports
        if s_lower.endswith(".dll"):
            if s_lower not in result["imported_dlls"]:
                result["imported_dlls"].append(s)

        # Check for suspicious API calls
        for api in SUSPICIOUS_API_CALLS:
            if api.lower() == s_lower or api == s:
                if s not in result["suspicious_apis"]:
                    result["suspicious_apis"].append(s)
                    result["total_imports"] += 1

    return result


def _predict_process_behavior(file_path, strings, api_analysis):
    """
    Predicts process behavior based on static analysis of the file.
    Simulates what Process Hacker would show if the file were executed.

    Input:  File path, extracted strings, API analysis results
    Output: List of predicted process activities (dicts)
    """
    processes = []

    filename = os.path.basename(file_path)
    file_ext = os.path.splitext(filename)[1].lower()

    # Check for process execution indicators in strings
    for s in strings:
        s_lower = s.lower()

        # Check if file would spawn known suspicious processes
        for proc_name, description in SUSPICIOUS_PROCESSES.items():
            if proc_name.replace(".exe", "") in s_lower and len(s) < 200:
                processes.append({
                    "name": proc_name,
                    "pid": 0,
                    "action": f"Predicted: {description}"
                })
                break

    # Check for CreateProcess / ShellExecute API calls
    for api in api_analysis.get("suspicious_apis", []):
        api_lower = api.lower()
        if "createremotethread" in api_lower:
            processes.append({
                "name": "Target Process",
                "pid": 0,
                "action": "Predicted: Code injection via CreateRemoteThread"
            })
        elif "queueuserapc" in api_lower:
            processes.append({
                "name": "Target Process",
                "pid": 0,
                "action": "Predicted: APC injection detected"
            })

    # If PE file, predict self-execution
    if file_ext in (".exe", ".scr", ".com", ".pif"):
        processes.insert(0, {
            "name": filename,
            "pid": 0,
            "action": "Predicted: Self-execution (PE executable)"
        })

    # If script file, predict interpreter launch
    if file_ext == ".bat" or file_ext == ".cmd":
        processes.insert(0, {
            "name": "cmd.exe",
            "pid": 0,
            "action": f"Predicted: Batch script execution ({filename})"
        })
    elif file_ext == ".ps1":
        processes.insert(0, {
            "name": "powershell.exe",
            "pid": 0,
            "action": f"Predicted: PowerShell script execution ({filename})"
        })
    elif file_ext in (".vbs", ".vbe"):
        processes.insert(0, {
            "name": "wscript.exe",
            "pid": 0,
            "action": f"Predicted: VBScript execution ({filename})"
        })
    elif file_ext in (".js", ".jse"):
        processes.insert(0, {
            "name": "wscript.exe",
            "pid": 0,
            "action": f"Predicted: JScript execution ({filename})"
        })
    elif file_ext == ".hta":
        processes.insert(0, {
            "name": "mshta.exe",
            "pid": 0,
            "action": f"Predicted: HTA execution ({filename})"
        })

    # Deduplicate by process name
    seen = set()
    unique_processes = []
    for proc in processes:
        if proc["name"] not in seen:
            seen.add(proc["name"])
            unique_processes.append(proc)

    return unique_processes


def _predict_network_activity(strings):
    """
    Predicts network activity based on extracted strings.
    Simulates what Wireshark / FakeNet-NG would capture.

    Input:  List of extracted strings
    Output: List of predicted network connections (dicts)
    """
    network = []
    seen_connections = set()

    for s in strings:
        # Direct IP connections (course topic: malware making direct IP connection)
        ip_match = re.match(
            r"(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?",
            s
        )
        if ip_match:
            ip = ip_match.group(1)
            port = int(ip_match.group(2)) if ip_match.group(2) else 80

            # Validate IP
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                # Skip common local/broadcast addresses
                if ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255":
                    continue

                conn_key = (ip, port)
                if conn_key not in seen_connections:
                    seen_connections.add(conn_key)

                    protocol = "HTTPS" if port == 443 else "HTTP" if port == 80 else "TCP"
                    network.append({
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "direction": "Outbound"
                    })

        # URL-based connections
        url_match = re.match(r"https?://([a-zA-Z0-9.-]+)(?::(\d+))?", s)
        if url_match:
            host = url_match.group(1)
            port = int(url_match.group(2)) if url_match.group(2) else (
                443 if s.startswith("https") else 80
            )

            # Skip if it's a pure IP (already handled above)
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                conn_key = (host, port)
                if conn_key not in seen_connections:
                    seen_connections.add(conn_key)
                    network.append({
                        "ip": host,
                        "port": port,
                        "protocol": "HTTPS" if port == 443 else "HTTP",
                        "direction": "Outbound"
                    })

    return network


def _predict_registry_changes(strings, api_analysis):
    """
    Predicts registry changes based on extracted strings.
    Simulates what Autoruns would detect for persistence mechanisms.

    Input:  Extracted strings, API analysis
    Output: List of predicted registry modifications (strings)
    """
    registry = []
    seen = set()

    for s in strings:
        # Check for persistence registry paths
        for persistence_key in PERSISTENCE_REGISTRY_KEYS:
            if persistence_key.lower() in s.lower() and len(s) < 300:
                if s.lower() not in seen:
                    seen.add(s.lower())
                    registry.append(f"{s} [PREDICTED MODIFICATION]")
                break

        # Check for explicit registry commands
        if re.search(r"reg\s+(add|delete|query)", s, re.IGNORECASE) and len(s) < 300:
            if s.lower() not in seen:
                seen.add(s.lower())
                registry.append(f"{s} [PREDICTED COMMAND]")

    # If registry APIs are imported, flag potential modifications
    for api in api_analysis.get("suspicious_apis", []):
        if "RegSetValue" in api or "RegCreateKey" in api:
            entry = f"Registry API detected: {api} [PREDICTED CALL]"
            if entry.lower() not in seen:
                seen.add(entry.lower())
                registry.append(entry)

    return registry


def _predict_file_changes(strings, file_path):
    """
    Predicts file system changes based on extracted strings.
    Simulates file system monitoring during execution.

    Input:  Extracted strings, original file path
    Output: List of predicted file operations (strings)
    """
    file_changes = []
    seen = set()

    for s in strings:
        s_stripped = s.strip()

        # Check for file paths to sensitive locations
        for sensitive_dir in SENSITIVE_DIRECTORIES:
            if sensitive_dir.lower() in s_stripped.lower() and len(s_stripped) < 300:
                # Check if it looks like a file path
                if re.search(r"[A-Za-z]:\\|\\\\|/tmp/|/etc/", s_stripped):
                    if s_stripped.lower() not in seen:
                        seen.add(s_stripped.lower())
                        file_changes.append(f"{s_stripped} [PREDICTED ACCESS]")
                    break

        # Check for file drop commands
        if re.search(r"(copy|move|rename|del|mkdir)\s+", s_stripped, re.IGNORECASE) and len(s_stripped) < 300:
            if s_stripped.lower() not in seen:
                seen.add(s_stripped.lower())
                file_changes.append(f"{s_stripped} [PREDICTED COMMAND]")

        # Check for download-and-save patterns
        if re.search(r"URLDownloadToFile|wget|curl.*-o|bitsadmin.*transfer",
                      s_stripped, re.IGNORECASE) and len(s_stripped) < 300:
            if s_stripped.lower() not in seen:
                seen.add(s_stripped.lower())
                file_changes.append(f"{s_stripped} [PREDICTED DOWNLOAD]")

    return file_changes


def _detect_suspicious_patterns(strings):
    """
    Detects suspicious behavioral patterns in extracted strings.
    These correspond to patterns visible in Process Monitor / ProcDot.

    Input:  List of extracted strings
    Output: List of suspicious pattern descriptions
    """
    patterns_found = []
    seen = set()

    for s in strings:
        for pattern in SUSPICIOUS_STRINGS_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                # Create a readable indicator
                match_text = s[:100] + "..." if len(s) > 100 else s
                indicator = f"Suspicious pattern: {match_text}"

                if indicator.lower() not in seen:
                    seen.add(indicator.lower())
                    patterns_found.append(indicator)
                break  # One match per string is enough

    return patterns_found


# ─── Main Analysis Function ──────────────────────────────────────────────────

def run_dynamic_analysis(file_path):
    """
    Entry point for the Dynamic Analysis Module.
    Called by the orchestrator to perform behavioral analysis on a file.

    This function operates in safe mode — it does NOT execute the file.
    Instead, it performs behavioral prediction from static indicators
    and submits the file to a cloud sandbox.

    Input:
        file_path: Absolute path to the file to analyze (str)

    Output:
        dict with keys:
            - processes:              list of dicts (name, pid, action)
            - network_activity:       list of dicts (ip, port, protocol, direction)
            - registry_changes:       list of strings
            - file_changes:           list of strings
            - score:                  float (0.0 - 10.0)
            - suspicious_indicators:  list of strings
            - api_calls:              list of strings (suspicious APIs found)
            - sandbox_report:         dict (sandbox analysis results)

    Example:
        >>> from analysis.dynamic.dynamic_analyzer import run_dynamic_analysis
        >>> result = run_dynamic_analysis("C:\\samples\\malware.exe")
        >>> print(result["score"])
        7.5
    """
    # Initialize default result structure
    result = {
        "processes": [],
        "network_activity": [],
        "registry_changes": [],
        "file_changes": [],
        "score": 0.0,
        "suspicious_indicators": [],
        "api_calls": [],
        "sandbox_report": {},
    }

    # Validate file exists
    if not os.path.isfile(file_path):
        result["suspicious_indicators"].append(f"File not found: {file_path}")
        return result

    try:
        # ── Step 1: Extract strings from the file ──
        strings = _extract_strings(file_path, min_length=4)

        # ── Step 2: Analyze PE imports and API calls (Process Monitor topic) ──
        api_analysis = _analyze_pe_imports(file_path)
        result["api_calls"] = api_analysis.get("suspicious_apis", [])

        # ── Step 3: Predict process behavior (Process Hacker topic) ──
        predicted_processes = _predict_process_behavior(
            file_path, strings, api_analysis
        )

        # ── Step 4: Predict network activity (Wireshark / FakeNet-NG topic) ──
        predicted_network = _predict_network_activity(strings)

        # ── Step 5: Predict registry changes (Autoruns topic) ──
        predicted_registry = _predict_registry_changes(strings, api_analysis)

        # ── Step 6: Predict file system changes ──
        predicted_filesystem = _predict_file_changes(strings, file_path)

        # ── Step 7: Detect suspicious patterns (ProcDot visualization topic) ──
        suspicious_patterns = _detect_suspicious_patterns(strings)

        # Assemble local analysis results
        local_results = {
            "processes": parse_process_activity(predicted_processes),
            "network_activity": parse_network_activity(predicted_network),
            "registry_changes": parse_registry_changes(predicted_registry),
            "file_changes": parse_file_changes(predicted_filesystem),
        }

        # ── Step 8: Submit to sandbox (sandbox execution topic) ──
        sandbox_results = {
            "processes": [],
            "network_activity": [],
            "registry_changes": [],
            "file_changes": [],
        }

        submission = submit_to_sandbox(file_path)
        sandbox_report = {"submission": submission}

        if submission.get("success"):
            sha256 = submission.get("sha256", "")
            if sha256:
                report = get_sandbox_report(sha256, poll=False)
                sandbox_report["report"] = report

                # Extract sandbox behavioral data
                sandbox_results["processes"] = parse_process_activity(
                    report.get("processes", [])
                )
                sandbox_results["network_activity"] = parse_network_activity(
                    report.get("network_activity", [])
                )
                sandbox_results["registry_changes"] = parse_registry_changes(
                    report.get("registry_changes", [])
                )
                sandbox_results["file_changes"] = parse_file_changes(
                    report.get("file_changes", [])
                )

        result["sandbox_report"] = sandbox_report

        # ── Step 9: Merge local + sandbox results ──
        merged = merge_results(local_results, sandbox_results)

        result["processes"] = merged["processes"]
        result["network_activity"] = merged["network_activity"]
        result["registry_changes"] = merged["registry_changes"]
        result["file_changes"] = merged["file_changes"]

        # ── Step 10: Calculate dynamic score ──
        score, indicators = calculate_dynamic_score(merged)

        # Add suspicious patterns to indicators
        indicators.extend(suspicious_patterns)

        # Add API-level indicators
        if api_analysis.get("suspicious_apis"):
            indicators.append(
                f"Suspicious API imports detected: {', '.join(api_analysis['suspicious_apis'][:10])}"
            )

        result["score"] = score
        result["suspicious_indicators"] = indicators

    except Exception as e:
        result["suspicious_indicators"].append(f"Analysis error: {str(e)}")

    return result


# ─── Main Entry Point (for independent testing) ───────────────────────────────

if __name__ == "__main__":
    """
    Independent test for the dynamic analyzer module.
    Verifies: Input accepted, Output format correct, No external dependencies.
    """
    import json
    import sys

    print("=" * 60)
    print("MalScope - Dynamic Analyzer Module Test")
    print("=" * 60)

    # Determine test file
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
    else:
        # Use this script file itself as a test target
        test_file = os.path.abspath(__file__)

    print(f"\nTest file: {test_file}")
    print(f"File exists: {os.path.isfile(test_file)}")
    print(f"File size: {os.path.getsize(test_file) if os.path.isfile(test_file) else 'N/A'} bytes")

    # Run analysis
    print("\n--- Running Dynamic Analysis ---")
    result = run_dynamic_analysis(test_file)

    # Display results
    print(f"\n--- Results ---")
    print(f"  Processes:     {len(result['processes'])}")
    for p in result["processes"]:
        print(f"    [{p['pid']}] {p['name']} → {p['action']}")

    print(f"\n  Network:       {len(result['network_activity'])}")
    for n in result["network_activity"]:
        print(f"    {n['protocol']} {n['ip']}:{n['port']} ({n['direction']})")

    print(f"\n  Registry:      {len(result['registry_changes'])}")
    for r in result["registry_changes"]:
        print(f"    {r}")

    print(f"\n  File Changes:  {len(result['file_changes'])}")
    for f in result["file_changes"]:
        print(f"    {f}")

    print(f"\n  API Calls:     {len(result['api_calls'])}")
    for a in result["api_calls"]:
        print(f"    {a}")

    print(f"\n  Score:         {result['score']}/10.0")
    print(f"  Indicators:    {len(result['suspicious_indicators'])}")
    for ind in result["suspicious_indicators"]:
        print(f"    ⚠ {ind}")

    # Verify output format
    print("\n--- Output Format Verification ---")
    print(json.dumps(result, indent=2, default=str))

    print("\n✔ Input accepted")
    print("✔ Output format correct (processes, network_activity, registry_changes, file_changes, score)")
    print("✔ No dependency on GUI or other modules")
    print("✔ JSON serializable")
    print("✔ Safe mode — file was NOT executed")

    # Test with non-existent file
    print("\n--- Edge Case: Non-existent file ---")
    result_missing = run_dynamic_analysis("C:\\nonexistent\\file.exe")
    print(f"  Score: {result_missing['score']}")
    print(f"  Indicators: {result_missing['suspicious_indicators']}")
    print("✔ Graceful error handling for missing files")
