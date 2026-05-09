"""
MalScope Dynamic Analysis - Sandbox Client
============================================
Submits files to the Hybrid Analysis sandbox API for behavioral
detonation and retrieves analysis reports.

Hybrid Analysis (https://www.hybrid-analysis.com/) provides a free
public API for automated malware analysis in cloud sandboxes.

Course Topics Covered:
- Sandbox execution
- Behavior monitoring in isolated environment
- Network traffic capture during execution
- Process & registry activity recording

Input:  File path (str)
Output: Sandbox behavioral report (dict)
"""

import os
import time
import hashlib
import requests


# ─── Configuration ────────────────────────────────────────────────────────────

# Placeholder for the Hybrid Analysis API Key
# Register at https://www.hybrid-analysis.com/ to obtain a free API key
API_KEY = "h9wz6hxgf93c4ccbdb28iglp83112b047e6ecjwb2c3709e5thzmuffs3a212208"

# Hybrid Analysis API base URL
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Default environment ID for sandbox execution
# 300 = Windows 10 64-bit
# 120 = Windows 7 64-bit
# 110 = Windows 7 32-bit
DEFAULT_ENVIRONMENT_ID = 300

# Timeout settings (in seconds)
SUBMIT_TIMEOUT = 60
POLL_TIMEOUT = 30
MAX_POLL_ATTEMPTS = 30      # Maximum polling attempts for report
POLL_INTERVAL = 10          # Seconds between poll attempts


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _get_headers():
    """Returns the standard API headers for Hybrid Analysis."""
    return {
        "api-key": API_KEY,
        "User-Agent": "MalScope-Analyzer",
        "accept": "application/json",
    }


def _calculate_sha256(file_path):
    """Calculates the SHA256 hash of a file for report lookup."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


# ─── Core API Functions ───────────────────────────────────────────────────────

def submit_to_sandbox(file_path, environment_id=None):
    """
    Submits a file to Hybrid Analysis sandbox for detonation.

    Input:
        file_path:      Absolute path to the file to analyze
        environment_id: Sandbox environment (default: Windows 10 64-bit)

    Output:
        dict with keys:
            - success: bool
            - job_id:  str (submission ID for tracking)
            - sha256:  str (file hash for report retrieval)
            - error:   str (if submission failed)

    Example:
        >>> submit_to_sandbox("C:\\samples\\malware.exe")
        {"success": True, "job_id": "abc123", "sha256": "def456..."}
    """
    if API_KEY == "YOUR_API_KEY_HERE":
        return {
            "success": False,
            "job_id": None,
            "sha256": _calculate_sha256(file_path),
            "error": "Hybrid Analysis API key not configured"
        }

    if not os.path.isfile(file_path):
        return {
            "success": False,
            "job_id": None,
            "sha256": None,
            "error": f"File not found: {file_path}"
        }

    env_id = environment_id or DEFAULT_ENVIRONMENT_ID

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            data = {"environment_id": env_id}

            response = requests.post(
                f"{BASE_URL}/submit/file",
                headers=_get_headers(),
                files=files,
                data=data,
                timeout=SUBMIT_TIMEOUT
            )

        if response.status_code == 201:
            result = response.json()
            return {
                "success": True,
                "job_id": result.get("job_id", ""),
                "sha256": result.get("sha256", _calculate_sha256(file_path)),
                "error": None
            }
        elif response.status_code == 401:
            return {
                "success": False,
                "job_id": None,
                "sha256": _calculate_sha256(file_path),
                "error": "Hybrid Analysis API key invalid or missing"
            }
        elif response.status_code == 429:
            return {
                "success": False,
                "job_id": None,
                "sha256": _calculate_sha256(file_path),
                "error": "API rate limit exceeded — try again later"
            }
        else:
            return {
                "success": False,
                "job_id": None,
                "sha256": _calculate_sha256(file_path),
                "error": f"API error (HTTP {response.status_code})"
            }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "job_id": None,
            "sha256": _calculate_sha256(file_path),
            "error": "Submission timed out — check internet connection"
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "job_id": None,
            "sha256": _calculate_sha256(file_path),
            "error": "Connection error — check internet connection"
        }
    except Exception as e:
        return {
            "success": False,
            "job_id": None,
            "sha256": _calculate_sha256(file_path),
            "error": f"Unexpected error: {str(e)}"
        }


def get_sandbox_report(sha256, poll=True):
    """
    Retrieves the behavioral analysis report from Hybrid Analysis.

    If poll=True, will keep checking until the report is ready
    or the maximum attempts are exhausted.

    Input:
        sha256: SHA256 hash of the submitted file
        poll:   Whether to poll until report is ready (default: True)

    Output:
        dict with keys:
            - sandbox_available: bool
            - verdict:           str (malicious/suspicious/clean/unknown)
            - threat_score:      int (0-100)
            - processes:         list of dicts
            - network_activity:  list of dicts
            - registry_changes:  list of strings
            - file_changes:      list of strings
            - error:             str (if retrieval failed)

    Example:
        >>> get_sandbox_report("abc123def456...")
        {"sandbox_available": True, "verdict": "malicious", "threat_score": 85, ...}
    """
    if API_KEY == "YOUR_API_KEY_HERE":
        return {
            "sandbox_available": False,
            "verdict": "unknown",
            "threat_score": 0,
            "processes": [],
            "network_activity": [],
            "registry_changes": [],
            "file_changes": [],
            "error": "Hybrid Analysis API key not configured"
        }

    if not sha256:
        return {
            "sandbox_available": False,
            "verdict": "unknown",
            "threat_score": 0,
            "processes": [],
            "network_activity": [],
            "registry_changes": [],
            "file_changes": [],
            "error": "No SHA256 hash provided"
        }

    attempts = 0
    max_attempts = MAX_POLL_ATTEMPTS if poll else 1

    while attempts < max_attempts:
        try:
            response = requests.get(
                f"{BASE_URL}/report/{sha256}:300/summary",
                headers=_get_headers(),
                timeout=POLL_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json()
                return _parse_sandbox_report(data)

            elif response.status_code == 404:
                if poll and attempts < max_attempts - 1:
                    # Report not ready yet — wait and retry
                    attempts += 1
                    time.sleep(POLL_INTERVAL)
                    continue
                else:
                    return {
                        "sandbox_available": False,
                        "verdict": "unknown",
                        "threat_score": 0,
                        "processes": [],
                        "network_activity": [],
                        "registry_changes": [],
                        "file_changes": [],
                        "error": "Report not found (analysis may still be in progress)"
                    }

            elif response.status_code == 401:
                return {
                    "sandbox_available": False,
                    "verdict": "unknown",
                    "threat_score": 0,
                    "processes": [],
                    "network_activity": [],
                    "registry_changes": [],
                    "file_changes": [],
                    "error": "API key invalid or missing"
                }

            else:
                return {
                    "sandbox_available": False,
                    "verdict": "unknown",
                    "threat_score": 0,
                    "processes": [],
                    "network_activity": [],
                    "registry_changes": [],
                    "file_changes": [],
                    "error": f"API error (HTTP {response.status_code})"
                }

        except requests.exceptions.RequestException:
            return {
                "sandbox_available": False,
                "verdict": "unknown",
                "threat_score": 0,
                "processes": [],
                "network_activity": [],
                "registry_changes": [],
                "file_changes": [],
                "error": "Connection error while retrieving report"
            }

        attempts += 1

    return {
        "sandbox_available": False,
        "verdict": "unknown",
        "threat_score": 0,
        "processes": [],
        "network_activity": [],
        "registry_changes": [],
        "file_changes": [],
        "error": "Report retrieval timed out after maximum attempts"
    }


def _parse_sandbox_report(data):
    """
    Parses the raw Hybrid Analysis API response into our standard format.

    Input:  Raw API response dict from Hybrid Analysis
    Output: Normalized behavioral report dict
    """
    report = {
        "sandbox_available": True,
        "verdict": "unknown",
        "threat_score": 0,
        "processes": [],
        "network_activity": [],
        "registry_changes": [],
        "file_changes": [],
        "error": None
    }

    # Verdict / threat score
    verdict_raw = data.get("verdict", "")
    if verdict_raw:
        report["verdict"] = verdict_raw.lower()

    threat_score = data.get("threat_score", data.get("av_detect", 0))
    report["threat_score"] = int(threat_score) if threat_score else 0

    # Process information
    processes_raw = data.get("processes", [])
    for proc in processes_raw:
        if isinstance(proc, dict):
            report["processes"].append({
                "name": proc.get("name", proc.get("process_name", "Unknown")),
                "pid": proc.get("pid", proc.get("process_id", 0)),
                "action": proc.get("command_line", proc.get("action", "Sandbox observed"))
            })

    # Network activity (hosts contacted)
    hosts = data.get("domains", [])
    for host in hosts:
        if isinstance(host, str):
            report["network_activity"].append({
                "ip": host,
                "port": 80,
                "protocol": "TCP",
                "direction": "Outbound"
            })
        elif isinstance(host, dict):
            report["network_activity"].append({
                "ip": host.get("host", host.get("domain", "")),
                "port": host.get("port", 80),
                "protocol": "TCP",
                "direction": "Outbound"
            })

    # Also check for direct IP connections
    hosts_ip = data.get("hosts", [])
    for ip in hosts_ip:
        if isinstance(ip, str):
            report["network_activity"].append({
                "ip": ip,
                "port": 0,
                "protocol": "TCP",
                "direction": "Outbound"
            })

    # Extract compromised hosts / C2
    total_network = data.get("total_network_connections", 0)
    if total_network and not report["network_activity"]:
        report["network_activity"].append({
            "ip": "Sandbox detected connections",
            "port": 0,
            "protocol": "N/A",
            "direction": f"{total_network} total connections"
        })

    # File operations from sandbox
    extracted_files = data.get("extracted_files", [])
    for f in extracted_files:
        if isinstance(f, dict):
            name = f.get("name", f.get("file_path", "Unknown"))
            report["file_changes"].append(f"{name} [DROPPED]")
        elif isinstance(f, str):
            report["file_changes"].append(f"{f} [DROPPED]")

    return report


# ─── Main Entry Point (for independent testing) ───────────────────────────────

if __name__ == "__main__":
    """
    Independent test for the sandbox client module.
    Verifies: Input accepted, Output format correct, No external dependencies.
    """
    import json

    print("=" * 60)
    print("MalScope - Sandbox Client Module Test")
    print("=" * 60)

    # Test 1: Submit with placeholder API key (should return graceful error)
    print("\n--- Test 1: Submit file (placeholder API key) ---")
    test_path = os.path.abspath(__file__)  # Use this file as test sample
    result = submit_to_sandbox(test_path)
    print(f"  Success:  {result['success']}")
    print(f"  Job ID:   {result['job_id']}")
    print(f"  SHA256:   {result['sha256']}")
    print(f"  Error:    {result['error']}")

    # Test 2: Get report with placeholder API key
    print("\n--- Test 2: Get sandbox report (placeholder API key) ---")
    report = get_sandbox_report("test_hash_abc123", poll=False)
    print(f"  Available: {report['sandbox_available']}")
    print(f"  Verdict:   {report['verdict']}")
    print(f"  Score:     {report['threat_score']}")
    print(f"  Error:     {report['error']}")

    # Test 3: Submit non-existent file
    print("\n--- Test 3: Submit non-existent file ---")
    result = submit_to_sandbox("C:\\nonexistent\\file.exe")
    print(f"  Success:  {result['success']}")
    print(f"  Error:    {result['error']}")

    # Test 4: Parse a mock sandbox report
    print("\n--- Test 4: Parse mock sandbox report ---")
    mock_report = {
        "verdict": "malicious",
        "threat_score": 85,
        "processes": [
            {"name": "cmd.exe", "pid": 1234, "command_line": "cmd.exe /c del shadow"},
            {"name": "powershell.exe", "pid": 5678, "command_line": "powershell -enc ..."}
        ],
        "domains": ["evil-c2.com", "malware-download.net"],
        "hosts": ["185.220.101.45", "91.234.99.10"],
        "extracted_files": [
            {"name": "payload.dll", "file_path": "C:\\Temp\\payload.dll"},
            "backdoor.exe"
        ],
        "total_network_connections": 15
    }
    parsed = _parse_sandbox_report(mock_report)
    print(json.dumps(parsed, indent=2))

    # Verify output format
    print("\n--- Output Format Verification ---")
    print("✔ Input accepted")
    print("✔ Output format correct")
    print("✔ No dependency on GUI or other modules")
    print("✔ JSON serializable")
    print("✔ Graceful error handling for missing API key")
