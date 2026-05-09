# ⚡ Dynamic Analysis Module

## What This Module Does

The Dynamic Analysis module performs **behavioral analysis** on suspicious files to detect malicious runtime behavior. It operates in **safe mode** by default — it does NOT execute files directly on your system.

Instead, it:
1. **Extracts strings** from the binary to find suspicious commands, URLs, IPs
2. **Analyzes PE imports** to detect suspicious Windows API usage
3. **Predicts process behavior** based on file type and embedded commands
4. **Predicts network activity** based on extracted URLs and IP addresses
5. **Predicts registry changes** based on persistence patterns
6. **Predicts file system changes** based on file paths and commands
7. **Submits to Hybrid Analysis sandbox** for cloud-based detonation (when API key is configured)
8. **Merges and scores** all behavioral data

### Course Topics Covered

| Topic | How It's Covered |
|-------|-----------------|
| Process Hacker | Process activity prediction from file contents |
| Autoruns | Registry persistence key detection |
| Process Monitor (WinAPI) | Suspicious API import detection (CreateRemoteThread, VirtualAllocEx, etc.) |
| ProcDot Visualization | Suspicious behavioral pattern detection |
| File System Interaction | File drop/modification prediction |
| Registry Changes | Autorun and persistence key monitoring |
| Wireshark & FakeNet-NG | Network connection prediction from URLs/IPs |
| Direct IP Connection | Detection of IP-based C2 (no DNS resolution) |
| Word Document Analysis | Handles all file types including documents |
| REMnux & iNetSim | Network sinkhole pattern awareness in scoring |

---

## Input Format

```python
file_path: str  # Absolute path to the file to analyze
```

**Example:**
```python
from analysis.dynamic.dynamic_analyzer import run_dynamic_analysis

result = run_dynamic_analysis("C:\\samples\\malware.exe")
```

---

## Output Format

```json
{
  "processes": [
    {
      "name": "cmd.exe",
      "pid": 0,
      "action": "Predicted: Command shell execution"
    }
  ],
  "network_activity": [
    {
      "ip": "185.220.101.45",
      "port": 443,
      "protocol": "HTTPS",
      "direction": "Outbound"
    }
  ],
  "registry_changes": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware [PREDICTED MODIFICATION]"
  ],
  "file_changes": [
    "C:\\Windows\\Temp\\payload.dll [PREDICTED ACCESS]"
  ],
  "score": 7.5,
  "suspicious_indicators": [
    "Shell process spawned: cmd.exe (PID: 0)",
    "Outbound connection: 185.220.101.45:443 (HTTPS) [Direct IP — no DNS resolution]",
    "Registry persistence detected: HKLM\\...\\Run\\Malware [PREDICTED MODIFICATION]"
  ],
  "api_calls": [
    "CreateRemoteThread",
    "VirtualAllocEx",
    "InternetConnectA"
  ],
  "sandbox_report": {
    "submission": {"success": false, "error": "API key not configured"}
  }
}
```

---

## Example Output

### For a clean text file:
```json
{
  "processes": [],
  "network_activity": [],
  "registry_changes": [],
  "file_changes": [],
  "score": 0.0,
  "suspicious_indicators": [],
  "api_calls": [],
  "sandbox_report": {}
}
```

### For a suspicious PE executable:
```json
{
  "processes": [
    {"name": "malware.exe", "pid": 0, "action": "Predicted: Self-execution (PE executable)"},
    {"name": "cmd.exe", "pid": 0, "action": "Predicted: Command shell execution"},
    {"name": "powershell.exe", "pid": 0, "action": "Predicted: PowerShell execution"}
  ],
  "network_activity": [
    {"ip": "91.234.99.10", "port": 4444, "protocol": "TCP", "direction": "Outbound"}
  ],
  "registry_changes": [
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update [PREDICTED MODIFICATION]"
  ],
  "file_changes": [
    "C:\\Windows\\Temp\\dropper.dll [PREDICTED ACCESS]"
  ],
  "score": 8.5,
  "suspicious_indicators": [
    "Shell process spawned: cmd.exe (PID: 0)",
    "Shell process spawned: powershell.exe (PID: 0)",
    "Outbound connection: 91.234.99.10:4444 (TCP) [Suspicious port: Metasploit default handler] [Direct IP]",
    "Registry persistence detected: ...\\Run\\Update",
    "File operation in sensitive directory: C:\\Windows\\Temp\\dropper.dll",
    "Suspicious API imports detected: CreateRemoteThread, VirtualAllocEx"
  ],
  "api_calls": ["CreateRemoteThread", "VirtualAllocEx", "InternetConnectA"],
  "sandbox_report": {}
}
```

---

## Module Files

| File | Purpose |
|------|---------|
| `__init__.py` | Package init, exports `run_dynamic_analysis` |
| `dynamic_analyzer.py` | Main entry point — orchestrates all analysis steps |
| `sandbox_client.py` | Hybrid Analysis API client for sandbox submission |
| `behavior_parser.py` | Parses, normalizes, merges, and scores behavioral data |
| `README.md` | This documentation file |

---

## Dependencies

| Package | Purpose | Installation |
|---------|---------|-------------|
| `requests` | HTTP client for Hybrid Analysis API | Already in `requirements.txt` |
| `re` | Regex for pattern matching | Python standard library |
| `os` | File system operations | Python standard library |
| `struct` | Binary data parsing (PE headers) | Python standard library |
| `hashlib` | File hashing (SHA256) | Python standard library |

---

## How to Test Independently

```bash
# Test the behavior parser
python -m analysis.dynamic.behavior_parser

# Test the sandbox client
python -m analysis.dynamic.sandbox_client

# Test the full dynamic analyzer
python -m analysis.dynamic.dynamic_analyzer

# Test with a specific file
python -m analysis.dynamic.dynamic_analyzer "C:\path\to\sample.exe"
```

Each test will output:
- ✔ Input accepted
- ✔ Output format correct
- ✔ No dependency on GUI or other modules
- ✔ JSON serializable

---

## Integration with Orchestrator

The orchestrator calls this module as:
```python
from analysis.dynamic.dynamic_analyzer import run_dynamic_analysis

dynamic_result = run_dynamic_analysis(file_path)
```

The output is placed under the `"dynamic"` key in the orchestrator's result dictionary, which the GUI's `DynamicAnalysisTab` reads to display:
- ⚙️ Spawned Processes (tree view)
- 🌐 Network Activity (table)
- 📋 Registry Changes (text area)
- 📁 File System Changes (list)

---

## Sandbox Setup (Optional)

To enable cloud sandbox analysis:
1. Register at [https://www.hybrid-analysis.com/](https://www.hybrid-analysis.com/)
2. Go to your profile → API Key
3. Replace `YOUR_API_KEY_HERE` in `sandbox_client.py` with your key

The module works without the sandbox — it falls back to local behavioral prediction.
