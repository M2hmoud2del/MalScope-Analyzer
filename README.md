# 🛡️ MalScope – Automated Malware Analysis & Reporting Tool

MalScope is a modular malware analysis system that combines **static analysis**, **dynamic analysis**, and optional **AI-powered insights** to scan suspicious files and generate detailed security reports.

---

# 🧠 Project Idea

The system scans a folder of untrusted files and processes them using multiple independent analysis modules:

- Static Analysis
- Dynamic Analysis
- Risk Scoring Engine
- AI/LLM Explanation
- PDF Report Generation

Each module is **fully independent** and communicates through a central orchestrator.

---

# 🏗️ Architecture Overview
![Logo](/Docs/System_Architecture.png)

```

GUI → Orchestrator → Static Analysis → Dynamic Analysis → Scoring → AI → Reports

```

Each module produces a **standard output format** that is consumed by the next layer.

---

# 📦 Project Structure

```

MalScope/
│
├── gui/                  → User Interface (PyQt5)
├── core/                 → Orchestrator (System Controller)
│
├── analysis/
│   ├── static/           → Static Analysis Modules
│   ├── dynamic/          → Dynamic Analysis Modules
│   └── scoring/          → Risk Scoring Engine
│
├── ai/                   → LLM-based Analysis
├── utils/                → Helper functions (hashing, entropy, etc.)
├── reports/              → PDF Report Generator
└── main.py               → Entry point

````

---

# ⚙️ How the System Works

1. User selects a folder via GUI
2. Orchestrator processes each file
3. File is sent to:
   - Static Analysis module
   - Dynamic Analysis module
4. Results are sent to:
   - Risk Scoring Engine
   - AI Module
5. Final results are:
   - Displayed in GUI
   - Exported as PDF report

---

# 🧩 Module Responsibilities

## 🎨 GUI (PyQt5)
**Input/Output layer**

### Output:
- Folder path selected
- Scan progress
- Results table (file, hash, verdict, score)

---

## 🧠 Core / Orchestrator
**System brain**

### Input:
- Folder path

### Output:
```json
{
  "file": "sample.exe",
  "static": {...},
  "dynamic": {...},
  "score": 8,
  "verdict": "Malicious"
}
````

---

## 🔍 Static Analysis Module

### Responsibilities:

* 5-Hash Verification (MD5, SHA1, SHA256, SHA512, IMPHASH)
* String extraction
* VirusTotal lookup
* PE file inspection

### Output:

```json
{
  "hashes": {
    "md5": "...",
    "sha1": "...",
    "sha256": "...",
    "sha512": "...",
    "imphash": "..."
  },
  "urls": [],
  "ips": [],
  "vt_result": "5/70 malicious"
}
```

---

## ⚡ Dynamic Analysis Module

### Responsibilities:

* Behavior monitoring
* Sandbox execution (if available)
* Process & network tracking

### Output:

```json
{
  "processes": [],
  "network_activity": [],
  "registry_changes": []
}
```

---

## 📊 Scoring Engine

### Responsibilities:

* Combine static + dynamic results using a **Weighted Scoring System (60/40)**
  * The final Risk Score (0-10) is calculated as: `(Static Score * 0.6) + (Dynamic Score * 0.4)`
* Generate final risk score and verdict

### Output:

```json
{
  "score": 0-10,
  "verdict": "Clean | Suspicious | Malicious"
}
```

---

## 🤖 AI / LLM Module

### Responsibilities:

* Explain results in human language
* Provide security recommendations

### Output:
---
```
"This file shows ransomware-like behavior due to encryption patterns and suspicious API calls..."
```
----
---

## 📄 Reports Module

### Responsibilities:

* Generate final PDF report
* Include:

  * File results
  * Scores
  * Indicators
  * Final verdict

### Output:


*  output`report.pdf`

---

# 👥 Team Development Rules

## ⚠️ Important Collaboration Rules

To ensure clean integration:

### 1. Each module must be independent

No module should depend directly on another module’s internal logic.

---

### 2. Standard Output Format

Every module MUST return results in JSON-like structure.

---

### 3. README per Module

Each developer must document:

* What the module does
* Input format
* Output format
* Example output

---

### 4. No “black box” code

Each contributor must ensure:

* Clear functions
* Clear outputs
* Easy integration

---

### 5. Orchestrator responsibility

Only the orchestrator is allowed to:

* Call modules
* Combine results
* Decide final verdict

---

# 🔄 Integration Rule

When a module is finished, it must be tested independently and return:

✔ Input accepted
✔ Output format correct
✔ No dependency on GUI or other modules

---

# 🚀 Running the Project

```bash
pip install -r requirements.txt
python main.py
```

---

# 🎯 Goal of the Project

* Build a real-world malware analysis pipeline
* Simulate SOC-level analysis workflow
* Ensure modular cybersecurity system design
* Provide readable security reports

---

# 📌 Notes

* This project is fully modular
* Each module can be improved independently
  
