# 🤖 AI Analysis Module

## What This Module Does

The AI Analysis module acts as a virtual Senior Malware Research Specialist. It uses **Google's Gemini Large Language Model (LLM)** to process raw JSON data from the static and dynamic analysis modules and translate it into a human-readable threat intelligence summary.

Instead of just showing raw data to the user, it:
1. **Contextualizes** the risk score and engine verdict.
2. **Correlates** static indicators (like high entropy) with dynamic behaviors (like spawned command shells).
3. **Explains** the "why" behind a file's malicious or clean classification.
4. **Recommends** actionable next steps for a SOC analyst (quarantine, memory dumps, etc.).
5. **Strips formatting** to ensure plain-text compatibility with the PyQt5 GUI and PDF Report Generator.

## Technical Concepts Applied

| Capability | Implementation Detail |
| :--- | :--- |
| **Automated Threat Intelligence** | Translating raw IOCs (Indicators of Compromise) into SOC-ready reports. |
| **Prompt Engineering** | Structuring strict system prompts to prevent AI hallucinations and enforce JSON-to-text formatting. |
| **API Integration** | Securely authenticating and communicating with external REST APIs (Google Gemini). |
| **Data Normalization** | Parsing nested Python dictionaries from the Orchestrator into stringified formats for the LLM context window. |

## Input Format

The module expects a compiled dictionary of the file's scan results.

```python
target_data = {
    "file": "sample.exe",
    "verdict": "malicious",
    "score": 95,
    "static": {"entropy": 6.8, "pe_sections": 5},
    "dynamic": {"processes": [{"name": "cmd.exe"}], "network": []}
}

```

## Example Output

**For a benign file (Engine Verdict: Clean):**

```text
1. Threat Summary: The file appears to be a standard, benign executable. No suspicious behavioral anomalies or malicious signatures were detected during the analysis.
2. Suspicious Indicators:
- None detected. Static and dynamic profiles match expected baseline behavior.
3. Recommended Response:
- No action required. The file is safe for execution.

```

**For a malicious dropper (Engine Verdict: Suspicious/Malicious):**

```text
1. Threat Summary: This file is a confirmed malicious executable masquerading as a benign document. It demonstrates clear indicators of compromise including unauthorized process spawning and C2 communication.
2. Suspicious Indicators:
- High entropy level of 6.8 suggests packed or encrypted code.
- Execution results in the spawning of a system shell via cmd.exe.
- Outbound network traffic established on port 443.
3. Recommended Response:
- Quarantine the file immediately and block associated IP addresses at the firewall.
- Perform a memory dump of the infected host to capture volatile indicators.

```

## Module Files

| File | Purpose |
| --- | --- |
| `llm_analyzer.py` | Main class handling API configuration, prompt engineering, and response parsing. |
| `README.md` | This documentation file. |

## Dependencies

| Package | Purpose | Installation |
| --- | --- | --- |
| `google-generativeai` | Official Google Gemini API client | `pip install google-generativeai` |
| `python-dotenv` | Secure loading of environment variables | `pip install python-dotenv` |

## How to Test Independently

To test the AI parser without running the full GUI or Orchestrator:

```bash
# Run the analyzer directly from the root directory
python -m ai.llm_analyzer

```

*(Note: Ensure your `.env` file is configured first).*

## Integration with Orchestrator

The orchestrator calls this module inside the `ScanWorker` loop right before emitting the final result:

```python
from ai.llm_analyzer import LLMAnalyzer

ai_analyzer = LLMAnalyzer()
ai_text = ai_analyzer.analyze(scan_data_dictionary)

```

The resulting string is placed under the `"ai_explanation"` key in the orchestrator's result dictionary, which the GUI reads to display in the AI Insights tab.

## ⚠️ API Key Setup (Required)

To enable the AI module, you must provide a free Gemini API key:

1. Create a file named exactly `.env` in the root `MalScope-Analyzer` directory.
2. Add the following line: `GEMINI_API_KEY=your_key_here`
3. **DO NOT commit the `.env` file to GitHub.**
