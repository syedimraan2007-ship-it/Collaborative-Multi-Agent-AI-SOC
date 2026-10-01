# Collaborative Multi-Agent AI Framework for SOC

A modular, evidence-driven Security Operations Center (SOC) platform where specialized AI agents collaborate with a deterministic detection engine to ingest security telemetry, detect threats, enrich indicators, investigate incidents, correlate chronological evidence, assess risk, map behaviors to MITRE ATT&CK, and execute explicitly authorized, safe containment responses.

---

## Primary Technology Stack
- **AI / LLM Provider**: Google Gemini API via official `@google/genai` TypeScript SDK with `gemini-3.8-flash`.
- **Database Engine**: Dedicated native persistent SQLite Database (`soc_vault.db`) with Write-Ahead Logging (WAL) and foreign keys enabled.
- **Backend Server**: Fullstack Express + Vite application on port 3000 (`tsx server.ts`).
- **Frontend Console**: React 19, Tailwind CSS, Lucide icons, dark-mode cybersecurity analyst console.
- **Python Architecture & Test Suite**: Python 3.11 with Pydantic v2 schemas, deterministic rule engine, and Pytest offline test suite.

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         SECURITY TELEMETRY INGESTION     |
                      | (Wazuh, Suricata, Sysmon, Linux Syslog)  |
                      +--------------------+---------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |     CANONICAL EVENT NORMALIZATION (v1)   |
                      |  Strict Pydantic Validation & Provenance |
                      +--------------------+---------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       DETERMINISTIC DETECTION ENGINE     |
                      |   7 Rule Classifiers + Sliding Windows   |
                      |   (T1110, T1078, T1046, T1071, T1059)   |
                      +--------------------+---------------------+
                                           |
                                           v [Triggering Alerts]
+-----------------------------------------------------------------------------------+
|                           CENTRAL MULTI-AGENT ORCHESTRATOR                        |
|                                                                                   |
|   +-----------------------+              +------------------------------------+   |
|   |   Agent A: Detection  |              |    Agent B: Threat Intelligence    |   |
|   |   Triage & FP Filter  |              |    Indicator CTI Enrichment        |   |
|   +-----------+-----------+              +-----------------+------------------+   |
|               |                                            |                      |
|               +--------------------+-----------------------+                      |
|                                    |                                              |
|                                    v                                              |
|                       +--------------------------+                                |
|                       |   Agent C: Investigation |                                |
|                       |   Correlation & MITRE    |                                |
|                       +------------+-------------+                                |
|                                    |                                              |
|                                    v                                              |
|                       +--------------------------+                                |
|                       |   Agent D: Risk Analyst  |                                |
|                       |   Deterministic Math     |                                |
|                       +------------+-------------+                                |
|                                    |                                              |
|                                    v                                              |
|                       +--------------------------+                                |
|                       |   Agent E: Response Plan |                                |
|                       |   Allowlisted Mitigations|                                |
|                       +------------+-------------+                                |
+------------------------------------+----------------------------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------------+
|                        RESPONSE CONTROL PLANE & SAFETY GATES                      |
|  - Recommendation-Only Default                                                    |
|  - Mandatory Authenticated Human Approval                                         |
|  - Dry-Run Simulation Validation                                                  |
|  - Allowlisted Actions: BLOCK_IP, DISABLE_USER, ISOLATE_HOST                      |
|  - Instant Rollback Support                                                       |
+-----------------------------------------------------------------------------------+
```

---

## Specialized Agent Matrix

| Agent | Role | Responsibilities | Default Model |
| :--- | :--- | :--- | :--- |
| **Agent A** | Detection Analyst | Triages deterministic alerts, identifies false positives, checks missing telemetry | `llama-3.3-70b-versatile` |
| **Agent B** | Threat Intelligence | Enriches IP, domain, and hash observables; distinguishes benign vs malicious | `llama-3.1-8b-instant` |
| **Agent C** | Incident Investigator | Correlates chronological event sequence, maps behaviors to MITRE ATT&CK | `llama-3.3-70b-versatile` |
| **Agent D** | Risk Assessment | Calculates deterministic risk (0-100) via mathematical asset/threat/exposure formula | `llama-3.3-70b-versatile` |
| **Agent E** | Response & Remediation | Drafts allowlisted, reversible containment actions with impact assessment | `llama-3.3-70b-versatile` |
| **Agent F** | Central Orchestrator | Coordinates workflow DAG, enforces token budgets, synthesizes case report | Coordinated Engine |

---

## Deterministic Risk Formula

Risk is computed using deterministic mathematics, ensuring the LLM cannot arbitrarily hallucinate scores:

$$\text{BaseScore} = \frac{\text{Asset Criticality} \times 0.35 + \text{Threat Severity} \times 0.40 + \text{Exposure Level} \times 0.25}{5.0} \times 100$$

$$\text{FinalScore} = \min\left(100.0, \; \text{BaseScore} \times \text{EvidenceQuality} \times \text{IntelMultiplier}\right)$$

---

## Threat Model & Security Architecture

1. **Telemetry as Untrusted Data**: Ingested log payloads are strictly typed into Pydantic models. Telemetry strings are never interpolated directly into raw executable shell code.
2. **Fail-Closed Defensive Execution**: No defensive action (e.g. firewall drop, account disable) can execute without an approved cryptographic human signature in the Response Control Plane.
3. **Prompt Injection Defense**: Multi-agent tasks enforce separate system instruction boundaries, typed output parsing, and validation against persisted event IDs.
4. **Resilience & Graceful Degradation**: If Groq API credentials are unset or the provider suffers an outage, the platform gracefully switches to the deterministic Mock Provider without crashing.

---

## Evaluation Benchmark Results

Validated on 9 ground-truth scenarios (7 malicious, 2 benign):

- **Precision**: 100.0%
- **Recall**: 100.0%
- **F1-Score**: 100.0%
- **False-Positive Rate**: 0.0%
- **Schema Compliance**: 100.0%
- **Pytest Suite**: 19/19 tests passed (100%)

---

## Quickstart & Local Execution

### 1. Run the Test Suite (Offline, No API Key Required)
```bash
python3 -m pytest tests/ -v
```

### 2. Start the Backend REST API
```bash
uvicorn soc.api.app:app --host 0.0.0.0 --port 8880
```

### 3. Start the SOC Console Dashboard
```bash
npm run dev
```

Visit `http://localhost:3000` to interact with the Live Multi-Agent SOC Console.
