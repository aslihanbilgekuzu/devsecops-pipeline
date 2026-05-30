# 🛡️ AI-Powered DevSecOps Pipeline

> Automated Security Analysis and Semantic Vulnerability Interpretation for GitHub Workflows  
> Istanbul Atlas University — Computer Engineering Graduation Project  
> **Aslıhan Bilge Kuzu** | Advisor: Mehmet Raşit Eskicioğlu

[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-green)](https://devsecops-pipeline-kzos.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)](https://fastapi.tiangolo.com)

---

## What is this?

A GitHub-integrated pipeline that automatically analyzes every code push for security vulnerabilities, interprets findings using AI, and blocks risky deployments until a human approves them.

```
Developer pushes code to GitHub
        ↓
Webhook triggers analysis (Bandit + pip-audit)
        ↓
AI (Llama 3.3 70B via Groq) interprets findings semantically
        ↓
LOW/MEDIUM risk  →  Auto-deploy ✅
CRITICAL/HIGH    →  Block + notify, wait for human approval 🔴
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    4-Layer Architecture                      │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  Data Input  │   Analysis   │  Management  │  Deployment    │
│  & Trigger   │ & Processing │  Dashboard   │  & Automation  │
│              │              │              │                │
│  GitHub      │  Bandit      │  Streamlit   │  Docker        │
│  Webhook  →  │  pip-audit → │  Dashboard → │  Render        │
│  FastAPI     │  Groq AI     │  PostgreSQL  │  Deploy Hook   │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

---

## Features

- **SAST** — Static code analysis with Bandit (SQL injection, XSS, command injection, hardcoded secrets)
- **SCA** — Dependency vulnerability scanning with pip-audit (CVE database)
- **AI Semantic Analysis** — Groq Llama 3.3 70B explains *why* a vulnerability is risky and *how* to fix it
- **Human-in-the-Loop** — Critical findings block deployment; manual approve/reject via dashboard
- **Auto Deploy** — Clean code is automatically deployed to Render via deploy hook
- **Persistent Storage** — All scan history stored in PostgreSQL
- **PR Comments** — Analysis results posted directly to GitHub Pull Requests
- **Fail-Safe** — If AI is unavailable, static analysis results are still displayed

---

## Tech Stack

| Category | Tool | Reason |
|---|---|---|
| Backend | FastAPI (Python) | Async webhook handling, auto Swagger docs |
| AI / LLM | Groq — Llama 3.3 70B | Fast inference, free tier, semantic code analysis |
| SAST | Bandit + Semgrep | Industry standard for Python security (OWASP) |
| SCA | pip-audit | CVE scanning against PyPI / Google secure package DB |
| Secret Detection | Gitleaks | Lowest false-positive rate for secret scanning |
| Dashboard | Streamlit | Rapid Python-based web UI |
| Database | PostgreSQL | Persistent scan history across deploys |
| Containerization | Docker | Environment consistency local ↔ cloud |
| CI/CD | GitHub Actions + Render | Free tier, native GitHub integration |

---

## Project Structure

```
devsecops-pipeline/
├── app/
│   ├── main.py            # FastAPI backend, webhook handler, deploy logic
│   ├── analyzer.py        # Bandit + pip-audit integration
│   └── ai_interpreter.py  # Groq LLM semantic analysis
├── dashboard/
│   └── streamlit_app.py   # Web dashboard (approve/reject, scan history)
├── Dockerfile
├── requirements.txt
└── .env                   # GITHUB_TOKEN, GROQ_API_KEY, RENDER_DEPLOY_HOOK, etc.
```

---

## How to Run Locally

**1. Clone and install:**
```bash
git clone https://github.com/aslihanbilgekuzu/devsecops-pipeline.git
cd devsecops-pipeline/devsecops-pipeline
pip install -r requirements.txt
```

**2. Set environment variables** (create `.env`):
```
GITHUB_WEBHOOK_SECRET=your_secret
GITHUB_TOKEN=your_github_token
GROQ_API_KEY=your_groq_key
RENDER_DEPLOY_HOOK=your_render_hook_url
DATABASE_URL=postgresql://user:password@host/dbname
```

**3. Start the backend:**
```bash
uvicorn app.main:app --reload
```

**4. Start the dashboard:**
```bash
streamlit run dashboard/streamlit_app.py
```

---

## Live Demo

| Service | URL |
|---|---|
| Backend API | https://devsecops-pipeline-kzos.onrender.com |
| API Docs | https://devsecops-pipeline-kzos.onrender.com/docs |
| Dashboard | https://devsecops-dashboard-zcbu.onrender.com |

### Demo Scenario

**Scenario 1 — Clean code:**
```bash
# Push safe Python code → system auto-approves and deploys
git push origin master
# Result: risk_level: LOW, status: auto_approved ✅
```

**Scenario 2 — Vulnerable code:**
```python
# vulnerable_test.py contains:
password = "admin123"                          # Hardcoded secret
query = "SELECT * FROM users WHERE id=" + id  # SQL Injection
os.system("ls " + user_input)                 # Command Injection
```
```bash
git push origin main
# Result: risk_level: CRITICAL, status: pending 🔴
# → Manual approval required via dashboard
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check |
| POST | `/webhook` | GitHub webhook receiver |
| GET | `/scans` | List all scan results |
| GET | `/scans/{id}` | Get specific scan |
| POST | `/scans/{id}/approve` | Approve deployment |
| POST | `/scans/{id}/reject` | Reject deployment |

---

## Risk Management

| Risk | Impact | Mitigation |
|---|---|---|
| LLM Hallucination | High | Strict JSON mode, static analysis as ground truth |
| API Rate Limits | Medium | Response caching, fallback to cheaper models |
| False Positives | High | AI filters Bandit output by checking actual data flow |
| Webhook Delays | Low | Async queue + retry mechanism |
| Secret Key Leak | Critical | Gitleaks scans project itself before push |

---

## Scope

**Included:** Python 3.x projects, SAST, SCA, secret detection, AI interpretation, human-in-the-loop deployment, GitHub webhook/PR integration.

**Excluded:** DAST (runtime analysis), auto-refactoring, mobile/embedded/desktop apps, enterprise security frameworks (CIS Benchmark, Zero Trust).

---

