from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import hmac, hashlib, json, os, base64
from dotenv import load_dotenv
from app.analyzer import run_bandit, run_pip_audit, run_flake8, run_gitleaks, run_semgrep
from app.ai_interpreter import interpret_findings
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

app = FastAPI(title="DevSecOps Pipeline")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///pipeline.db")
engine = create_engine(DATABASE_URL)
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    repo = Column(String)
    commit = Column(String)
    pusher = Column(String)
    risk_level = Column(String)
    summary = Column(Text)
    findings = Column(Text)
    deploy_recommendation = Column(String)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def verify_signature(payload: bytes, signature: str) -> bool:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "devsecops123").encode()
    expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

async def trigger_render_deploy():
    hook_url = os.getenv("RENDER_DEPLOY_HOOK")
    if not hook_url:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.get(hook_url)
    except Exception as e:
        print(f"Deploy hook error (non-fatal): {e}")

async def trigger_rollback_deploy():
    """Render API üzerinden önceki deploy'u yeniden tetikler."""
    api_key = os.getenv("RENDER_API_KEY")
    service_id = os.getenv("RENDER_SERVICE_ID", "srv-d88qms0jo6nc73d7ctkg")
    if not api_key:
        print("RENDER_API_KEY not found, falling back to deploy hook")
        await trigger_render_deploy()
        return
    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"https://api.render.com/v1/services/{service_id}/deploys"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, headers=headers, json={"clearCache": "do_not_clear"})
            print(f"Rollback deploy triggered: {r.status_code}")
    except Exception as e:
        print(f"Rollback deploy error (non-fatal): {e}")


def send_critical_alert_email(repo: str, commit: str, risk_level: str, findings: list):
    gmail_user = os.getenv("GMAIL_USER")
    gmail_password = os.getenv("GMAIL_APP_PASSWORD")
    if not gmail_user or not gmail_password:
        return
    findings_text = "\n".join([f"- {f.get('issue', '')}: {f.get('explanation', '')}" for f in findings[:5]])
    body = f"""⚠️ CRITICAL Security Alert - DevSecOps Pipeline

Repo: {repo}
Commit: {commit}
Risk Level: {risk_level}

Findings:
{findings_text}

→ Review on Dashboard: https://devsecops-dashboard-zcbu.onrender.com
"""
    msg = MIMEMultipart()
    msg["From"] = gmail_user
    msg["To"] = 210504003@st.atlas.edu.tr
    msg["Subject"] = f"🔴 CRITICAL Alert: {repo} - {commit[:7]}"
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_user, gmail_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Email error: {e}")
async def post_github_pr_comment(repo: str, pr_number: int, body: str):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(url, json={"body": body}, headers=headers)

async def fetch_file_content(repo: str, commit: str, filename: str) -> str:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        return ""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/repos/{repo}/contents/{filename}?ref={commit}"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                content = r.json().get("content", "")
                return base64.b64decode(content).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"File fetch error: {e}")
    return ""

async def run_analysis(payload: dict, event: str):
    repo = payload.get("repository", {}).get("full_name", "unknown")
    commit = payload.get("after", "unknown")
    pusher = payload.get("pusher", {}).get("name", "unknown")

    code_sample = payload.get("code", "")
    requirements = payload.get("requirements", "")

    if not code_sample:
        commits = payload.get("commits", [])
        code_sample = f"# Repo: {repo}\n# Commit: {commit[:7]}\n# Pusher: {pusher}\n"
        if commits and os.getenv("GITHUB_TOKEN"):
            changed_files = commits[0].get("added", []) + commits[0].get("modified", [])
            py_files = [f for f in changed_files if f.endswith(".py")][:3]
            for filename in py_files:
                content = await fetch_file_content(repo, commit, filename)
                if content:
                    code_sample += f"\n# File: {filename}\n{content}\n"
            if not py_files:
                code_sample += f"# Changed files: {', '.join(changed_files[:5])}\n"

    commit = commit[:7]

    bandit = run_bandit(code_sample)
    pip_audit = run_pip_audit(requirements if requirements else "")
    flake8 = run_flake8(code_sample)
    gitleaks = run_gitleaks(code_sample)
    semgrep = run_semgrep(code_sample)
    ai_result = interpret_findings(bandit, pip_audit, code_sample, flake8, gitleaks, semgrep)

    risk_level = ai_result.get("risk_level", "UNKNOWN")
    deploy_recommendation = ai_result.get("deploy_recommendation", "BLOCK")

    if risk_level in ["LOW", "MEDIUM"] and deploy_recommendation == "APPROVE":
        status = "auto_approved"
        await trigger_render_deploy()
    else:
        status = "pending"
        send_critical_alert_email(repo, commit, risk_level, ai_result.get("findings", []))

    session = Session()
    scan = ScanResult(
        repo=repo,
        commit=commit,
        pusher=pusher,
        risk_level=risk_level,
        summary=ai_result.get("summary", ""),
        findings=json.dumps(ai_result.get("findings", [])),
        deploy_recommendation=deploy_recommendation,
        status=status
    )
    session.add(scan)
    session.commit()
    scan_id = scan.id
    session.close()

    if event == "pull_request":
        pr_number = payload.get("number")
        if pr_number:
            recommendation = ai_result.get("deploy_recommendation", "BLOCK")
            emoji = "✅" if recommendation == "APPROVE" else "🚨"
            comment = f"""## {emoji} AI-Powered DevSecOps Analysis

**Risk Level:** `{risk_level}`
**Recommendation:** `{recommendation}`
**Auto Deploy:** `{"YES" if status == "auto_approved" else "NO - Manual approval required"}`

**Summary:** {ai_result.get("summary", "")}

---
*Powered by AI DevSecOps Pipeline 🛡️*"""
            await post_github_pr_comment(repo, pr_number, comment)

@app.get("/")
def root():
    return {"status": "DevSecOps Pipeline running"}

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    payload_bytes = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if signature and not verify_signature(payload_bytes, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(payload_bytes)
    except:
        payload = await request.json()
    event = request.headers.get("X-GitHub-Event", "push")

    if event not in ["push", "pull_request"]:
        return {"message": "Event ignored"}

    background_tasks.add_task(run_analysis, payload, event)
    return {"message": "Webhook received, analysis started"}

@app.get("/scans")
def get_scans():
    session = Session()
    scans = session.query(ScanResult).order_by(ScanResult.created_at.desc()).all()
    result = []
    for s in scans:
        result.append({
            "id": s.id, "repo": s.repo, "commit": s.commit,
            "pusher": s.pusher, "risk_level": s.risk_level,
            "summary": s.summary, "findings": json.loads(s.findings or "[]"),
            "deploy_recommendation": s.deploy_recommendation,
            "status": s.status, "created_at": str(s.created_at)
        })
    session.close()
    return result

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    session = Session()
    scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    session.close()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id, "repo": scan.repo, "commit": scan.commit,
        "pusher": scan.pusher, "risk_level": scan.risk_level,
        "summary": scan.summary, "findings": json.loads(scan.findings or "[]"),
        "deploy_recommendation": scan.deploy_recommendation,
        "status": scan.status, "created_at": str(scan.created_at)
    }

@app.post("/scans/{scan_id}/approve")
async def approve_scan(scan_id: int):
    session = Session()
    scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "approved"
    session.commit()
    session.close()
    await trigger_render_deploy()
    return {"message": "Deployment approved and triggered", "scan_id": scan_id}

@app.post("/scans/{scan_id}/reject")
def reject_scan(scan_id: int):
    session = Session()
    scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "rejected"
    session.commit()
    session.close()
    return {"message": "Deployment rejected", "scan_id": scan_id}

@app.post("/scans/{scan_id}/rollback")
async def rollback_scan(scan_id: int):
    session = Session()

    # Mevcut scan'i bul
    current_scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not current_scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    # Bu scan'den önceki son temiz scan'i bul
    previous_safe = session.query(ScanResult).filter(
        ScanResult.id < scan_id,
        ScanResult.status.in_(["approved", "auto_approved"])
    ).order_by(ScanResult.id.desc()).first()

    if not previous_safe:
        session.close()
        raise HTTPException(status_code=404, detail="No previous safe deployment found to roll back to")

    # Mevcut scan'i rolled_back olarak işaretle
    current_scan.status = "rolled_back"
    rollback_commit = previous_safe.commit
    session.commit()
    session.close()

    # Render'da yeniden deploy tetikle
    await trigger_rollback_deploy()

    return {
        "message": f"Rollback triggered successfully",
        "rolled_back_from_commit": current_scan.commit,
        "rolled_back_to_commit": rollback_commit
    }