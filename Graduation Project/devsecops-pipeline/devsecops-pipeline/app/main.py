from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import hmac, hashlib, json, os, asyncio
from dotenv import load_dotenv
from app.analyzer import run_bandit, run_pip_audit
from app.ai_interpreter import interpret_findings
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

load_dotenv()

app = FastAPI(title="DevSecOps Pipeline")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Database setup
engine = create_engine("sqlite:///pipeline.db")
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

@app.get("/")
def root():
    return {"status": "DevSecOps Pipeline running"}

@app.post("/webhook")
async def webhook(request: Request):
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

    repo = payload.get("repository", {}).get("full_name", "unknown")
    commit = payload.get("after", "unknown")[:7]
    pusher = payload.get("pusher", {}).get("name", "unknown")
    
    # Get code from payload
    code_sample = payload.get("code", "")
    requirements = payload.get("requirements", "")
    
    if not code_sample:
        commits = payload.get("commits", [])
        code_sample = f"# Repo: {repo}\n# Commit: {commit}\n# Pusher: {pusher}\n"
        if commits:
            added = commits[0].get("added", []) + commits[0].get("modified", [])
            code_sample += f"# Changed files: {', '.join(added[:5])}\n"

    # Run analysis
    bandit = run_bandit(code_sample)
    pip_audit = run_pip_audit(requirements if requirements else "")
    ai_result = interpret_findings(bandit, pip_audit, code_sample)

    # Save to DB
    session = Session()
    scan = ScanResult(
        repo=repo,
        commit=commit,
        pusher=pusher,
        risk_level=ai_result.get("risk_level", "UNKNOWN"),
        summary=ai_result.get("summary", ""),
        findings=json.dumps(ai_result.get("findings", [])),
        deploy_recommendation=ai_result.get("deploy_recommendation", "BLOCK"),
        status="analyzed"
    )
    session.add(scan)
    session.commit()
    scan_id = scan.id
    session.close()

    return {
        "scan_id": scan_id,
        "repo": repo,
        "commit": commit,
        "risk_level": ai_result.get("risk_level"),
        "deploy_recommendation": ai_result.get("deploy_recommendation"),
        "summary": ai_result.get("summary")
    }

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
def approve_scan(scan_id: int):
    session = Session()
    scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        session.close()
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "approved"
    session.commit()
    session.close()
    return {"message": "Deployment approved", "scan_id": scan_id}

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