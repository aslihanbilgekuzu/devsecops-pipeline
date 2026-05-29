import streamlit as st
import httpx
import json

API_URL = "https://devsecops-pipeline-kzos.onrender.com"

st.set_page_config(page_title="DevSecOps Pipeline", page_icon="🛡️", layout="wide")

st.title("🛡️ DevSecOps Pipeline Dashboard")
st.markdown("AI-Powered Security Analysis for GitHub Workflows")

def get_scans():
    try:
        r = httpx.get(f"{API_URL}/scans", timeout=10)
        return r.json()
    except:
        return []

def approve(scan_id):
    httpx.post(f"{API_URL}/scans/{scan_id}/approve", timeout=10)

def reject(scan_id):
    httpx.post(f"{API_URL}/scans/{scan_id}/reject", timeout=10)


# Sidebar
st.sidebar.header("📊 Pipeline Status")
scans = get_scans()
total = len(scans)
critical = sum(1 for s in scans if s["risk_level"] == "CRITICAL")
approved = sum(1 for s in scans if s["status"] in ["approved", "auto_approved"])

st.sidebar.metric("Total Scans", total)
st.sidebar.metric("Critical Issues", critical)
st.sidebar.metric("Approved Deploys", approved)

if st.sidebar.button("🔄 Refresh"):
    st.rerun()

# Manual test scan
st.header("🧪 Manual Scan Test")
with st.expander("Test a code snippet"):
    test_code = st.text_area("Paste Python code here:", height=150, value="""import os
password = 'admin123'
os.system('ls ' + password)""")
    test_req = st.text_area("requirements.txt (optional):", height=80)
    
    if st.button("🔍 Run Scan"):
        with st.spinner("Analyzing..."):
            try:
                payload = {
                    "repository": {"full_name": "manual/test"},
                    "after": "abc1234",
                    "pusher": {"name": "dashboard-user"},
                    "commits": [{"added": ["test.py"], "modified": []}],
                    "code": test_code,
                    "requirements": test_req
                }
                r = httpx.post(
                    f"{API_URL}/webhook",
                    json=payload,
                    headers={"Content-Type": "application/json", "X-GitHub-Event": "push"},
                    timeout=60
                )
                if r.status_code != 200:
                    st.error(f"Server error: {r.status_code} - {r.text}")
                else:
                    result = r.json()
                
                risk = result.get("risk_level", "UNKNOWN")
                color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
                st.success(f"{color} Risk Level: **{risk}**")
                st.info(result.get("summary", ""))
                st.write(f"**Deploy Recommendation:** {result.get('deploy_recommendation')}")
            except Exception as e:
                st.error(f"Error: {e}")

# Scan history
st.header("📋 Scan History")

if not scans:
    st.info("No scans yet. Push code to GitHub or use the manual test above.")
else:
    for scan in scans:
        risk = scan["risk_level"]
        color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
        status_icon = {
            "approved": "✅",
            "auto_approved": "🚀",
            "rejected": "❌",
            "pending": "⏳",
            "analyzed": "🔍",
            "rolled_back": "↩️"
        }.get(scan["status"], "❓")
        
        with st.expander(f"{color} {scan['repo']} — commit `{scan['commit']}` {status_icon} {scan['created_at'][:16]}"):
            col1, col2, col3 = st.columns(3)
            col1.metric("Risk Level", risk)
            col2.metric("Deploy", scan["deploy_recommendation"])
            col3.metric("Status", scan["status"].upper())
            
            st.markdown(f"**Summary:** {scan['summary']}")
            
            findings = scan.get("findings", [])
            if findings:
                st.markdown("**Findings:**")
                for f in findings:
                    sev_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(f.get("severity"), "⚪")
                    st.markdown(f"- {sev_color} **{f.get('issue')}**: {f.get('explanation')}")
                    st.markdown(f"  💡 *Fix: {f.get('fix')}*")

            # Karar bekleyen taramalar — Approve / Reject
            if scan["status"] in ["analyzed", "pending"]:
                col_a, col_r = st.columns(2)
                if col_a.button("✅ Approve Deploy", key=f"approve_{scan['id']}"):
                    approve(scan["id"])
                    st.success("Approved!")
                    st.rerun()
                if col_r.button("❌ Reject Deploy", key=f"reject_{scan['id']}"):
                    reject(scan["id"])
                    st.error("Rejected!")
                    st.rerun()

