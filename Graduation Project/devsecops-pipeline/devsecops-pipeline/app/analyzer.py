import subprocess
import json
import tempfile
import os

def run_bandit(code: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ["bandit", "-r", tmp_path, "-f", "json", "-q"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout) if result.stdout else {}
        issues = data.get("results", [])
        return {"tool": "bandit", "issues": issues, "count": len(issues)}
    except Exception as e:
        return {"tool": "bandit", "issues": [], "error": str(e)}
    finally:
        os.unlink(tmp_path)

def run_pip_audit(requirements: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(requirements)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ["pip-audit", "-r", tmp_path, "-f", "json", "--progress-spinner=off"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout) if result.stdout else {}
        vulns = data.get("dependencies", [])
        vuln_list = [d for d in vulns if d.get("vulns")]
        return {"tool": "pip_audit", "vulnerable_packages": vuln_list, "count": len(vuln_list)}
    except Exception as e:
        return {"tool": "pip_audit", "vulnerable_packages": [], "error": str(e)}
    finally:
        os.unlink(tmp_path)