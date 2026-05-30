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

def run_flake8(code: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ["flake8", "--max-line-length=120", "--format=json", tmp_path],
            capture_output=True, text=True
        )
        issues = []
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                issues.append({
                    "line": parts[1].strip(),
                    "col": parts[2].strip(),
                    "message": ":".join(parts[3:]).strip()
                })
        return {"tool": "flake8", "issues": issues, "count": len(issues)}
    except Exception as e:
        return {"tool": "flake8", "issues": [], "error": str(e)}
    finally:
        os.unlink(tmp_path)


def run_gitleaks(code: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ["gitleaks", "detect", "--source", tmp_path, "--no-git", "-f", "json", "-r", "/dev/stdout"],
            capture_output=True, text=True
        )
        findings = json.loads(result.stdout) if result.stdout.strip() else []
        if isinstance(findings, dict):
            findings = [findings]
        return {"tool": "gitleaks", "secrets": findings, "count": len(findings)}
    except Exception as e:
        return {"tool": "gitleaks", "secrets": [], "error": str(e)}
    finally:
        os.unlink(tmp_path)
