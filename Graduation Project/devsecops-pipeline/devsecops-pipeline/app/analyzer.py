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
    if not requirements or not requirements.strip():
        return {"tool": "pip_audit", "vulnerable_packages": [], "count": 0}
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
            # DÜZELTME: flake8'in JSON formatı yok, default format kullan
            ["flake8", "--max-line-length=120", tmp_path],
            capture_output=True, text=True
        )
        issues = []
        for line in result.stdout.splitlines():
            # Format: /path/file.py:LINE:COL: CODE message
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
    # DÜZELTME: gitleaks --source bir DIZIN bekliyor, tek dosya değil
    # Geçici bir dizin oluşturup dosyayı oraya koyuyoruz
    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "scan_target.py")
    report_path = os.path.join(tmp_dir, "gitleaks_report.json")
    try:
        with open(tmp_path, "w") as f:
            f.write(code)

        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", tmp_dir,
                "--no-git",
                "-f", "json",
                "-r", report_path
            ],
            capture_output=True, text=True
        )

        findings = []
        if os.path.exists(report_path):
            with open(report_path, "r") as rf:
                content = rf.read().strip()
                if content:
                    parsed = json.loads(content)
                    findings = parsed if isinstance(parsed, list) else [parsed]

        return {"tool": "gitleaks", "secrets": findings, "count": len(findings)}
    except Exception as e:
        return {"tool": "gitleaks", "secrets": [], "error": str(e)}
    finally:
        # Temizlik
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_semgrep(code: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ["semgrep", "--config=p/python", "--json", tmp_path],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout) if result.stdout else {}
        issues = data.get("results", [])
        simplified = [
            {
                "rule": i.get("check_id", ""),
                "message": i.get("extra", {}).get("message", ""),
                "severity": i.get("extra", {}).get("severity", "")
            }
            for i in issues
        ]
        return {"tool": "semgrep", "issues": simplified, "count": len(simplified)}
    except Exception as e:
        return {"tool": "semgrep", "issues": [], "error": str(e)}
    finally:
        os.unlink(tmp_path)