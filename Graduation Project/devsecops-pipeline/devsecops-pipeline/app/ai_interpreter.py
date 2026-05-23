import httpx
import json
import os
from dotenv import load_dotenv

load_dotenv()

def interpret_findings(bandit_result: dict, pip_audit_result: dict, code_snippet: str = "") -> dict:
    prompt = f"""You are a senior security engineer. Analyze these findings and respond ONLY with valid JSON.

SAST findings (Bandit): {json.dumps(bandit_result, indent=2)}
Dependency vulnerabilities (pip-audit): {json.dumps(pip_audit_result, indent=2)}
Code snippet: {code_snippet[:2000] if code_snippet else "Not provided"}

Respond ONLY with this JSON structure, no extra text:
{{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "2-3 sentence overall assessment",
  "findings": [
    {{
      "issue": "issue name",
      "severity": "HIGH|MEDIUM|LOW",
      "explanation": "why this is dangerous",
      "fix": "concrete fix suggestion"
    }}
  ],
  "deploy_recommendation": "BLOCK|APPROVE",
  "developer_message": "friendly message to developer"
}}"""

    try:
        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            },
            timeout=30
        )
        text = response.json()["choices"][0]["message"]["content"].strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        return {
            "risk_level": "UNKNOWN",
            "summary": f"AI analysis failed: {str(e)}",
            "findings": [],
            "deploy_recommendation": "BLOCK",
            "developer_message": "Manual review required."
        }