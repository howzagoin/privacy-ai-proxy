import sys
import os

# Ensure pythonw.exe has valid stream targets
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import re
import math
import json
import uvicorn
from collections import Counter
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import httpx

# 1. Known RAW API Keys, Tokens & Hashes (Match anywhere with NO label or prefix)
RAW_PATTERNS = [
    # Private Key blocks
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # OpenAI & generic sk- keys
    (re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,})\b"), "[REDACTED_API_KEY]"),
    # Anthropic keys
    (re.compile(r"\b(sk-ant-[a-zA-Z0-9_\-]{20,})\b"), "[REDACTED_API_KEY]"),
    # Google AI / Gemini API keys
    (re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "[REDACTED_API_KEY]"),
    # GitHub Tokens (personal, app, oauth, refresh)
    (re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{36,})\b"), "[REDACTED_API_KEY]"),
    # AWS Access Keys
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_API_KEY]"),
    # Slack Tokens
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,})\b"), "[REDACTED_API_KEY]"),
    # Stripe API keys
    (re.compile(r"\b((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,})\b"), "[REDACTED_API_KEY]"),
    # HuggingFace Tokens
    (re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"), "[REDACTED_API_KEY]"),
    # JWT tokens
    (re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"), "[REDACTED_TOKEN]"),
    # Bearer tokens
    (re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{16,})\b"), "Bearer [REDACTED_TOKEN]"),
    # Raw 32, 40, or 64 character hex secrets (API secrets, HMAC keys, client secrets)
    (re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"), "[REDACTED_SECRET]"),
    # Emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"), "[REDACTED_EMAIL]"),
    # IPv4 addresses (excluding localhost 127.0.0.1)
    (re.compile(r"\b(?!127\.0\.0\.1)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"), "[REDACTED_IP]"),
    # Key-Value Passwords & Secrets (when explicit labels exist)
    (re.compile(r'(?i)\b(password|passwd|pwd|secret|client_secret|sec)\s*[:=]\s*(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\r\n,;]+))'), r"\1=[REDACTED_PASSWORD]"),
]

# 2. Raw Password Detector (Strict code-safe token boundaries, NO labels required)
CANDIDATE_TOKEN_REGEX = re.compile(r"\b[A-Za-z0-9!@#$%^&*+=~?_]{8,64}\b")

def is_raw_password(tok: str) -> bool:
    if len(tok) < 8 or len(tok) > 64:
        return False
    # Skip common code/web extensions and paths
    if any(tok.endswith(ext) for ext in ('.js', '.py', '.ts', '.html', '.css', '.json', '.xml', '.md', '.txt', '.log')):
        return False
    if '://' in tok or tok.startswith(('http', 'file', 'ftp', 'git@')):
        return False

    has_u = any(c.isupper() for c in tok)
    has_l = any(c.islower() for c in tok)
    has_d = any(c.isdigit() for c in tok)
    has_s = any(c in '!@#$%^&*+=~?' for c in tok)

    # 1. Complex raw password (letters + numbers + special symbols) e.g. SecretSauceSEC!99, xK9#mQ2$vL1, P@ssw0rd2026
    if (has_u or has_l) and has_d and has_s:
        return True

    # 2. Mixed-case word with special password symbols e.g. SecretSauce#9
    if has_u and has_l and has_s:
        return True

    return False

def redact_text(text: str) -> str:
    # Pass 1: Apply known raw API keys, IPs, emails, and labeled secrets
    for pattern, repl in RAW_PATTERNS:
        text = pattern.sub(repl, text)

    # Pass 2: Detect raw unlabelled passwords
    def filter_raw_token(match):
        tok = match.group(0)
        if tok.startswith('[REDACTED_'):
            return tok
        if is_raw_password(tok):
            return "[REDACTED_PASSWORD]"
        return tok

    text = CANDIDATE_TOKEN_REGEX.sub(filter_raw_token, text)
    return text

def sanitize_json(data):
    if isinstance(data, str):
        return redact_text(data)
    elif isinstance(data, dict):
        return {k: sanitize_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_json(elem) for elem in data]
    return data

app = FastAPI(title="Local Privacy AI Proxy", version="1.2.0")
client = httpx.AsyncClient(timeout=180.0)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "privacy_proxy", "version": "1.2.0", "raw_detection": "active"}

@app.post("/sanitize")
async def test_sanitize(request: Request):
    """Test endpoint to inspect how text or JSON gets sanitized without making cloud calls."""
    body = await request.body()
    try:
        data = json.loads(body.decode("utf-8"))
        return {"sanitized": sanitize_json(data)}
    except Exception:
        return {"sanitized": redact_text(body.decode("utf-8"))}

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_openai(path: str, request: Request):
    url = f"https://api.openai.com/v1/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length"]}

    body = await request.body()
    if body and request.headers.get("content-type", "").startswith("application/json"):
        try:
            data = json.loads(body.decode("utf-8"))
            sanitized = sanitize_json(data)
            body = json.dumps(sanitized).encode("utf-8")
            headers["content-length"] = str(len(body))
        except Exception:
            pass

    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
        params=request.query_params,
    )
    res = await client.send(req, stream=True)
    return StreamingResponse(
        res.aiter_bytes(),
        status_code=res.status_code,
        headers={k: v for k, v in res.headers.items() if k.lower() not in ["content-encoding", "content-length", "transfer-encoding"]},
        media_type=res.headers.get("content-type"),
    )

@app.api_route("/v1beta/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_gemini(path: str, request: Request):
    url = f"https://generativelanguage.googleapis.com/v1beta/{path}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length"]}

    body = await request.body()
    if body and request.headers.get("content-type", "").startswith("application/json"):
        try:
            data = json.loads(body.decode("utf-8"))
            sanitized = sanitize_json(data)
            body = json.dumps(sanitized).encode("utf-8")
            headers["content-length"] = str(len(body))
        except Exception:
            pass

    req = client.build_request(
        method=request.method,
        url=url,
        headers=headers,
        content=body,
        params=request.query_params,
    )
    res = await client.send(req, stream=True)
    return StreamingResponse(
        res.aiter_bytes(),
        status_code=res.status_code,
        headers={k: v for k, v in res.headers.items() if k.lower() not in ["content-encoding", "content-length", "transfer-encoding"]},
        media_type=res.headers.get("content-type"),
    )

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8085, log_level="warning")
