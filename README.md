# Local AI Privacy Proxy & Secrets Sanitization Gateway

A high-performance, local reverse proxy that transparently intercepts, inspects, and scrubs sensitive personal identifiable information (PII), credentials, API keys, private keys, and high-entropy passwords from prompt payloads before they reach cloud Large Language Models (OpenAI, Google Gemini, Anthropic).

---

## Key Features

- **Zero-Cloud PII Scrubbing**: All regex and heuristic redaction executes 100% locally on your machine with near-zero latency.
- **Deep JSON Payload Traversal**: Recursively scans nested dictionaries and lists in JSON message bodies and tool call arguments.
- **Multi-Pass Sanitization Engine**:
  - **Raw API Key & Token Detection**: Scans for OpenAI (`sk-`), Anthropic (`sk-ant-`), Gemini (`AIza...`), GitHub (`ghp_`, `gho_`), AWS (`AKIA...`), Slack (`xox...`), Stripe (`sk_live_`, `sk_test_`), HuggingFace (`hf_`), JWTs, Bearer tokens, and raw hex hashes.
  - **PII Scrubbing**: Automatically detects and replaces email addresses (`[REDACTED_EMAIL]`) and IPv4 addresses (`[REDACTED_IP]`).
  - **Labeled Password Redaction**: Matches common password assignments (`password=...`, `secret: ...`, `pwd: ...`).
  - **Unlabeled Password / Entropy Heuristic**: Catches unlabelled raw passwords (8–64 character tokens combining uppercase, lowercase, numbers, and special symbols) while whitelisting file paths, URLs, and code extensions (`.py`, `.js`, `.json`, etc.).
  - **Private Key Shielding**: Redacts complete PEM private key blocks.
- **Full Streaming Reverse Proxy**: Proxies requests to upstream endpoints (`/v1/...` for OpenAI, `/v1beta/...` for Gemini) while maintaining real-time response streaming.
- **Offline Inspection Endpoint**: Includes `/sanitize` for testing and previewing redactions without dispatching calls to cloud LLMs.

---

## Architecture

```
                  +--------------------------------------------+
                  |         Local Machine (127.0.0.1)           |
+-------------+   |   +-------------------+                    |   +-----------------------+
|  AI Client  |   |   |   Privacy Proxy   |  Regex & Entropy   |   |  Remote Cloud LLM     |
|  (Codex /   | ----> | (FastAPI / Uvicorn| =================> | ----> (OpenAI / Gemini /   |
| Antigravity)|   |   |    Port 8085)     |  Sanitization      |   |      Anthropic)       |
+-------------+   |   +-------------------+                    |   +-----------------------+
                  +--------------------------------------------+
```

---

## Installation

### Prerequisites
- Python 3.10+
- `pip`

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Run in Foreground
```bash
python privacy_proxy.py
```
By default, the server listens on `http://127.0.0.1:8085`.

### 2. Run in Background on Windows (Startup)
Place `PrivacyAIProxy.vbs` in your Windows Startup directory:
```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
```
Or launch it silently in the background:
```cmd
wscript PrivacyAIProxy.vbs
```

---

## API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/health` | `GET` | Health check verifying proxy status and detection engine state. |
| `/sanitize` | `POST` | Test endpoint to test text or JSON sanitization offline. |
| `/v1/{path}` | `ALL` | Proxies and sanitizes requests destined for OpenAI API endpoints. |
| `/v1beta/{path}` | `ALL` | Proxies and sanitizes requests destined for Google Gemini API endpoints. |

### Testing Sanitization
```bash
curl -X POST http://127.0.0.1:8085/sanitize \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Connect to admin@company.com with password SecretSauceSEC!99 at 10.0.0.1"}'
```

**Response:**
```json
{
  "sanitized": {
    "prompt": "Connect to [REDACTED_EMAIL] with password=[REDACTED_PASSWORD] at [REDACTED_IP]"
  }
}
```

---

## License
MIT License
