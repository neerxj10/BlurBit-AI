# BlurBit AI - Agentic Honeypot (FastAPI)

BlurBit AI is a FastAPI-based honeypot system that engages scammers, extracts intelligence, scores risk, and provides real-time dashboard/chat monitoring with Telegram alerting.

## Features
- `POST /honeypot` scam conversation handler (hackathon-compatible response shape)
- Entity extraction: phone, bank account, UPI, email, phishing links, case/policy/order IDs
- Risk scoring (`/analyze`) with scam probability and risk level
- Playwright URL sandbox scan + screenshots
- Callback submission to evaluator endpoint
- Telegram webhook bot with invite/access-request admin flow
- Authenticated dashboard + live chat console + WebSocket live updates

## Tech Stack
- Python 3.11+
- FastAPI + Jinja2
- SQLite
- Playwright (Chromium)
- OpenAI / Ollama (LLM response generation)

## Project Structure
```text
.
├── main.py
├── scoring_engine.py
├── database.py
├── requirements.txt
├── templates/
│   ├── auth.html
│   ├── dashboard.html
│   └── chat.html
├── static/
│   ├── auth.css
│   ├── login.js
│   ├── dashboard.css
│   ├── dashboard.js
│   ├── chat.css
│   ├── chat.js
│   ├── i18n.js
│   └── BlurBitLogo.png
├── evaluation/
│   └── sample_scenarios.json
└── sandbox_shots/
```

## Main Endpoints

### Auth + UI
- `GET /` (redirects to login/dashboard)
- `GET /signup`, `POST /signup`
- `GET /login`, `POST /login`
- `GET /logout`
- `GET /dashboard`
- `GET /chat`
- `GET /auth/google/login`
- `GET /auth/google/callback`

### Honeypot + Scoring
- `POST /honeypot` (supports `x-api-key`)
- `POST /analyze`
- `POST /honeypot/log` (background login intelligence logging)

### Dashboard APIs
- `GET /api/overview`
- `GET /api/sessions`
- `GET /api/sessions/{session_id}`
- `POST /api/test-telegram`
- `WS /ws/live`

### Telegram APIs
- `POST /telegram-webhook`
- `GET /api/telegram/invite-tokens`
- `POST /api/telegram/invite-token`
- `POST /api/telegram/invite-token/revoke`
- `GET /api/telegram/access-requests`
- `POST /api/telegram/access-request/approve`
- `POST /api/telegram/access-request/reject`

### Evaluation APIs
- `GET /api/evaluation/scenarios`
- `POST /api/evaluation/run` (requires `x-api-key`)

### Health / Debug
- `GET /health`
- `GET /debug/google`

## Hackathon Submission Endpoint
- **URL**: `https://<your-domain>/honeypot`
- **Method**: `POST`
- **Header**: `x-api-key: <HONEYPOT_API_KEY>` (if enabled)
- **Response shape**:
```json
{
  "status": "success",
  "reply": "..."
}
```

## `/honeypot` Sample Request
```json
{
  "sessionId": "uuid-or-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account is blocked. Share OTP now.",
    "timestamp": 1739269800000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

## Environment Variables (`.env`)
```env
# Core
HONEYPOT_API_KEY=your_api_key
OPENAI_API_KEY=your_openai_key
OLLAMA_URL=http://localhost:11434/api/generate
CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult

# Auth + DB
AUTH_SECRET=replace_with_long_random_secret
DB_PATH=users.db

# Google OAuth
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback

# Telegram
TELEGRAM_ALERTS_ENABLED=true
TELEGRAM_BOT_TOKEN=
TELEGRAM_BOT_USERNAME=BlurBitAI_bot
TELEGRAM_ACCESS_KEY=
TELEGRAM_ADMIN_EMAILS=
TELEGRAM_USERS_FILE=users.json
TELEGRAM_INVITE_TOKENS_FILE=telegram_invite_tokens.json
TELEGRAM_ACCESS_REQUESTS_FILE=telegram_access_requests.json
TELEGRAM_UPDATE_DEDUPE_TTL_SECONDS=600

# Files / runtime
SCREENSHOT_DIR=sandbox_shots
EVALUATION_SCENARIOS_FILE=evaluation/sample_scenarios.json
HONEYPOT_LOG_FILE=honeypot_login_logs.jsonl
ASSET_VERSION=1

# Performance tuning
MAX_URL_SCAN_PER_MESSAGE=1
PLAYWRIGHT_GOTO_TIMEOUT_MS=8000
LINK_SCAN_TIMEOUT_SECONDS=10
HONEY_POT_STRICT_RESPONSE=true
OPENAI_CHAT_TIMEOUT_SECONDS=8
OLLAMA_CHAT_TIMEOUT_SECONDS=8
REPLY_TIMEOUT_SECONDS=9
```

## Local Run
```bash
cd "/Users/neerajkoushik/Documents/New project"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
uvicorn main:app --reload
```

Open:
- `http://127.0.0.1:8000/login`
- `http://127.0.0.1:8000/dashboard`
- `http://127.0.0.1:8000/chat`

## Render Deployment

### Build Command
```bash
pip install -r requirements.txt && python -m playwright install chromium
```

### Start Command
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Persistent Disk (recommended)
Use `/var/data` for file-backed runtime data on Render:
- `DB_PATH=/var/data/users.db`
- `SCREENSHOT_DIR=/var/data/sandbox_shots`
- `TELEGRAM_USERS_FILE=/var/data/users.json`
- `TELEGRAM_INVITE_TOKENS_FILE=/var/data/telegram_invite_tokens.json`
- `TELEGRAM_ACCESS_REQUESTS_FILE=/var/data/telegram_access_requests.json`
- `HONEYPOT_LOG_FILE=/var/data/honeypot_login_logs.jsonl`

## Telegram Webhook Setup
After deploy:
```text
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=https://<YOUR_DOMAIN>/telegram-webhook
```

Example:
```text
https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://blurbit-ai.onrender.com/telegram-webhook
```

## Troubleshooting

### Playwright link verdict = `ERROR` on Render
- Cause: Chromium not installed in build image
- Fix: ensure build command includes `python -m playwright install chromium`

### Google OAuth `401 invalid_client`
- Verify exact `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- Verify exact redirect URI in Google Cloud OAuth client
- Check via `GET /debug/google`

### Telegram not receiving alerts
- Verify `TELEGRAM_BOT_TOKEN`
- Verify webhook is set correctly
- Ensure recipient is authorized through invite/request flow

## Security Notes
- Never commit `.env` or secrets
- Rotate exposed bot/API keys immediately
- Keep `HONEYPOT_API_KEY` private
- Use a strong `AUTH_SECRET`
