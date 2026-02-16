# Agentic Honeypot AI

Production-ready FastAPI honeypot platform with:
- Live scam conversation handling
- Infrastructure-based scam probability scoring (0-100)
- Real-time dashboard + chat console
- Telegram webhook registration + alert broadcasting
- Google sign-in + local auth
- URL sandbox scanning with Playwright screenshots

## Tech Stack

- Python 3.11+
- FastAPI
- SQLite
- Playwright (Chromium)
- Jinja2 templates + static frontend
- Telegram Bot API

---

## Project Structure

```text
.
├── main.py                 # FastAPI app (API + auth + dashboard + chat + webhook)
├── scoring_engine.py       # Scam probability scoring engine
├── database.py             # Scam history DB and scoring context
├── requirements.txt
├── templates/
│   ├── auth.html
│   ├── dashboard.html
│   └── chat.html
├── static/
│   ├── dashboard.css
│   ├── dashboard.js
│   ├── chat.css
│   └── chat.js
└── sandbox_shots/          # URL screenshots (runtime)
```

---

## Features

### 1. Honeypot Conversation Engine
- Endpoint: `POST /honeypot`
- Extracts intel from scammer messages (UPI, phone, bank account, links)
- Generates natural replies (English/Hinglish handling)
- Scans URLs in sandbox and classifies phishing/suspicious

### 2. Scam Probability Engine (`/analyze`)
- Endpoint: `POST /analyze`
- Returns:
  - `scam_probability` (0-100)
  - `risk_level` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `reasons` (scoring evidence)
- Uses infrastructure correlation:
  - UPI clustering and provider patterns
  - Phone number batch proximity
  - Suspicious domain infrastructure
  - Repeat history from SQLite

### 3. Live Dashboard
- Route: `GET /dashboard`
- Real-time updates via WebSocket `GET /ws/live`
- Includes session table, risk levels, verdict metrics
- Circular probability gauge (0-100%)

### 4. Live Chat Console
- Route: `GET /chat`
- Simulates live scammer-to-honeypot conversation
- Session intel panel + exports + test Telegram alerts

### 5. Telegram Broadcast Alerts (Webhook-only)
- Endpoint: `POST /telegram-webhook`
- Any user sending `/start` to bot is auto-registered in `users.json`
- Alerts are broadcast to all registered users
- Screenshot sent once per session

### 6. Authentication
- Signup/login with local credentials
- Google OAuth sign-in

---

## Environment Variables

Create `.env` in project root:

```env
# Core
HONEYPOT_API_KEY=your_api_key
OPENAI_API_KEY=your_openai_key
OLLAMA_URL=http://localhost:11434/api/generate
CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult

# Auth
AUTH_SECRET=replace_with_long_random_secret

# Google OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/auth/google/callback

# Telegram
TELEGRAM_BOT_TOKEN=...
TELEGRAM_ALERTS_ENABLED=true
TELEGRAM_USERS_FILE=users.json

# Storage paths
DB_PATH=users.db
SCAM_DB_PATH=scam_history.db
SCREENSHOT_DIR=sandbox_shots
```

---

## Local Setup

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

---

## API Reference

### Health
```http
GET /health
```

### Honeypot Conversation
```http
POST /honeypot
Header: x-api-key: <HONEYPOT_API_KEY>
Content-Type: application/json

{
  "sessionId": "session-001",
  "message": {
    "sender": "scammer",
    "text": "Your account is blocked. Send OTP now",
    "timestamp": 1700000000
  },
  "conversationHistory": [],
  "metadata": {}
}
```

### Scam Analysis
```http
POST /analyze
Content-Type: application/json

{
  "message": "urgent transfer to refund01@paytm",
  "phone": "+919876543210",
  "upi": "refund01@paytm",
  "links": ["https://sbi-verify1.xyz"]
}
```

### Telegram Webhook
```http
POST /telegram-webhook
```

Telegram sends updates here automatically.

---

## Telegram Setup

1. Create bot with BotFather and get token.
2. Deploy app to a public URL.
3. Set webhook:

```text
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=https://<YOUR_DOMAIN>/telegram-webhook
```

4. Send `/start` to your bot from Telegram.
5. Your `chat_id` gets stored in `users.json`.
6. Alerts are broadcast to all registered users.

---

## Google OAuth Setup

In Google Cloud OAuth client:
- Authorized redirect URI:
  - Local: `http://127.0.0.1:8000/auth/google/callback`
  - Production: `https://<your-domain>/auth/google/callback`

Common error `invalid_client` means client ID/secret or redirect URI mismatch.

---

## Deploy on Render

### Build Command
```bash
pip install -r requirements.txt && python -m playwright install chromium
```

### Start Command
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Required Env Vars on Render
- `HONEYPOT_API_KEY`
- `OPENAI_API_KEY` (optional if fallback used)
- `AUTH_SECRET`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ALERTS_ENABLED=true`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI=https://<service>.onrender.com/auth/google/callback`

### Persistent Disk (recommended)
Set paths to mounted disk, e.g. `/var/data`:
- `DB_PATH=/var/data/users.db`
- `SCAM_DB_PATH=/var/data/scam_history.db`
- `TELEGRAM_USERS_FILE=/var/data/users.json`
- `SCREENSHOT_DIR=/var/data/sandbox_shots`

---

## Troubleshooting

### `No module named requests`
```bash
pip install -r requirements.txt
```

### Uvicorn reload loop
Avoid writing generated files inside watched source dirs, or run:
```bash
uvicorn main:app --reload --reload-exclude sandbox_shots
```

### Telegram alerts not coming
- Check `TELEGRAM_BOT_TOKEN`
- Confirm webhook is set to your live domain
- Ensure at least one user sent `/start`

### Google sign-in 401 / invalid_client
- Verify exact client ID + secret
- Verify exact redirect URI match in Google console

---

## Security Notes

- Never commit `.env`
- Rotate bot tokens and secrets if leaked
- Use strong `AUTH_SECRET`
- Restrict API keys in production
- Use HTTPS in production

---

## License

Use internally for demo/hackathon unless a project license is added.
