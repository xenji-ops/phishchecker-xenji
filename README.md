# ⬡ URL Verdict

**Is that link safe?** URL Verdict checks any URL for phishing, scams, and fraud using AI + real community reports — for free.

🔗 **Live → [urlverdict.vercel.app](https://urlverdict.vercel.app)**

![URL Verdict Screenshot](https://urlverdict.vercel.app/static/og-image.png)

---

## How It Works

URL Verdict runs every URL through **three layers of analysis**:

| Layer | What it does |
|-------|-------------|
| **1. Pattern Scan** | Instant heuristic checks — IP addresses, `@` symbols, encoded tricks, entropy analysis |
| **2. Community Hunt** | Searches Reddit & Trustpilot for real victim reports, fraud warnings, and reviews |
| **3. AI Verdict** | An AI model reads the evidence and writes a plain-English verdict anyone can understand |

You get one of three verdicts: ✅ **Safe**, ⚠️ **Suspicious**, or 🚫 **Phishy**.

---

## Tech Stack

- **Backend** — Python, FastAPI
- **AI** — Google Gemini 2.5 Flash
- **OSINT** — Tavily Search API (Reddit + Trustpilot)
- **Frontend** — Vanilla HTML/CSS/JS, no frameworks
- **Design** — Dark theme, glassmorphism, matrix animations

---

## Self-Hosting

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/phishchecker-xenji.git
cd phishchecker-xenji

# Install deps
pip install -r requirements.txt

# Set your API keys
cp .env.example .env
# Edit .env with your TAVILY_API_KEY and GEMINI_API_KEY

# Run
uvicorn app:app --reload
```

### Get API Keys
- **Tavily** — [tavily.com](https://tavily.com) (free tier available)
- **Gemini** — [aistudio.google.com](https://aistudio.google.com) (free tier available)

---

## Privacy

- We **never log or store** any URL you submit
- No cookies, no tracking, no accounts
- All processing happens in real-time and is discarded

---

## Disclaimer

URL Verdict is an independent tool and is **not affiliated with** any platform, search engine, AI provider, or review service. All verdicts are AI-generated from publicly available information and may be incomplete or incorrect. Use results as a starting point — always use your own judgement.

---

## License

[MIT](LICENSE)

---

Made with ❤️ by [xenji ops](https://instagram.com/xenji.ops)

If this helped you, consider [buying me a coffee ☕](https://buymeacoffee.com/xenjiops)
