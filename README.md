# 🛰️ Safe OSINT AI Command Center

**An educational, defensive Open-Source Intelligence (OSINT) dashboard with a 3D interface, AI analyst summaries, and a safe reconnaissance toolkit.**

Built with **Python (FastAPI)** on the backend and a **Three.js** 3D frontend.
Created as a portfolio project to demonstrate practical skills in Python, web development, DNS/network protocols, and defensive security analysis.

> ⚠️ **Ethical use only.** This tool is for education, self-audits, and authorized security assessments. Only query domains and usernames that you own or have explicit written permission to investigate. The author is not responsible for misuse.

---

## ✨ Features

- 🌐 **3D animated dashboard** (Three.js) — responsive on desktop & mobile
- 🧬 **DNS intelligence** — A / AAAA / MX / NS / TXT / SOA / CNAME lookups
- 📜 **WHOIS / RDAP** — registration data with automatic fallback
- 🌲 **Subdomain discovery** — passive Certificate Transparency (crt.sh)
- 🛡️ **Security inspection** — TLS expiry, security headers, tech-stack fingerprinting, A–F grade
- 📧 **Email infrastructure OSINT** — SPF / DMARC / DKIM / MX analysis & grade
- 🔌 **Passive port probe** — common services (requires authorization)
- 🧪 **Safe vulnerability assessment** — config & disclosure findings + CVE intelligence (requires authorization)
- 🔍 **Username footprint** — 46 automated platform checks + 14 manual social links (60 total) (requires authorization)
- 🧠 **AI analyst** — executive summaries via local Ollama (Llama3), with a built-in rule-based fallback
- 📥 **Case-file export** — download all findings as JSON

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn |
| Networking | httpx, dnspython, python-whois, ssl, socket |
| Frontend | HTML / CSS / JS + Three.js (3D) |
| Optional AI | Ollama (local Llama3) |

---

## 📦 Requirements

`requirements.txt`

```txt
fastapi
uvicorn[standard]
httpx
dnspython
python-whois
```

---

## 🚀 Quick Start (Windows / macOS / Linux)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/osint-bot.git
cd osint-bot

# 2. Create & activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python app.py
```

Open **http://127.0.0.1:8000** in your browser.

---

## 🐉 Kali Linux Installation

Kali ships with Python 3, but its system pip is *externally managed* — always use a virtual environment.

```bash
# 1. System dependencies
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv

# 2. Clone the repository
git clone https://github.com/YOUR_USERNAME/osint-bot.git
cd osint-bot

# 3. Virtual environment + install requirements
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. Run
python app.py
```

Open **http://127.0.0.1:8000**.

### Optional: local AI analyst on Kali

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama run llama3
```

Keep Ollama running in a **second terminal**. If Ollama isn't running, the app automatically falls back to its built-in Python analyst.

---

## 🖥️ How To Use

1. Enter a **domain** (e.g. `example.com`) or a **username**.
2. Click a module button.
3. Modules marked ⚠️ (**PORTS / FOOTPRINT / VULNSCAN**) require the **AUTHORIZED TARGET MODE** toggle at the top of the panel.
4. Click **🧠 AI ANALYST SUMMARY** for an executive report.
5. Click **📥 EXPORT CASE FILE** to download all findings as JSON.

| Module | Purpose | Auth |
|---|---|---|
| SCAN | DNS A-record resolution | No |
| NSLOOKUP | Extended DNS records | No |
| WHOIS | Registration data (RDAP + WHOIS) | No |
| SUBDOMAINS | Certificate Transparency discovery | No |
| INSPECT | TLS, headers, tech stack, grade | No |
| EMAIL | SPF / DMARC / DKIM / MX analysis | No |
| PORTS | Passive common-port probe | ✅ |
| FOOTPRINT | Username across 60 platforms | ✅ |
| VULNSCAN | Safe configuration assessment | ✅ |

---

## 🔐 Built-In Safety Guardrails

- ❌ Blocks doxxing / stalking / harassment queries
- ❌ Rejects private & internal hostnames (`.local`, `.lan`, `localhost`, …)
- ✅ Authorization toggle required for active modules
- ✅ Passive, read-only reconnaissance — no exploits, no attacks
- ✅ Username footprint framed for self-audit & brand protection

---

## ☁️ Free Hosting (Render)

1. Push this repository to GitHub.
2. On [render.com](https://render.com) → **New → Web Service** → select the repo.
3. Settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app:app --host 0.0.0.0 --port $PORT`
   - **Instance type:** Free
4. Deploy → you get a public `https://….onrender.com` URL.

> The free tier sleeps after inactivity; the first request may take ~30 seconds to wake up.

### Instant demo (no hosting)

```bash
ngrok http 8000
```

---

## 📁 Project Structure

```
osint-bot/
├── app.py            # Full backend + 3D frontend (single file)
├── requirements.txt  # Python dependencies
└── README.md         # This document
```

---

## 🧭 Roadmap

- [ ] PDF report generation
- [ ] Historical DNS tracking
- [ ] CVE database deep-lookup
- [ ] Multi-user case management

---

## 🤝 Contributing

Contributions, issues, and suggestions are welcome! This is an educational project — please keep all contributions defensive and lawful.

---

## 📜 License

MIT — free for education and research. See the ethical-use note above.

---

## 📬 Contact

**Your Name** — [p79241487@gmail.com]

*Built as a portfolio project to demonstrate Python, web, and defensive-security skills.*
