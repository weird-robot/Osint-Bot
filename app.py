from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
import dns.resolver
import httpx
import re
import whois
import ssl
import socket
import datetime
import concurrent.futures

app = FastAPI()

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "llama3"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

def is_safe_request(text):
    bad_words = ["dox", "doxx", "stalk", "harass", "swat", "location", "phone number", "address", "password"]
    return not any(word in text.lower() for word in bad_words)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
BLOCKED_SUFFIXES = (".local", ".internal", ".lan", ".home", ".arpa", ".localhost", ".test", ".example", ".invalid")

def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    return domain

def is_public_hostname(domain: str) -> bool:
    if not domain: return False
    if not DOMAIN_RE.match(domain): return False
    if any(domain.endswith(suffix) for suffix in BLOCKED_SUFFIXES): return False
    return True

def sanitize_username(username: str) -> str:
    username = username.strip().lower().lstrip('@')
    username = re.sub(r'[^a-z0-9_.\-]', '', username)
    return username

def txt_strings(rdata) -> str:
    return "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])

def extract_registrar_from_rdap(data: dict) -> str:
    entities = data.get("entities", [])
    for entity in entities:
        if "registrar" in entity.get("roles", []):
            vcard_array = entity.get("vcardArray")
            if isinstance(vcard_array, list) and len(vcard_array) > 1:
                for field in vcard_array[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn": return str(field[3])
            if entity.get("handle"): return str(entity.get("handle"))
    return ""

USERNAME_SITES = {
    "GitHub": {"url": "https://github.com/{u}"},
    "GitLab": {"url": "https://gitlab.com/{u}"},
    "BitBucket": {"url": "https://bitbucket.org/{u}/"},
    "Reddit": {"url": "https://www.reddit.com/user/{u}"},
    "Medium": {"url": "https://medium.com/@{u}"},
    "Twitch": {"url": "https://www.twitch.tv/{u}"},
    "SoundCloud": {"url": "https://soundcloud.com/{u}"},
    "Keybase": {"url": "https://keybase.io/{u}"},
    "ProductHunt": {"url": "https://www.producthunt.com/@{u}"},
    "NPM": {"url": "https://www.npmjs.com/~{u}"},
    "PyPI": {"url": "https://pypi.org/user/{u}/"},
    "CodePen": {"url": "https://codepen.io/{u}"},
    "About.me": {"url": "https://about.me/{u}"},
    "DeviantArt": {"url": "https://www.deviantart.com/{u}"},
    "Flickr": {"url": "https://www.flickr.com/people/{u}"},
    "Spotify": {"url": "https://open.spotify.com/user/{u}"},
    "Pinterest": {"url": "https://www.pinterest.com/{u}/"},
    "Steam": {"url": "https://steamcommunity.com/id/{u}"},
    "HackerEarth": {"url": "https://www.hackerearth.com/@{u}"},
    "Replit": {"url": "https://replit.com/@{u}"},
    "HackerRank": {"url": "https://www.hackerrank.com/{u}"},
    "LeetCode": {"url": "https://leetcode.com/{u}/"},
    "Codeforces": {"url": "https://codeforces.com/profile/{u}"},
    "Kaggle": {"url": "https://www.kaggle.com/{u}"},
    "Dribbble": {"url": "https://dribbble.com/{u}"},
    "Behance": {"url": "https://www.behance.net/{u}"},
    "Gravatar": {"url": "https://en.gravatar.com/{u}"},
    "Disqus": {"url": "https://disqus.com/by/{u}/"},
    "Tumblr": {"url": "https://{u}.tumblr.com"},
    "WordPress Profile": {"url": "https://profiles.wordpress.org/{u}/"},
    "SourceForge": {"url": "https://sourceforge.net/u/{u}/profile"},
    "Launchpad": {"url": "https://launchpad.net/~{u}"},
    "Fandom": {"url": "https://www.fandom.com/u/{u}"},
    "Goodreads": {"url": "https://www.goodreads.com/{u}"},
    "Wattpad": {"url": "https://www.wattpad.com/user/{u}"},
    "Archive of Our Own": {"url": "https://archiveofourown.org/users/{u}"},
    "Patreon": {"url": "https://www.patreon.com/{u}"},
    "Buy Me a Coffee": {"url": "https://buymeacoffee.com/{u}"},
    "Ko-fi": {"url": "https://ko-fi.com/{u}"},
    "Linktree": {"url": "https://linktr.ee/{u}"},
    "Hashnode": {"url": "https://hashnode.com/@{u}"},
    "DEV Community": {"url": "https://dev.to/{u}"},
    "Docker Hub": {"url": "https://hub.docker.com/u/{u}"},
    "RubyGems": {"url": "https://rubygems.org/profiles/{u}"},
    "Crates.io": {"url": "https://crates.io/users/{u}"},
    "Roblox": {"url": "https://www.roblox.com/user.aspx?username={u}"},
}

MANUAL_USERNAME_SITES = {
    "Instagram": {"url": "https://www.instagram.com/{u}/"},
    "TikTok": {"url": "https://www.tiktok.com/@{u}"},
    "Facebook": {"url": "https://www.facebook.com/{u}"},
    "X / Twitter": {"url": "https://x.com/{u}"},
    "Threads": {"url": "https://www.threads.net/@{u}"},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{u}"},
    "Snapchat": {"url": "https://www.snapchat.com/add/{u}"},
    "YouTube": {"url": "https://www.youtube.com/@{u}"},
    "VK": {"url": "https://vk.com/{u}"},
    "OK.ru": {"url": "https://ok.ru/{u}"},
    "Pixiv": {"url": "https://www.pixiv.net/en/users/{u}"},
    "Mastodon": {"url": "https://mastodon.social/@{u}"},
    "Telegram": {"url": "https://t.me/{u}"},
    "Fiverr": {"url": "https://www.fiverr.com/{u}"},
}

def detect_tech_stack(headers: dict, html: str, cookies: list) -> dict:
    tech = {"web_server": [], "backend_language": [], "framework": [], "cms_platform": [], "cdn_waf": [], "ui_library": []}
    html_lower = html.lower() if html else ""
    server = headers.get("server", "").lower()
    x_powered = headers.get("x-powered-by", "").lower()
    cookie_str = " ".join(cookies).lower()
    all_headers_str = " ".join(str(v).lower() for v in headers.values())
    if "apache" in server: tech["web_server"].append("Apache")
    if "nginx" in server: tech["web_server"].append("Nginx")
    if "iis" in server or "microsoft-iis" in server: tech["web_server"].append("Microsoft IIS")
    if "litespeed" in server: tech["web_server"].append("LiteSpeed")
    if "openresty" in server: tech["web_server"].append("OpenResty")
    if "gws" in server: tech["web_server"].append("Google Web Server")
    if "php" in x_powered: tech["backend_language"].append("PHP")
    if "asp.net" in x_powered: tech["backend_language"].append("ASP.NET")
    if "express" in x_powered: tech["backend_language"].append("Node.js / Express")
    if "phpsessid" in cookie_str: tech["backend_language"].append("PHP")
    if "asp.net_sessionid" in cookie_str: tech["backend_language"].append("ASP.NET")
    if "jsessionid" in cookie_str: tech["backend_language"].append("Java")
    if "laravel_session" in cookie_str or "laravel" in cookie_str: tech["framework"].append("Laravel (PHP)")
    if "django" in cookie_str or "csrftoken" in cookie_str: tech["framework"].append("Django (Python)")
    if "react" in html_lower or "react-dom" in html_lower: tech["framework"].append("React")
    if "__next_data__" in html_lower or "_next/" in html_lower: tech["framework"].append("Next.js")
    if "vue.js" in html_lower or "vue@" in html_lower or "v-bind" in html_lower: tech["framework"].append("Vue.js")
    if "angular" in html_lower or "ng-version" in html_lower: tech["framework"].append("Angular")
    if "symfony" in cookie_str or "symfony" in html_lower: tech["framework"].append("Symfony (PHP)")
    if "ruby on rails" in html_lower or "_rails" in cookie_str: tech["framework"].append("Ruby on Rails")
    if "wp-content" in html_lower or "wp-includes" in html_lower or ("wordpress" in html_lower and "generator" in html_lower): tech["cms_platform"].append("WordPress")
    if "cdn.shopify.com" in html_lower or "shopify.theme" in html_lower: tech["cms_platform"].append("Shopify")
    if "wixstatic.com" in html_lower or "wix.com" in html_lower: tech["cms_platform"].append("Wix")
    if "squarespace" in html_lower: tech["cms_platform"].append("Squarespace")
    if "drupal.settings" in html_lower or "drupal.js" in html_lower: tech["cms_platform"].append("Drupal")
    if "/media/jui/" in html_lower or "joomla" in html_lower: tech["cms_platform"].append("Joomla")
    if "ghost" in html_lower and "ghost.org" in html_lower: tech["cms_platform"].append("Ghost")
    if "bootstrap" in html_lower: tech["ui_library"].append("Bootstrap")
    if "tailwindcss" in html_lower or "tailwind" in html_lower: tech["ui_library"].append("Tailwind CSS")
    if "jquery" in html_lower: tech["ui_library"].append("jQuery")
    if "font-awesome" in html_lower or "fontawesome" in html_lower: tech["ui_library"].append("Font Awesome")
    if "material-ui" in html_lower or "@mui" in html_lower: tech["ui_library"].append("Material UI")
    if "cf-ray" in headers or "cloudflare" in server: tech["cdn_waf"].append("Cloudflare")
    if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", "").lower(): tech["cdn_waf"].append("AWS CloudFront")
    if "x-sucuri-id" in headers: tech["cdn_waf"].append("Sucuri WAF")
    if "x-akamai-transformed" in headers or "akamai" in all_headers_str: tech["cdn_waf"].append("Akamai")
    if "fastly" in all_headers_str: tech["cdn_waf"].append("Fastly")
    if "incapsula" in all_headers_str or "_visid_incap" in cookie_str: tech["cdn_waf"].append("Imperva / Incapsula")
    for key in tech:
        tech[key] = list(dict.fromkeys(tech[key]))
    return tech

def build_analyst_prompt(scans: list) -> str:
    lines = []
    for s in scans[-15:]:
        module = s.get("module", "UNKNOWN")
        domain = s.get("domain", "")
        res = s.get("result", {})
        lines.append(f"--- {module} on {domain} ---")
        if module == "SCAN":
            lines.append(f"Resolved IPs: {', '.join(res.get('ip_addresses', []))}")
        elif module == "WHOIS":
            lines.append(f"Registrar: {res.get('registrar')}, Created: {res.get('created')}, Expires: {res.get('expires')}")
        elif module == "INSPECT":
            lines.append(f"Security Grade: {res.get('grade')}")
            tls = res.get("tls", {})
            lines.append(f"TLS Status: {tls.get('status')}, Days Left: {tls.get('days_left')}")
            tech = res.get("technologies", {})
            tech_str = "; ".join([f"{k.replace('_',' ').title()}: {', '.join(v)}" for k,v in tech.items() if v])
            lines.append(f"Tech Stack: {tech_str}")
            lines.append(f"Missing Security Headers: {', '.join(res.get('missing_headers', []))}")
        elif module == "EMAIL":
            lines.append(f"Email Security Grade: {res.get('grade')}")
            spf = res.get("spf", {}).get("found")
            dmarc_found = res.get("dmarc", {}).get("found")
            dmarc_pol = res.get("dmarc", {}).get("policy")
            dkim = res.get("dkim", {}).get("found")
            lines.append(f"SPF: {'Yes' if spf else 'No'}, DMARC: {'Yes ('+str(dmarc_pol)+')' if dmarc_found else 'No'}, DKIM: {'Yes' if dkim else 'No'}")
        elif module == "VULNSCAN":
            findings = res.get("findings", [])
            lines.append(f"Total Findings: {len(findings)}")
            severities = {}
            for f in findings:
                sev = f.get("severity", "Info")
                severities[sev] = severities.get(sev, 0) + 1
            lines.append(f"Findings by Severity: {severities}")
        elif module == "SUBDOMAINS":
            lines.append(f"Subdomains Discovered: {res.get('count', 0)}")
        elif module == "PORTS":
            open_ports = res.get("open_ports", [])
            lines.append(f"Open Ports: {len(open_ports)}")
            for p in open_ports:
                lines.append(f"  • Port {p.get('port')} ({p.get('service')})")
        elif module == "FOOTPRINT":
            lines.append(f"Username accounts found: {res.get('found_count', 0)}")
            for r in res.get("results", []):
                if r.get("status") == "FOUND":
                    lines.append(f"  • {r.get('site')}: {r.get('url')}")
        elif module == "NSLOOKUP":
            lines.append("Extended DNS records retrieved.")
        lines.append("")
    return "\n".join(lines)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>OSINT AI Command Center</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { box-sizing: border-box; }
        body { margin: 0; overflow: hidden; font-family: 'Segoe UI', system-ui, sans-serif; background: #02050a; color: #e0e6ed; }
        #bg-canvas { position: fixed; top: 0; left: 0; z-index: -1; width: 100vw; height: 100vh; }
        .ui-panel { position: fixed; top: 10px; right: 10px; left: 10px; max-height: calc(100vh - 20px); display: flex; flex-direction: column; background: rgba(10, 20, 35, 0.88); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid rgba(0, 243, 255, 0.3); border-radius: 16px; padding: 16px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5), 0 0 20px rgba(0, 243, 255, 0.1); overflow: hidden; }
        h2 { margin: 0 0 10px 0; color: #00f3ff; font-size: 18px; font-weight: 600; letter-spacing: 1px; display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
        h2::before { content: ''; display: inline-block; width: 8px; height: 8px; background: #00f3ff; border-radius: 50%; box-shadow: 0 0 10px #00f3ff; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
        .auth-top { display: flex; align-items: center; gap: 10px; background: rgba(255,255,255,0.06); border: 1px solid rgba(0, 243, 255, 0.25); border-radius: 999px; padding: 10px 12px; margin-bottom: 10px; cursor: pointer; user-select: none; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); transition: 0.2s; flex-shrink: 0; }
        .auth-top:hover { border-color: rgba(0,243,255,0.55); background: rgba(255,255,255,0.09); }
        .auth-top input { accent-color: #ff0055; width: 16px; height: 16px; margin: 0; cursor: pointer; }
        .auth-dot { width: 10px; height: 10px; border-radius: 50%; background: #555; transition: 0.2s; flex-shrink: 0; }
        .auth-top.active { border-color: rgba(255,0,85,0.65); background: rgba(255,0,85,0.08); box-shadow: 0 0 18px rgba(255,0,85,0.18); }
        .auth-top.active .auth-dot { background: #ff0055; box-shadow: 0 0 12px #ff0055; }
        .auth-text { flex: 1; font-size: 12px; color: #ffd6e2; letter-spacing: 0.3px; }
        .chat-box { background: rgba(0,0,0,0.4); padding: 12px; border-radius: 10px; flex: 1 1 auto; min-height: 80px; overflow-y: auto; margin-bottom: 10px; border: 1px solid rgba(255,255,255,0.05); font-size: 13px; line-height: 1.4; }
        .chat-box::-webkit-scrollbar { width: 6px; }
        .chat-box::-webkit-scrollbar-thumb { background: #00f3ff; border-radius: 3px; }
        .user { color: #ffb400; margin-bottom: 10px; font-weight: 500; white-space: pre-wrap; word-break: break-word; }
        .ai { color: #a0e8ff; margin-bottom: 12px; padding-left: 10px; border-left: 2px solid #00f3ff; white-space: pre-wrap; word-break: break-word; }
        .ai pre { background: rgba(0,0,0,0.35); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 8px; margin-top: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; font-size: 11px; }
        .controls { display: flex; flex-direction: column; gap: 8px; flex-shrink: 0; }
        input[type="text"] { width: 100%; padding: 12px; background: rgba(255,255,255,0.05); color: white; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; outline: none; transition: 0.2s; font-size: 14px; }
        input[type="text"]:focus { border-color: #00f3ff; background: rgba(0,0,0,0.5); box-shadow: 0 0 15px rgba(0, 243, 255, 0.2); }
        .btn-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; }
        button { padding: 11px 0; background: linear-gradient(135deg, #004477, #0088cc); color: white; border: 1px solid rgba(0, 243, 255, 0.2); border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 11px; letter-spacing: 0.5px; transition: 0.2s; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3); width: 100%; }
        button:hover { background: linear-gradient(135deg, #007acc, #00f3ff); transform: translateY(-1px); box-shadow: 0 6px 15px rgba(0, 243, 255, 0.4); }
        button:active { transform: translateY(1px); }
        .btn-danger { background: linear-gradient(135deg, #660022, #aa0044) !important; border: 1px solid rgba(255, 0, 85, 0.3) !important; }
        .btn-danger:hover { background: linear-gradient(135deg, #aa0044, #ff0055) !important; box-shadow: 0 6px 15px rgba(255, 0, 85, 0.4) !important; }
        .btn-export { background: linear-gradient(135deg, #115511, #22aa22) !important; border: 1px solid rgba(100, 255, 100, 0.3) !important; }
        .btn-export:hover { background: linear-gradient(135deg, #22aa22, #44ff44) !important; box-shadow: 0 6px 15px rgba(100, 255, 100, 0.4) !important; }
        .btn-ai { background: linear-gradient(135deg, #4a0080, #8a2be2) !important; border: 1px solid rgba(200, 100, 255, 0.4) !important; }
        .btn-ai:hover { background: linear-gradient(135deg, #8a2be2, #b366ff) !important; box-shadow: 0 6px 15px rgba(200, 100, 255, 0.5) !important; }
        .full-width { grid-column: 1 / -1; }
        .status-bar { margin-top: 8px; font-size: 11px; color: #6688aa; display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; }
        .status-dot { display: inline-block; width: 6px; height: 6px; background: #66ff66; border-radius: 50%; margin-right: 5px; box-shadow: 0 0 5px #66ff66; }
        .hint { margin-top: 6px; font-size: 10px; color: #5b7b99; text-align: center; flex-shrink: 0; }
        @media (min-width: 768px) { .ui-panel { left: auto; right: 20px; top: 20px; width: min(520px, calc(100vw - 40px)); max-height: calc(100vh - 40px); padding: 20px; } .btn-grid { grid-template-columns: repeat(4, 1fr); } .chat-box { min-height: 140px; font-size: 14px; } h2 { font-size: 20px; } }
        @media (min-width: 1200px) { .ui-panel { width: 600px; } .chat-box { min-height: 200px; } }
        @media (max-height: 500px) { .chat-box { min-height: 60px; } .hint { display: none; } }
    </style>
</head>
<body>
    <canvas id="bg-canvas"></canvas>
    <div class="ui-panel">
        <h2>OSINT DASHBOARD</h2>
        <label class="auth-top" id="authPill">
            <span class="auth-dot"></span>
            <span class="auth-text">AUTHORIZED TARGET MODE — enable for Ports / VulnScan / Footprint</span>
            <input type="checkbox" id="authorized" onchange="updateAuthPill()">
        </label>
        <div class="chat-box" id="chat">
            <div class="ai">System initialized. Enter a target domain or username below and select a module.</div>
        </div>
        <div class="controls">
            <input type="text" id="domainInput" placeholder="Domain or Username (e.g. example.com or johndoe)" onkeypress="if(event.key === 'Enter') runCommand('scan')">
            <div class="btn-grid">
                <button onclick="runCommand('scan')">SCAN</button>
                <button onclick="runCommand('nslookup')">NSLOOKUP</button>
                <button onclick="runCommand('whois')">WHOIS</button>
                <button onclick="runCommand('subs')">SUBDOMAINS</button>
                <button onclick="runCommand('inspect')">INSPECT</button>
                <button onclick="runCommand('email')">EMAIL</button>
                <button onclick="runCommand('ports')">PORTS</button>
                <button onclick="runCommand('footprint')">FOOTPRINT</button>
                <button onclick="runCommand('vulnscan')" class="btn-danger full-width">⚠️ VULNSCAN (Requires Auth)</button>
            </div>
            <button onclick="aiAnalyze()" class="btn-ai full-width">🧠 AI ANALYST SUMMARY</button>
            <button onclick="downloadReport()" class="btn-export full-width">📥 EXPORT CASE FILE (JSON)</button>
        </div>
        <div class="status-bar">
            <span><span class="status-dot"></span> UPLINK ACTIVE</span>
        </div>
        <div class="hint">Educational use only. Only query domains/usernames you own or are authorized to investigate.</div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script>
        const canvas = document.getElementById('bg-canvas');
        const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.toneMapping = THREE.ACESFilmicToneMapping;
        renderer.toneMappingExposure = 1.2;
        const scene = new THREE.Scene();
        scene.fog = new THREE.FogExp2(0x02050a, 0.05);
        const camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 100);
        camera.position.set(0, 1, 8);
        camera.lookAt(0, 0, 0);
        scene.add(new THREE.AmbientLight(0x404040, 0.5));
        const mainLight = new THREE.DirectionalLight(0xffffff, 1.5); mainLight.position.set(5, 5, 5); scene.add(mainLight);
        const rimLight1 = new THREE.PointLight(0x00f3ff, 3, 15); rimLight1.position.set(-4, 2, -2); scene.add(rimLight1);
        const rimLight2 = new THREE.PointLight(0xff0055, 2, 15); rimLight2.position.set(4, -2, -2); scene.add(rimLight2);
        const avatarGroup = new THREE.Group(); scene.add(avatarGroup);
        const shellMat = new THREE.MeshPhysicalMaterial({ color: 0x112233, metalness: 0.1, roughness: 0.05, transmission: 0.95, thickness: 1.0, envMapIntensity: 1.5, clearcoat: 1.0, clearcoatRoughness: 0.1 });
        avatarGroup.add(new THREE.Mesh(new THREE.SphereGeometry(1.2, 64, 64), shellMat));
        const coreMat = new THREE.MeshBasicMaterial({ color: 0x00f3ff, wireframe: true, transparent: true, opacity: 0.8, blending: THREE.AdditiveBlending });
        const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.7, 2), coreMat); avatarGroup.add(core);
        const ringMat = new THREE.MeshBasicMaterial({ color: 0x00f3ff, transparent: true, opacity: 0.6 });
        const ringGeo = new THREE.TorusGeometry(1.6, 0.015, 16, 100);
        const ring1 = new THREE.Mesh(ringGeo, ringMat); ring1.rotation.x = Math.PI / 2; avatarGroup.add(ring1);
        const ring2 = new THREE.Mesh(ringGeo, ringMat.clone()); ring2.rotation.x = Math.PI / 3; ring2.rotation.y = Math.PI / 4; avatarGroup.add(ring2);
        const ring3 = new THREE.Mesh(ringGeo, ringMat.clone()); ring3.rotation.x = -Math.PI / 3; ring3.rotation.y = -Math.PI / 4; avatarGroup.add(ring3);
        const gridHelper = new THREE.GridHelper(40, 40, 0x004466, 0x001122); gridHelper.position.y = -3; gridHelper.material.opacity = 0.3; gridHelper.material.transparent = true; scene.add(gridHelper);
        let pulseUntil = 0;
        function pulseAvatar(seconds) { pulseUntil = Date.now() + (seconds || 2) * 1000; }
        function animate() { requestAnimationFrame(animate); const time = Date.now() * 0.001; avatarGroup.position.y = Math.sin(time * 0.8) * 0.2; core.rotation.x += 0.01; core.rotation.y += 0.015; const active = Date.now() < pulseUntil; if (active) { const pulse = Math.abs(Math.sin(time * 10)); core.scale.setScalar(1 + pulse * 0.3); coreMat.color.setHSL(0.55 + pulse * 0.1, 1, 0.5 + pulse * 0.2); ring1.rotation.z += 0.05; ring2.rotation.z -= 0.04; ring3.rotation.z += 0.03; } else { core.scale.setScalar(1); ring1.rotation.z += 0.002; ring2.rotation.z -= 0.001; ring3.rotation.z += 0.0015; } renderer.render(scene, camera); }
        animate();
        window.addEventListener('resize', () => { camera.aspect = window.innerWidth / window.innerHeight; camera.updateProjectionMatrix(); renderer.setSize(window.innerWidth, window.innerHeight); });
        const chat = document.getElementById('chat');
        let caseFile = { tool: "Safe OSINT AI Command Center", session_start: new Date().toISOString(), analyst: "Local User", scans: [] };
        function addMsg(who, text) { const div = document.createElement('div'); div.className = who; div.textContent = text; chat.appendChild(div); chat.scrollTop = chat.scrollHeight; }
        function addJSON(who, label, obj) { const div = document.createElement('div'); div.className = who; const labelDiv = document.createElement('div'); labelDiv.textContent = label; const pre = document.createElement('pre'); pre.textContent = JSON.stringify(obj, null, 2); div.appendChild(labelDiv); div.appendChild(pre); chat.appendChild(div); chat.scrollTop = chat.scrollHeight; }
        function addList(who, label, items, limit) { limit = limit || 100; const div = document.createElement('div'); div.className = who; const labelDiv = document.createElement('div'); labelDiv.textContent = label; const pre = document.createElement('pre'); pre.textContent = items.slice(0, limit).join("\\n"); if (items.length > limit) pre.textContent += "\\n\\n[ Results limited to " + limit + " entries ]"; div.appendChild(labelDiv); div.appendChild(pre); chat.appendChild(div); chat.scrollTop = chat.scrollHeight; }
        function updateAuthPill() { const pill = document.getElementById('authPill'); const box = document.getElementById('authorized'); if (pill && box) { pill.classList.toggle('active', box.checked); } }
        window.addEventListener('load', updateAuthPill);
        async function apiCall(path, target) { let paramName = (path === 'footprint') ? 'username' : 'domain'; let url = "/api/" + path + "?" + paramName + "=" + encodeURIComponent(target); if (path === 'vulnscan' || path === 'ports' || path === 'footprint') { const authBox = document.getElementById('authorized'); url += "&authorized=" + ((authBox && authBox.checked) ? "true" : "false"); } const res = await fetch(url); return await res.json(); }
        function downloadReport() { if (caseFile.scans.length === 0) { addMsg('ai', '⚠️ Case file is empty. Run some scans first.'); pulseAvatar(2); return; } const reportString = JSON.stringify(caseFile, null, 4); const blob = new Blob([reportString], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; const dateStr = new Date().toISOString().slice(0,19).replace(/:/g, '-'); a.download = `OSINT_Report_${dateStr}.json`; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); addMsg('ai', '📥 Case file exported successfully to your downloads folder.'); pulseAvatar(2); }
        async function aiAnalyze() { if (caseFile.scans.length === 0) { addMsg('ai', '⚠️ No scan data to analyze yet. Run some modules first.'); pulseAvatar(2); return; } addMsg('user', 'REQUESTING AI ANALYST SUMMARY...'); addMsg('ai', '🧠 AI Analyst is reviewing the case file...'); pulseAvatar(3); try { const res = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(caseFile.scans) }); const data = await res.json(); if (data.status === 'success') { addMsg('ai', data.summary); caseFile.scans.push({ timestamp: new Date().toISOString(), module: 'AI_ANALYST', domain: 'ALL', result: { summary: data.summary } }); } else { addMsg('ai', '⚠️ AI Analysis failed: ' + data.error); } } catch (e) { addMsg('ai', '⚠️ Error contacting AI backend: ' + e.toString()); } pulseAvatar(2.5); }
        function formatTechStack(tech) { if (!tech) return ''; const cats = { web_server: 'Web Server', backend_language: 'Backend / Language', framework: 'Frameworks', cms_platform: 'CMS / Platform', cdn_waf: 'CDN / WAF', ui_library: 'UI Libraries' }; let out = ''; let foundAny = false; for (const key in cats) { if (tech[key] && tech[key].length > 0) { out += '  • ' + cats[key] + ': ' + tech[key].join(', ') + '\\n'; foundAny = true; } } if (!foundAny) out = '  • No specific technologies fingerprinted.\\n'; return out; }
        async function runCommand(cmd) { const domainInput = document.getElementById('domainInput'); let rawInput = domainInput.value.trim(); let target = rawInput.toLowerCase(); const parts = target.split(/\\s+/); if (parts.length > 1) { cmd = parts[0].toLowerCase(); target = parts[1].toLowerCase(); } if (!target) { addMsg('ai', '⚠️ Please enter a target domain or username in the text box first.'); pulseAvatar(2); return; } addMsg('user', 'EXECUTING: ' + cmd.toUpperCase() + ' ' + target); try { let data = null; if (cmd === 'scan') { addMsg('ai', 'Running basic DNS scan on ' + target + '...'); pulseAvatar(1.5); data = await apiCall('scan', target); if (data.status === 'success') addMsg('ai', 'Target acquired. ' + data.domain + ' resolves to: ' + data.ip_addresses.join(', ')); else if (data.status === 'blocked') addMsg('ai', 'Access denied. Safety protocols engaged.'); else addMsg('ai', 'Target unreachable. ' + data.error); } else if (cmd === 'nslookup') { addMsg('ai', 'Running extended DNS lookup on ' + target + '...'); pulseAvatar(1.5); data = await apiCall('nslookup', target); if (data.status === 'success') addJSON('ai', 'DNS records for ' + data.domain + ':', data.records); else if (data.status === 'blocked') addMsg('ai', 'Access denied.'); else addMsg('ai', 'DNS lookup failed. ' + data.error); } else if (cmd === 'whois') { addMsg('ai', 'Querying registration data for ' + target + '...'); pulseAvatar(1.5); data = await apiCall('whois', target); if (data.status === 'success') addJSON('ai', 'Registration data for ' + data.domain + ' (Source: ' + (data.source || 'Unknown') + '):', { registrar: data.registrar, created: data.created, expires: data.expires, updated: data.updated, status: data.status, nameservers: data.nameservers }); else if (data.status === 'blocked') addMsg('ai', 'Access denied.'); else addMsg('ai', 'WHOIS lookup failed. ' + data.error); } else if (cmd === 'subs' || cmd === 'subdomains') { addMsg('ai', 'Running passive subdomain discovery on ' + target + '...'); pulseAvatar(2); data = await apiCall('subdomains', target); if (data.status === 'success') { addMsg('ai', 'Found ' + data.count + ' certificate-linked subdomains for ' + data.domain + '.'); addList('ai', 'Subdomains:', data.subdomains, 100); } else if (data.status === 'blocked') addMsg('ai', 'Access denied.'); else addMsg('ai', 'Subdomain discovery failed. ' + data.error); } else if (cmd === 'inspect') { addMsg('ai', 'Initiating deep inspection + tech fingerprinting on ' + target + '...'); pulseAvatar(2.5); data = await apiCall('inspect', target); if (data.status === 'success') { let summary = '🛡️ SECURITY GRADE: ' + data.grade + '\\n\\n'; summary += '🔒 TLS/SSL Status: ' + data.tls.status + '\\n'; if (data.tls.days_left !== undefined) summary += '⏳ Certificate Expires in: ' + data.tls.days_left + ' days\\n'; summary += '\\n🧩 TECH STACK:\\n' + formatTechStack(data.technologies); summary += '\\n📋 Security Headers Found: ' + Object.keys(data.headers).length + '/5\\n'; if (data.missing_headers.length > 0) summary += '⚠️ Missing: ' + data.missing_headers.join(', '); else summary += '✅ All critical headers present.'; addMsg('ai', summary); addJSON('ai', 'Raw Inspection Data:', data); } else if (data.status === 'blocked') addMsg('ai', 'Access denied.'); else addMsg('ai', 'Inspection failed. ' + data.error); } else if (cmd === 'email') { addMsg('ai', '📧 Running email infrastructure OSINT on ' + target + '...'); pulseAvatar(2); data = await apiCall('email', target); if (data.status === 'success') { let summary = '📧 EMAIL SECURITY GRADE: ' + data.grade + '\\n\\n'; summary += 'MX records: ' + (data.mx.length ? data.mx.length : 'None') + '\\n'; summary += 'SPF: ' + (data.spf.found ? 'Found' : 'Missing') + '\\n'; summary += 'DMARC: ' + (data.dmarc.found ? ('Found (p=' + (data.dmarc.policy || '?') + ')') : 'Missing') + '\\n'; summary += 'DKIM: ' + (data.dkim.found ? ('Found on: ' + data.dkim.selectors.join(', ')) : 'Not found on common selectors') + '\\n'; addMsg('ai', summary); addJSON('ai', 'Email OSINT data:', { mx: data.mx, spf: data.spf, dmarc: data.dmarc, dkim: data.dkim }); addJSON('ai', 'Findings:', data.findings); addJSON('ai', 'Recommendations:', data.recommendations); } else if (data.status === 'blocked') addMsg('ai', 'Access denied. Safety protocols engaged.'); else addMsg('ai', 'Email OSINT failed. ' + data.error); } else if (cmd === 'ports') { const authBox = document.getElementById('authorized'); if (!authBox || !authBox.checked) { addMsg('ai', '⚠️ Enable AUTHORIZED TARGET MODE at the top before running a port probe.'); pulseAvatar(2); return; } addMsg('ai', '🔌 Running passive port probe on ' + target + '...'); pulseAvatar(2.5); data = await apiCall('ports', target); if (data.status === 'success') { let summary = '🔌 PORT PROBE RESULTS:\\n\\n'; summary += 'Target IP: ' + data.ip + '\\n'; summary += 'Open Ports Found: ' + data.open_ports.length + '\\n'; if (data.open_ports.length > 0) { data.open_ports.forEach(p => { summary += '  • Port ' + p.port + ' (' + p.service + ')\\n'; }); } else { summary += '  • No common ports detected as open.\\n'; } addMsg('ai', summary); addJSON('ai', 'Raw Port Data:', data); } else if (data.status === 'blocked') addMsg('ai', 'Access denied. ' + (data.error || 'Safety protocols engaged.')); else addMsg('ai', 'Port probe failed. ' + data.error); } else if (cmd === 'footprint') { const authBox = document.getElementById('authorized'); if (!authBox || !authBox.checked) { addMsg('ai', '⚠️ Enable AUTHORIZED TARGET MODE at the top before running Footprint.'); pulseAvatar(2); return; } addMsg('ai', '🔍 Running username footprint check for "' + target + '" across 60 platforms...'); pulseAvatar(3); data = await apiCall('footprint', target); if (data.status === 'success') { let summary = '🔍 USERNAME FOOTPRINT: @' + data.username + '\\n\\n'; summary += 'Auto platforms checked: ' + data.total_checked + '\\n'; summary += 'Accounts FOUND: ' + data.found_count + '\\n'; summary += 'Manual social checks: ' + data.manual_count + '\\n\\n'; if (data.found_count > 0) { summary += '✅ AUTO-CONFIRMED ACCOUNTS:\\n'; data.results.filter(r => r.status === 'FOUND').forEach(r => { summary += '  • ' + r.site + ': ' + r.url + '\\n'; }); } else { summary += 'No auto-confirmed accounts found.\\n'; } if (data.manual_count > 0) { summary += '\\n👁️ MANUAL SOCIAL CHECKS (open in browser):\\n'; data.manual_links.forEach(m => { summary += '  • ' + m.site + ': ' + m.url + '\\n'; }); } addMsg('ai', summary); addJSON('ai', 'Full Auto Footprint Data:', data.results); addJSON('ai', 'Manual Social Links:', data.manual_links); } else if (data.status === 'blocked') addMsg('ai', 'Access denied. ' + (data.error || 'Safety protocols engaged.')); else addMsg('ai', 'Footprint check failed. ' + data.error); } else if (cmd === 'vulnscan') { const authBox = document.getElementById('authorized'); if (!authBox || !authBox.checked) { addMsg('ai', '⚠️ Enable AUTHORIZED TARGET MODE at the top before running a vulnerability scan.'); pulseAvatar(2); return; } addMsg('ai', '🧪 Running safe vulnerability assessment on ' + target + '...'); pulseAvatar(2.5); data = await apiCall('vulnscan', target); if (data.status === 'success') { let summary = '🧪 SAFE VULN ASSESSMENT: ' + data.domain + '\\n\\n'; summary += 'Findings: ' + data.findings.length + '\\n'; summary += 'Technologies detected: ' + data.technologies.length + '\\n'; summary += 'TLS: ' + (data.tls.status || 'Unknown') + '\\n'; addMsg('ai', summary); addJSON('ai', 'Findings:', data.findings); if (data.cve_search.length > 0) addJSON('ai', 'Possible CVE intelligence:', data.cve_search); addJSON('ai', 'Recommendations:', data.recommendations); } else if (data.status === 'blocked') addMsg('ai', 'Access denied. ' + (data.error || 'Safety protocols engaged.')); else addMsg('ai', 'Vuln scan failed. ' + data.error); } else { addMsg('ai', 'Unknown command module.'); return; } if (data) { caseFile.scans.push({ timestamp: new Date().toISOString(), module: cmd.toUpperCase(), domain: target, result: data }); } } catch (e) { addMsg('ai', 'Network timeout or uplink lost. The target server may be blocking automated queries.'); } pulseAvatar(2.5); }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root(): return HTML_PAGE

@app.post("/api/analyze")
async def analyze_scans(scans: list):
    prompt_data = build_analyst_prompt(scans)
    system_prompt = "You are a professional defensive cybersecurity analyst. Review the OSINT scan data. Write a concise executive summary."
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(OLLAMA_URL, json={"model": OLLAMA_MODEL, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt_data}], "stream": False})
            if resp.status_code == 200:
                summary = resp.json().get("message", {}).get("content", "")
                return {"status": "success", "summary": "🧠 AI ANALYST (LLAMA3):\\n\\n" + summary}
    except Exception:
        pass
    summary = ["🧠 EXECUTIVE SECURITY SUMMARY (Built-in Analyst)\\n"]
    summary.append("Ollama was not detected, so the built-in Python analyst generated this report.\\n")
    domains_scanned = set()
    grades = []
    missing_headers_all = []
    tech_found = []
    email_issues = []
    vuln_findings = []
    port_findings = []
    footprint_findings = []
    for s in scans:
        domain = s.get("domain", "Unknown")
        if domain != "ALL": domains_scanned.add(domain)
        module = s.get("module")
        res = s.get("result", {})
        if module == "INSPECT":
            grades.append(f"{domain}: Grade {res.get('grade', 'F')}")
            missing_headers_all.extend(res.get("missing_headers", []))
            tech = res.get("technologies", {})
            for cat, items in tech.items(): tech_found.extend(items)
        elif module == "EMAIL":
            if not res.get("spf", {}).get("found"): email_issues.append(f"{domain}: Missing SPF")
            if not res.get("dmarc", {}).get("found"): email_issues.append(f"{domain}: Missing DMARC")
            if res.get("spf", {}).get("record") and "+all" in res.get("spf", {}).get("record", "").lower(): email_issues.append(f"{domain}: Dangerous SPF (+all)")
        elif module == "VULNSCAN":
            for f in res.get("findings", []):
                if f.get("severity") in ["High", "Medium"]: vuln_findings.append(f"{domain}: [{f.get('severity')}] {f.get('issue')}")
        elif module == "PORTS":
            for p in res.get("open_ports", []): port_findings.append(f"{domain}: Port {p.get('port')} ({p.get('service')})")
        elif module == "FOOTPRINT":
            for r in res.get("results", []):
                if r.get("status") == "FOUND": footprint_findings.append(f"{r.get('site')}: {r.get('url')}")
    summary.append(f"🎯 TARGETS INVESTIGATED: {', '.join(domains_scanned) if domains_scanned else 'None'}\\n")
    if grades: summary.append("🛡️ INFRASTRUCTURE GRADES:\\n  • " + "\\n  • ".join(grades) + "\\n")
    if tech_found:
        unique_tech = list(dict.fromkeys(tech_found))
        summary.append("🧩 TECHNOLOGIES IDENTIFIED:\\n  • " + ", ".join(unique_tech[:10]) + "\\n")
    if missing_headers_all:
        unique_missing = list(dict.fromkeys(missing_headers_all))
        summary.append("⚠️ CRITICAL MISSING HEADERS:\\n  • " + ", ".join(unique_missing) + "\\n")
    if email_issues: summary.append("📧 EMAIL SPOOFING RISKS:\\n  • " + "\\n  • ".join(email_issues) + "\\n")
    if port_findings: summary.append("🔌 EXPOSED SERVICES:\\n  • " + "\\n  • ".join(port_findings) + "\\n")
    if footprint_findings: summary.append("🔍 USERNAME ACCOUNTS FOUND:\\n  • " + "\\n  • ".join(footprint_findings) + "\\n")
    if vuln_findings: summary.append("🚨 VULNERABILITY FINDINGS (High/Medium):\\n  • " + "\\n  • ".join(vuln_findings[:5]) + "\\n")
    summary.append("📝 RECOMMENDATIONS:")
    if missing_headers_all: summary.append("  1. Implement missing HTTP security headers immediately to prevent XSS and Clickjacking.")
    if email_issues: summary.append("  2. Harden email authentication (SPF/DMARC) to prevent domain spoofing and phishing.")
    if port_findings: summary.append("  3. Review exposed ports and close unnecessary services to reduce attack surface.")
    if vuln_findings: summary.append("  4. Patch or update exposed technologies identified in the vulnerability scan.")
    if not missing_headers_all and not email_issues and not vuln_findings and not port_findings and not footprint_findings:
        summary.append("  1. Target appears well-configured. Continue monitoring for new CVEs.")
    return {"status": "success", "summary": "\\n".join(summary)}

@app.get("/api/scan")
def scan_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked by safety guardrails.", "status": "blocked"}
    try:
        answers = dns.resolver.resolve(domain, "A")
        return {"domain": domain, "ip_addresses": [ip.to_text() for ip in answers], "status": "success"}
    except Exception as e: return {"domain": domain, "error": str(e), "status": "error"}

@app.get("/api/nslookup")
def nslookup_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked by safety guardrails.", "status": "blocked"}
    records = {}
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata).strip() for rdata in answers]
        except Exception: records[record_type] = []
    return {"domain": domain, "records": records, "status": "success"}

@app.get("/api/whois")
def whois_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked.", "status": "blocked"}
    try:
        url = f"https://rdap.org/domain/{domain}"
        response = httpx.get(url, timeout=15, follow_redirects=True, headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            events = {e.get("eventAction", "").lower(): e.get("eventDate") for e in data.get("events", [])}
            return {"domain": domain, "registrar": extract_registrar_from_rdap(data), "created": events.get("registration"), "expires": events.get("expiration"), "updated": events.get("last changed") or events.get("last update"), "status": data.get("status", []), "nameservers": [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])], "source": "RDAP HTTP", "status": "success"}
    except Exception: pass
    try:
        w = whois.whois(domain)
        def get_first(val): return str(val[0]) if isinstance(val, list) and val else (str(val) if val else None)
        return {"domain": domain, "registrar": get_first(w.registrar), "created": get_first(w.creation_date), "expires": get_first(w.expiration_date), "updated": get_first(w.updated_date), "status": w.status if isinstance(w.status, list) else ([w.status] if w.status else []), "nameservers": [str(ns) for ns in w.name_servers] if w.name_servers else [], "source": "WHOIS Port 43", "status": "success"}
    except Exception as e: return {"domain": domain, "error": f"Both RDAP and WHOIS failed. ({str(e)})", "status": "error"}

@app.get("/api/subdomains")
def subdomains_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked.", "status": "blocked"}
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = httpx.get(url, timeout=60.0, headers=HEADERS)
        if response.status_code != 200: return {"domain": domain, "error": f"crt.sh HTTP {response.status_code}", "status": "error"}
        entries = response.json()
        if not isinstance(entries, list): return {"domain": domain, "error": "Unexpected crt.sh response format.", "status": "error"}
        subdomains = set()
        for entry in entries[:1000]:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.startswith("*."): name = name[2:]
                if name == domain or name.endswith("." + domain):
                    if is_public_hostname(name): subdomains.add(name)
        sorted_subdomains = sorted(subdomains)
        return {"domain": domain, "count": len(sorted_subdomains), "subdomains": sorted_subdomains[:200], "status": "success"}
    except Exception as e: return {"domain": domain, "error": str(e), "status": "error"}

@app.get("/api/inspect")
def inspect_domain(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked.", "status": "blocked"}
    result = {"domain": domain, "tls": {}, "headers": {}, "missing_headers": [], "technologies": {}, "grade": "F", "status": "success"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.datetime.strptime(cert.get('notAfter'), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                result["tls"] = {"expires": expires.isoformat(), "days_left": (expires - datetime.datetime.now(datetime.timezone.utc)).days, "status": "Valid"}
    except Exception as e: result["tls"] = {"status": "Failed", "error": str(e)}
    required_headers = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-frame-options": "X-Frame", "x-content-type-options": "X-Content-Type", "referrer-policy": "Referrer-Policy"}
    try:
        headers_response = httpx.get(f"https://{domain}", timeout=10, follow_redirects=True, headers=HEADERS)
        resp_headers = {k.lower(): v for k, v in headers_response.headers.items()}
        resp_cookies = [v for k, v in headers_response.headers.multi_items() if k.lower() == "set-cookie"]
        html_body = headers_response.text[:100000]
        for h_key, h_name in required_headers.items():
            if h_key in resp_headers: result["headers"][h_name] = resp_headers[h_key]
            else: result["missing_headers"].append(h_name)
        result["technologies"] = detect_tech_stack(resp_headers, html_body, resp_cookies)
    except Exception as e: result["headers_error"] = str(e)
    score = 0
    if result["tls"].get("status") == "Valid":
        score += 50
        if result["tls"].get("days_left", 0) > 14: score += 10
    score += (len(result["headers"]) / len(required_headers)) * 40
    if score >= 90: result["grade"] = "A"
    elif score >= 75: result["grade"] = "B"
    elif score >= 60: result["grade"] = "C"
    elif score >= 40: result["grade"] = "D"
    return result

@app.get("/api/email")
def email_osint(domain: str):
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked by safety guardrails.", "status": "blocked"}
    result = {"domain": domain, "mx": [], "spf": {"found": False, "record": None}, "dmarc": {"found": False, "record": None, "policy": None}, "dkim": {"found": False, "selectors": []}, "findings": [], "recommendations": [], "grade": "F", "status": "success"}
    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["mx"] = sorted([str(r).strip() for r in answers])
    except Exception: result["mx"] = []
    if not result["mx"]: result["findings"].append({"severity": "Info", "issue": "No MX records", "detail": "Domain does not appear to receive email."})
    try:
        txt_answers = dns.resolver.resolve(domain, "TXT")
        txt_records = [txt_strings(r) for r in txt_answers]
        spf_records = [t for t in txt_records if t.strip().lower().startswith("v=spf1")]
        if spf_records:
            spf = spf_records[0]
            result["spf"]["found"] = True
            result["spf"]["record"] = spf
            low = spf.lower()
            if "+all" in low:
                result["findings"].append({"severity": "High", "issue": "SPF allows any sender (+all)", "detail": spf})
                result["recommendations"].append("Replace +all with ~all or -all in the SPF record.")
            elif "?all" in low:
                result["findings"].append({"severity": "Medium", "issue": "SPF neutral (?all)", "detail": spf})
                result["recommendations"].append("Consider ~all or -all instead of ?all in SPF.")
        else:
            result["findings"].append({"severity": "Medium", "issue": "No SPF record", "detail": "No v=spf1 TXT record found."})
            result["recommendations"].append("Publish an SPF record to reduce spoofing risk.")
    except Exception:
        result["findings"].append({"severity": "Medium", "issue": "No SPF record", "detail": "TXT lookup failed or empty."})
        result["recommendations"].append("Publish an SPF record to reduce spoofing risk.")
    try:
        dmarc_answers = dns.resolver.resolve("_dmarc." + domain, "TXT")
        dmarc_records = [txt_strings(r) for r in dmarc_answers]
        dmarc = [d for d in dmarc_records if "v=DMARC1" in d]
        if dmarc:
            rec = dmarc[0]
            result["dmarc"]["found"] = True
            result["dmarc"]["record"] = rec
            m = re.search(r"\bp=(none|quarantine|reject)", rec, re.IGNORECASE)
            policy = m.group(1).lower() if m else None
            result["dmarc"]["policy"] = policy
            if policy == "none":
                result["findings"].append({"severity": "Medium", "issue": "DMARC policy is none", "detail": rec})
                result["recommendations"].append("Move DMARC policy toward quarantine or reject.")
            elif not policy:
                result["findings"].append({"severity": "Low", "issue": "DMARC missing p= policy", "detail": rec})
        else:
            result["findings"].append({"severity": "Medium", "issue": "No DMARC record", "detail": "_dmarc TXT exists but no v=DMARC1."})
            result["recommendations"].append("Publish a DMARC record.")
    except Exception:
        result["findings"].append({"severity": "Medium", "issue": "No DMARC record", "detail": "No _dmarc TXT record found."})
        result["recommendations"].append("Publish a DMARC record.")
    selectors = ["google._domainkey", "default._domainkey", "mail._domainkey", "smtp._domainkey", "selector1._domainkey", "selector2._domainkey", "k1._domainkey", "s1._domainkey", "s2._domainkey"]
    for sel in selectors:
        try:
            dk = dns.resolver.resolve(sel + "." + domain, "TXT")
            recs = [txt_strings(r) for r in dk]
            if any("v=DKIM1" in r or "p=" in r for r in recs):
                result["dkim"]["found"] = True
                result["dkim"]["selectors"].append(sel)
        except Exception: continue
    if not result["dkim"]["found"]: result["findings"].append({"severity": "Low", "issue": "No DKIM on common selectors", "detail": "Checked common selectors. Custom selectors may still exist."})
    score = 0
    if result["mx"]: score += 20
    if result["spf"]["found"]: score += 30
    if result["dmarc"]["found"]: score += 30
    if result["dmarc"]["policy"] in ("quarantine", "reject"): score += 10
    if result["dkim"]["found"]: score += 10
    if "+all" in (result["spf"]["record"] or "").lower(): score -= 20
    if score >= 90: result["grade"] = "A"
    elif score >= 75: result["grade"] = "B"
    elif score >= 60: result["grade"] = "C"
    elif score >= 40: result["grade"] = "D"
    else: result["grade"] = "F"
    result["recommendations"] = list(dict.fromkeys(result["recommendations"]))
    return result

def safe_tls_check(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.datetime.strptime(cert.get("notAfter"), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                return {"status": "Valid", "expires": expires.isoformat(), "days_left": (expires - datetime.datetime.now(datetime.timezone.utc)).days}
    except Exception as e: return {"status": "Failed", "error": str(e)}

def search_nvd_cves(query: str, limit: int = 3):
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response = httpx.get(url, params={"keywordSearch": query, "resultsPerPage": limit}, headers=HEADERS, timeout=25)
        if response.status_code != 200: return {"query": query, "error": f"NVD HTTP {response.status_code}", "items": []}
        data = response.json()
        items = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve = vuln.get("cve", {})
            desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            score, severity = None, None
            for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                ml = cve.get("metrics", {}).get(mk)
                if ml: score, severity = ml[0].get("cvssData", {}).get("baseScore"), ml[0].get("cvssData", {}).get("baseSeverity"); break
            items.append({"id": cve.get("id"), "score": score, "severity": severity, "published": cve.get("published"), "description": desc[:250]})
        return {"query": query, "count": len(items), "items": items}
    except Exception as e: return {"query": query, "error": str(e), "items": []}

@app.get("/api/vulnscan")
def vulnscan_domain(domain: str, authorized: bool = False):
    domain = normalize_domain(domain)
    if not authorized: return {"error": "Authorization checkbox must be enabled.", "status": "blocked"}
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked by safety guardrails.", "status": "blocked"}
    result = {"domain": domain, "tls": {}, "findings": [], "missing_headers": [], "technologies": [], "cve_search": [], "recommendations": [], "status": "success"}
    result["tls"] = safe_tls_check(domain)
    if result["tls"].get("status") != "Valid":
        result["findings"].append({"severity": "High", "issue": "TLS/SSL check failed", "detail": result["tls"].get("error")})
        result["recommendations"].append("Ensure the target supports HTTPS and has a valid TLS certificate.")
    else:
        days_left = result["tls"].get("days_left")
        if isinstance(days_left, int):
            if days_left < 0:
                result["findings"].append({"severity": "High", "issue": "TLS certificate expired", "detail": f"Expired {abs(days_left)} days ago."})
                result["recommendations"].append("Renew the TLS certificate immediately.")
            elif days_left < 14:
                result["findings"].append({"severity": "Medium", "issue": "TLS certificate expiring soon", "detail": f"Expires in {days_left} days."})
                result["recommendations"].append("Renew the TLS certificate before expiration.")
    required_headers = {"strict-transport-security": "HSTS", "content-security-policy": "CSP", "x-frame-options": "X-Frame", "x-content-type-options": "X-Content-Type", "referrer-policy": "Referrer-Policy"}
    try:
        response = httpx.get(f"https://{domain}", timeout=15, follow_redirects=False, headers=HEADERS)
        headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
        if response.status_code in [301, 302, 307, 308]: result["findings"].append({"severity": "Info", "issue": "HTTP redirect detected", "detail": f"Redirects to: {headers.get('location', 'unknown')}"})
        if response.status_code >= 400: result["findings"].append({"severity": "Medium", "issue": "HTTP error status", "detail": f"HTTP {response.status_code}"})
        for h_key, h_name in required_headers.items():
            if h_key not in headers: result["missing_headers"].append(h_name)
        if result["missing_headers"]:
            result["findings"].append({"severity": "Medium", "issue": "Missing security headers", "detail": ", ".join(result["missing_headers"])})
            result["recommendations"].append("Add missing HTTP security headers.")
        server = headers.get("server")
        if server:
            result["technologies"].append({"type": "Server", "value": server})
            if re.search(r"\d", server):
                result["findings"].append({"severity": "Low", "issue": "Server version disclosure", "detail": server})
                result["recommendations"].append("Remove version info from Server header.")
        x_powered = headers.get("x-powered-by")
        if x_powered:
            result["technologies"].append({"type": "X-Powered-By", "value": x_powered})
            result["findings"].append({"severity": "Low", "issue": "Tech disclosure (X-Powered-By)", "detail": x_powered})
        cookie_flag_issue_added = False
        for cookie in cookies:
            lc = cookie.lower()
            if "phpsessid" in lc: result["technologies"].append({"type": "Cookie", "value": "PHP session"})
            if "asp.net_sessionid" in lc: result["technologies"].append({"type": "Cookie", "value": "ASP.NET session"})
            if "jsessionid" in lc: result["technologies"].append({"type": "Cookie", "value": "Java session"})
            missing = []
            if "secure" not in lc: missing.append("Secure")
            if "httponly" not in lc: missing.append("HttpOnly")
            if missing:
                result["findings"].append({"severity": "Low", "issue": "Cookie missing flags", "detail": f"{cookie[:60]}... missing {', '.join(missing)}"})
                if not cookie_flag_issue_added: result["recommendations"].append("Set Secure and HttpOnly on session cookies."); cookie_flag_issue_added = True
        tech_text = " ".join([t.get("value", "") for t in result["technologies"]]).lower()
        queries = []
        if "apache" in tech_text: queries.append("Apache HTTP Server")
        if "nginx" in tech_text: queries.append("nginx")
        if "php" in tech_text: queries.append("PHP")
        if "asp.net" in tech_text: queries.append("Microsoft ASP.NET")
        for q in list(dict.fromkeys(queries))[:2]: result["cve_search"].append(search_nvd_cves(q, 3))
    except Exception as e: result["findings"].append({"severity": "High", "issue": "HTTP check failed", "detail": str(e)})
    result["recommendations"] = list(dict.fromkeys(result["recommendations"]))
    return result

@app.get("/api/ports")
def check_ports(domain: str, authorized: bool = False):
    if not authorized: return {"error": "Authorization checkbox must be enabled.", "status": "blocked"}
    domain = normalize_domain(domain)
    if not is_safe_request(domain) or not is_public_hostname(domain): return {"error": "Target blocked by safety guardrails.", "status": "blocked"}
    try:
        ip = socket.gethostbyname(domain)
    except Exception: return {"error": "Could not resolve domain to IP address.", "status": "error"}
    ports_to_check = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
    open_ports = []
    for port, service in ports_to_check.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((ip, port))
            if result == 0: open_ports.append({"port": port, "service": service, "status": "OPEN"})
            sock.close()
        except Exception: pass
    return {"domain": domain, "ip": ip, "open_ports": open_ports, "status": "success"}

@app.get("/api/footprint")
def username_footprint(username: str, authorized: bool = False):
    if not authorized: return {"error": "Authorization checkbox must be enabled.", "status": "blocked"}
    username = sanitize_username(username)
    if not username or len(username) < 2: return {"error": "Invalid username. Use letters, numbers, dots, dashes, or underscores only.", "status": "error"}
    results = []
    def check_site(name, config):
        url = config["url"].format(u=username)
        try:
            r = httpx.get(url, timeout=8, follow_redirects=True, headers=HEADERS)
            if r.status_code == 200: return {"site": name, "url": url, "status": "FOUND", "code": r.status_code}
            elif r.status_code == 404: return {"site": name, "url": url, "status": "NOT FOUND", "code": r.status_code}
            else: return {"site": name, "url": url, "status": "UNCERTAIN", "code": r.status_code}
        except Exception as e: return {"site": name, "url": url, "status": "ERROR", "code": str(e)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_site, name, config): name for name, config in USERNAME_SITES.items()}
        for future in concurrent.futures.as_completed(futures): results.append(future.result())
    order = {"FOUND": 0, "UNCERTAIN": 1, "NOT FOUND": 2, "ERROR": 3}
    results.sort(key=lambda x: order.get(x["status"], 4))
    found = [r for r in results if r["status"] == "FOUND"]
    uncertain = [r for r in results if r["status"] == "UNCERTAIN"]
    manual_links = []
    for name, config in MANUAL_USERNAME_SITES.items():
        manual_links.append({"site": name, "url": config["url"].format(u=username), "note": "Manual check required. These platforms often block automated checks."})
    return {"username": username, "total_checked": len(results), "found_count": len(found), "uncertain_count": len(uncertain), "manual_count": len(manual_links), "results": results, "manual_links": manual_links, "status": "success"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
