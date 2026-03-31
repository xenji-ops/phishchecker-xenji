from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from urllib.parse import urlparse
import re
import math

app = FastAPI()

# Serve static files (CSS, JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --------------------------
# FRONTEND ROUTES
# --------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", encoding="utf-8") as f:
        return f.read()


@app.get("/app", response_class=HTMLResponse)
def app_page():
    with open("templates/app.html", encoding="utf-8") as f:
        return f.read()


# --------------------------
# MODEL
# --------------------------

class URLQuery(BaseModel):
    url: str


# --------------------------
# HELPER FUNCTIONS
# --------------------------

def is_ip(host):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


# --------------------------
# API ENDPOINT
# --------------------------

@app.post("/api/check")
def check(data: URLQuery):
    url = data.url.strip()

    # Ensure proper parsing
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    score = 0
    reasons = []

    # Rules
    if "@" in url:
        score += 0.5
        reasons.append("Contains @ (possible phishing)")

    if is_ip(host):
        score += 0.5
        reasons.append("Uses IP address instead of domain")

    if len(url) > 75:
        score += 0.2
        reasons.append("URL is very long")

    if entropy(host) > 3.5:
        score += 0.2
        reasons.append("Hostname looks random")

    # Decision
    if score > 0.7:
        verdict = "phishy"
    elif score > 0.3:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "verdict": verdict,
        "final_score": round(score, 2),
        "heuristic_reasons": reasons
    }