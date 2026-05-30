from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, field_validator
from urllib.parse import urlparse
import re
import math
import requests
from google import genai
import os
import logging
from dotenv import load_dotenv
 
# --------------------------
# SETUP
# --------------------------
load_dotenv()
 
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
 
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
 
# FIX 2: Check keys before starting, show clear error instead of cryptic crash
if not TAVILY_API_KEY:
    logger.error("TAVILY_API_KEY is missing from .env — Tavily search will not work.")
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY is missing from .env — AI analysis will not work.")
 
client = genai.Client(api_key=GEMINI_API_KEY)
 
# --------------------------
# APP & MIDDLEWARE
# --------------------------
limiter = Limiter(key_func=get_remote_address)
 
app = FastAPI()
app.state.limiter = limiter

# Custom rate limit handler with user-friendly message
@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "You're scanning too fast! Please wait a minute and try again."}
    )
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://urlverdict.vercel.app",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
 
app.mount("/static", StaticFiles(directory="static"), name="static")
 
# --------------------------
# KNOWN SAFE DOMAINS
# Skip Tavily for these — they'll never have scam reports
# --------------------------
KNOWN_SAFE_DOMAINS = {
    "google.com", "github.com", "amazon.com", "apple.com", "netflix.com",
    "microsoft.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "reddit.com", "wikipedia.org", "stackoverflow.com",
    "producthunt.com", "vercel.com", "cloudflare.com", "discord.com", "notion.so",
    "figma.com", "stripe.com", "shopify.com", "dropbox.com", "zoom.us",
    "whatsapp.com", "telegram.org", "paypal.com", "ebay.com", "flipkart.com",
    "myntra.com", "swiggy.com", "zomato.com", "paytm.com", "razorpay.com",
    "openai.com", "anthropic.com", "huggingface.co", "canva.com", "adobe.com",
}
 
def is_known_safe(host: str) -> bool:
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return host in KNOWN_SAFE_DOMAINS
 
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
 
@app.get("/ping")
def ping():
    return {"status": "ok"}
 
@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "1.1.0",
        "tavily_configured": bool(TAVILY_API_KEY),
        "gemini_configured": bool(GEMINI_API_KEY),
    }
 
# --------------------------
# MODELS
# --------------------------
class URLQuery(BaseModel):
    url: str
 
    # FIX 1: Limit URL input length to prevent abuse
    @field_validator('url')
    def limit_length(cls, v):
        if len(v) > 2048:
            raise ValueError('URL is too long (max 2048 characters)')
        return v
 
# --------------------------
# 1. HEURISTICS (original logic, unchanged)
# --------------------------
def is_ip(host):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
 
def entropy(s):
    if not s: return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)
 
def run_heuristics(url: str, host: str):
    score = 0
    reasons = []
 
    # Major Red Flags
    if "@" in url:
        score += 0.8
        reasons.append("Contains an '@' symbol (Hackers use this to hide fake domains).")
    if is_ip(host):
        score += 0.8
        reasons.append("Uses an IP address instead of a real name (Very suspicious).")
 
    # Minor Red Flags
    if len(url) > 120:
        score += 0.2
        reasons.append("The website link is unusually long.")
    if entropy(host) > 4.0:
        score += 0.2
        reasons.append("The website name looks like random gibberish.")
 
    return score, reasons
 
# --------------------------
# 2. OSINT SEARCH (original logic + timeout fix + FIX 3: status check)
# --------------------------
def search_internet_reviews(domain: str):
    query = f'"{domain}" (scam OR fake OR fraud OR review OR legit) (site:reddit.com OR site:trustpilot.com)'
    url = "https://api.tavily.com/search"
    payload = {
        "api_key": TAVILY_API_KEY,
        "query": query,
        "search_depth": "advanced",
        "include_answer": False,
        "max_results": 5
    }
    try:
        response = requests.post(url, json=payload, timeout=8)
        response.raise_for_status()  # FIX 3: raises error on 4xx/5xx from Tavily
        data = response.json()
        return [result['content'] for result in data.get('results', [])]
    except Exception as e:
        logger.error("Tavily search failed: %s", type(e).__name__)
        return []
 
# --------------------------
# 3. AI ANALYSIS (original logic + FIX 4: None safety check)
# --------------------------
def analyze_reviews_with_ai(domain: str, search_results: list):
    context = "\n".join(search_results) if search_results else "No reviews found."
 
    prompt = f"""
    You are a friendly cybersecurity guard helping a beginner who knows nothing about tech.
    Your job is to read these real internet comments (from Reddit/Trustpilot) about the website '{domain}'.
    
    CRITICAL — You must understand the DIFFERENCE between these two situations:
    A) A LEGITIMATE website that some users had bad experiences with (slow support, payout delays, bugs, policy disagreements). This is NORMAL — even Amazon and PayPal have angry reviews. These sites are NOT phishing.
    B) An ACTUAL SCAM or PHISHING site that was created to steal money, credentials, or personal data. People report being tricked, fake products, stolen credit cards, or the site disappearing after payment.
    
    RULES:
    1. If the domain is a well-known, established company or platform — output 'VERDICT: SAFE'. Even if some users had complaints, it is still a real business.
    2. If the site is a real, legitimate business BUT people have reported significant issues (poor service, refund problems, payment delays) — output 'VERDICT: SAFE_WITH_ISSUES'. This means the site itself is real, not a scam, but users should be aware of reported problems.
    3. If people are reporting that the site is an ACTUAL SCAM — fake products, stolen money with no real business behind it, phishing for credentials, impersonating another brand — output 'VERDICT: PHISHY'.
    4. If there are no search results at all, the site is either very new or unknown. Output 'VERDICT: SUSPICIOUS' and warn the user there is not enough public information yet.
    5. Only output 'VERDICT: PHISHY' if there is strong evidence of deliberate fraud, not just bad customer service.
    
    You MUST format your response exactly like this:
    VERDICT: [Choose one: SAFE, SAFE_WITH_ISSUES, SUSPICIOUS, or PHISHY]
    SUMMARY: [Write 2-3 very simple sentences. If SAFE, reassure them. If SAFE_WITH_ISSUES, tell them the site is legitimate but mention what issues people reported. If SUSPICIOUS, warn them there isn't enough info. If PHISHY, tell them exactly what scam people reported.]
    
    Search Results from Reddit/Trustpilot:
    {context}
    """
 
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        text = response.text
 
        # FIX 4: Gemini can return None if response is blocked by safety filters
        if not text:
            logger.warning("Gemini returned empty response for domain: %s", domain)
            return "SUSPICIOUS", "The AI analysis returned an empty response. Please try again."
 
        # Verdict extraction — SAFE_WITH_ISSUES maps to SAFE with nuanced summary
        ai_verdict = "SUSPICIOUS"
        text_upper = text.upper()
        if "VERDICT: PHISHY" in text_upper:
            ai_verdict = "PHISHY"
        elif "VERDICT: SAFE_WITH_ISSUES" in text_upper:
            ai_verdict = "SAFE_WITH_ISSUES"
        elif "VERDICT: SAFE" in text_upper:
            ai_verdict = "SAFE"
        elif "VERDICT: SUSPICIOUS" in text_upper:
            ai_verdict = "SUSPICIOUS"
 
        if "SUMMARY:" in text:
            summary = text.split("SUMMARY:")[-1].strip()
        else:
            summary = text
 
        return ai_verdict, summary
 
    except Exception as e:
        logger.error("Gemini AI error: %s", type(e).__name__)
        return "SUSPICIOUS", "Could not connect to the AI service right now. Please try again."
 
# --------------------------
# API ENDPOINT (original logic + rate limiting + input validation)
# --------------------------
@app.post("/api/check")
@limiter.limit("5/minute")
def check(request: Request, data: URLQuery):
    url = data.url.strip()
 
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
 
    parsed = urlparse(url)
    host = parsed.hostname or ""
 
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL")
 
    # Block internal/private network scanning
    blocked = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    blocked_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    if host in blocked or any(host.startswith(p) for p in blocked_prefixes):
        raise HTTPException(status_code=400, detail="Invalid URL")
 
    # Fast-path: skip Tavily for well-known safe domains to save API credits
    if is_known_safe(host):
        logger.info("Known safe domain, skipping scan: %s", host)
        return {
            "verdict": "safe",
            "final_score": 0.0,
            "heuristic_reasons": [],
            "ai_research_summary": "This is a well-known, globally trusted website with a strong reputation and no reported issues."
        }
 
    logger.info("Scanning: %s", host)
 
    # Step 1: Run heuristics
    heuristic_score, reasons = run_heuristics(url, host)
 
    # Step 2: Tavily hunts Reddit/Trustpilot for real user reports
    search_data = search_internet_reviews(host)
 
    # Step 3: Gemini reads those reports and gives a plain-English verdict
    ai_verdict, ai_summary = analyze_reviews_with_ai(host, search_data)
 
    # Step 4: Final verdict — SAFE_WITH_ISSUES = legit site with complaints, not a scam
    if heuristic_score >= 0.8 or ai_verdict == "PHISHY":
        verdict = "phishy"
    elif heuristic_score >= 0.4 or ai_verdict == "SUSPICIOUS":
        verdict = "suspicious"
    elif ai_verdict == "SAFE_WITH_ISSUES":
        verdict = "safe_with_issues"
    else:
        verdict = "safe"
 
    logger.info("Verdict for %s: %s (heuristic=%.2f, ai=%s)", host, verdict, heuristic_score, ai_verdict)
 
    return {
        "verdict": verdict,
        "final_score": round(heuristic_score, 2),
        "heuristic_reasons": reasons,
        "ai_research_summary": ai_summary
    }

class ReportRequest(BaseModel):
    url: str
    verdict: str
    reason: str = ""

@app.post("/api/report")
@limiter.limit("5/minute")
def report_verdict(request: Request, data: ReportRequest):
    """Allows users to report when the AI gets it wrong."""
    # Append to a local file (in a real app, this would go to a database)
    with open("reports.log", "a") as f:
        f.write(f"REPORT: {data.url} was marked as {data.verdict} - Reason: {data.reason}\n")
    logger.info("User reported incorrect verdict for %s (was marked %s) - Reason: %s", data.url, data.verdict, data.reason)
    return {"status": "success", "message": "Report submitted."}