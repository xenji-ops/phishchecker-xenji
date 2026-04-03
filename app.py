from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from urllib.parse import urlparse
import re
import math
import requests
from google import genai
import os # <-- NEW
from dotenv import load_dotenv # <-- NEW

# --- SETUP API KEYS ---
load_dotenv() # <-- This tells Python to secretly load the .env file

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY") # <-- Now it grabs the hidden key
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY")) # <-- Grabs the hidden key

app = FastAPI()

# ... (the rest of your code stays exactly the same) ...

# Serve static CSS and JS
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

@app.get("/ping")
def ping():
    return {"status": "ok"}

# --------------------------
# MODELS
# --------------------------
class URLQuery(BaseModel):
    url: str

# --------------------------
# 1. HEURISTICS (Relaxed & Smarter Math)
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
    
    # Major Red Flags (High Score)
    if "@" in url:
        score += 0.8
        reasons.append("Contains an '@' symbol (Hackers use this to hide fake domains).")
    if is_ip(host):
        score += 0.8
        reasons.append("Uses an IP address instead of a real name (Very suspicious).")
        
    # Minor Red Flags (Lower Score, won't trigger 'suspicious' on their own)
    if len(url) > 120: 
        score += 0.2
        reasons.append("The website link is unusually long.")
    if entropy(host) > 4.0: 
        score += 0.2
        reasons.append("The website name looks like random gibberish.")
        
    return score, reasons

# --------------------------
# 2. OSINT SEARCH (Better Social Media Hunting)
# --------------------------
def search_internet_reviews(domain: str):
    # This query specifically hunts for people complaining on Reddit or Trustpilot
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
        response = requests.post(url, json=payload)
        data = response.json()
        return [result['content'] for result in data.get('results', [])]
    except Exception as e:
        print("Search failed:", e)
        return []

# --------------------------
# 3. AI ANALYSIS (The "Explain it to me like I'm 5" Brain)
# --------------------------
def analyze_reviews_with_ai(domain: str, search_results: list):
    context = "\n".join(search_results) if search_results else "No reviews found."
    
    prompt = f"""
    You are a friendly cybersecurity guard helping a beginner who knows nothing about tech.
    Your job is to read these real internet comments (from Reddit/Trustpilot) about the website '{domain}'.
    
    RULES:
    1. If the domain is a famous, obviously safe company (like google, github, amazon, apple, netflix), you MUST output 'VERDICT: SAFE'.
    2. If people are complaining about losing money or not getting products, output 'VERDICT: PHISHY'.
    3. If there are no search results, DO NOT automatically call it suspicious. Just say there isn't much information yet.
    
    You MUST format your response exactly like this:
    VERDICT: [Choose one: SAFE, SUSPICIOUS, or PHISHY]
    SUMMARY: [Write 2 very simple sentences explaining what real people on the internet are saying. If it's safe, reassure them. If it's a scam, tell them exactly what people lost.]
    
    Search Results from Reddit/Trustpilot:
    {context}
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash', 
            contents=prompt
        )
        text = response.text
        
        # Extract the secret AI verdict
        ai_verdict = "SAFE"
        if "VERDICT: PHISHY" in text.upper():
            ai_verdict = "PHISHY"
        elif "VERDICT: SUSPICIOUS" in text.upper():
            ai_verdict = "SUSPICIOUS"
            
        # Extract the human-friendly summary
        if "SUMMARY:" in text:
            summary = text.split("SUMMARY:")[-1].strip()
        else:
            summary = text
            
        return ai_verdict, summary
        
    except Exception as e:
        print("AI Error:", e)
        return "SAFE", "Could not connect to the internet to check reviews right now."

# --------------------------
# API ENDPOINT (The Final Judge)
# --------------------------
@app.post("/api/check")
def check(data: URLQuery):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL")

    # Step 1: Run the relaxed math
    heuristic_score, reasons = run_heuristics(url, host)

    # Step 2: Hunt on Reddit/Trustpilot
    search_data = search_internet_reviews(host)
    
    # Step 3: Let the AI decide and explain in simple English
    ai_verdict, ai_summary = analyze_reviews_with_ai(host, search_data)
    
    # Step 4: The Final Verdict logic
    if heuristic_score >= 0.8 or ai_verdict == "PHISHY":
        verdict = "phishy"
    elif heuristic_score >= 0.4 or ai_verdict == "SUSPICIOUS":
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "verdict": verdict,
        "final_score": round(heuristic_score, 2),
        "heuristic_reasons": reasons,
        "ai_research_summary": ai_summary 
    }