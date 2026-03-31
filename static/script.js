document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');

    // State Elements
    const loadingState = document.getElementById('loading-state');
    const errorState = document.getElementById('error-state');
    const resultsState = document.getElementById('results-state');

    // Data Elements
    const verdictBanner = document.getElementById('verdict-banner');
    const verdictTitle = document.getElementById('verdict-title');
    const scoreText = document.getElementById('score-text');
    const aiSummaryText = document.getElementById('ai-summary-text');
    const reasonsList = document.getElementById('reasons-list');
    const errorText = document.getElementById('error-text');

    scanBtn.addEventListener('click', performScan);
    
    // Allow pressing "Enter" in the input box
    urlInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            performScan();
        }
    });

    async function performScan() {
        const url = urlInput.value.trim();
        
        if (!url) {
            showError("Please enter a URL to scan.");
            return;
        }

        // 1. Reset UI and Show Loading
        hideAllStates();
        loadingState.classList.remove('hidden');

        try {
            // 2. Call the FastAPI Backend
            const response = await fetch('/api/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) {
                throw new Error("Failed to connect to the analysis engine.");
            }

            const data = await response.json();

            // 3. Populate Results
            populateResults(data);

            // 4. Show Results
            hideAllStates();
            resultsState.classList.remove('hidden');

        } catch (error) {
            hideAllStates();
            showError(error.message);
        }
    }

    function populateResults(data) {
        // Clear previous formatting
        verdictBanner.className = 'result-banner'; 
        
        // Set Verdict Banner Color & Text
        if (data.verdict.toLowerCase() === 'safe' || data.verdict.toLowerCase() === 'likely safe') {
            verdictBanner.classList.add('is-safe');
            verdictTitle.innerText = "Likely Safe";
        } else if (data.verdict.toLowerCase() === 'suspicious') {
            verdictBanner.classList.add('is-suspicious');
            verdictTitle.innerText = "Suspicious";
        } else {
            verdictBanner.classList.add('is-phishy');
            verdictTitle.innerText = "Phishy / Scam";
        }

        // Set Math Score
        scoreText.innerText = data.final_score;

        // Set AI Summary
        aiSummaryText.innerText = data.ai_research_summary || "No AI summary available.";

        // Set Heuristics List
        reasonsList.innerHTML = ''; // Clear old list
        if (data.heuristic_reasons && data.heuristic_reasons.length > 0) {
            data.heuristic_reasons.forEach(reason => {
                const li = document.createElement('li');
                li.innerText = reason;
                reasonsList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.innerText = "No technical red flags detected.";
            reasonsList.appendChild(li);
        }
    }

    function hideAllStates() {
        loadingState.classList.add('hidden');
        errorState.classList.add('hidden');
        resultsState.classList.add('hidden');
    }

    function showError(message) {
        errorText.innerText = message;
        errorState.classList.remove('hidden');
    }
});