async function checkURL() {
    const url = document.getElementById("url").value;
    const resultDiv = document.getElementById("result");

    resultDiv.classList.remove("hidden");
    resultDiv.innerHTML = "Analyzing threat profile...";

    const res = await fetch("/api/check", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    });

    const data = await res.json();

    let color = data.verdict;

    resultDiv.innerHTML = `
        <h2 class="${color}">${data.verdict.toUpperCase()}</h2>
        <p><strong>Risk Score:</strong> ${data.final_score}</p>

        <div class="analysis">
            <h4>Threat Indicators</h4>
            <ul>
                ${data.heuristic_reasons.map(r => `<li>${r}</li>`).join("")}
            </ul>
        </div>
    `;
}