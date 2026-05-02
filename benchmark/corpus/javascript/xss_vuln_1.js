// VULN: CWE-79 — DOM-based XSS via innerHTML with URL parameter
function showGreeting() {
    const urlParams = new URLSearchParams(window.location.search);
    const name = urlParams.get('name') || 'World';
    document.getElementById('greeting').innerHTML = 'Hello, ' + name;
}

window.onload = showGreeting;
