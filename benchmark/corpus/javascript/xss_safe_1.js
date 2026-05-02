// SAFE: textContent instead of innerHTML; server side uses escaping
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function showGreeting() {
    const urlParams = new URLSearchParams(window.location.search);
    const name = urlParams.get('name') || 'World';
    document.getElementById('greeting').textContent = 'Hello, ' + name;
}

window.onload = showGreeting;
