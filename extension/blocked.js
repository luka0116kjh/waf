function getParam(name, fallback = "-") {
    return new URLSearchParams(window.location.search).get(name) || fallback;
}

function getHostname(targetUrl) {
    try {
        return new URL(targetUrl).hostname;
    } catch {
        return "this site";
    }
}

async function getCurrentTabId() {
    const currentTab = await chrome.tabs.getCurrent();
    return currentTab?.id || 0;
}

async function sendBypassMessage(type) {
    const targetUrl = getParam("url", "");
    const tabId = await getCurrentTabId();
    const feedback = document.getElementById("feedback");

    if (!targetUrl || !tabId) {
        feedback.textContent = "Could not determine the blocked tab.";
        return;
    }

    feedback.textContent = "Applying your selection...";
    const response = await chrome.runtime.sendMessage({ type, url: targetUrl, tabId });
    feedback.textContent = response?.ok ? "Redirecting..." : (response?.error || "Request failed.");
}

const blockedUrl = getParam("url");
document.getElementById("blockedUrl").textContent = blockedUrl;
document.getElementById("riskScore").textContent = `${getParam("score", "0")}%`;
document.getElementById("matchedRule").textContent = getParam("rule");
document.getElementById("statusCode").textContent = getParam("status");
document.getElementById("message").textContent = getParam("message");
document.getElementById("allowDomainBtn").textContent = `${getHostname(blockedUrl)} 도메인 허용`;

document.getElementById("continueBtn").addEventListener("click", () => {
    sendBypassMessage("continueOnce");
});

document.getElementById("allowDomainBtn").addEventListener("click", () => {
    sendBypassMessage("allowDomain");
});

document.getElementById("goBackBtn").addEventListener("click", () => {
    window.history.back();
});

document.getElementById("closeTabBtn").addEventListener("click", async () => {
    const tabId = await getCurrentTabId();
    if (tabId) {
        chrome.tabs.remove(tabId);
        return;
    }

    window.close();
});
