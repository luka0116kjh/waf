const WAF_API_URL = "http://127.0.0.1:8000/api/scan";
const BLOCKED_PAGE = "blocked.html";
const EXTENSION_PREFIX = `chrome-extension://${chrome.runtime.id}/`;
const DEFAULT_SETTINGS = {
    mode: "alert",
    allowedDomains: [],
    temporaryBypasses: {}
};

async function getSettings() {
    const settings = await chrome.storage.local.get(DEFAULT_SETTINGS);
    const now = Date.now();
    const bypasses = settings.temporaryBypasses || {};
    const activeBypasses = Object.fromEntries(
        Object.entries(bypasses).filter(([, expiresAt]) => Number(expiresAt) > now)
    );

    if (Object.keys(activeBypasses).length !== Object.keys(bypasses).length) {
        settings.temporaryBypasses = activeBypasses;
        await chrome.storage.local.set({ temporaryBypasses: activeBypasses });
    }

    return {
        mode: settings.mode || DEFAULT_SETTINGS.mode,
        allowedDomains: Array.isArray(settings.allowedDomains) ? settings.allowedDomains : [],
        temporaryBypasses: activeBypasses
    };
}

async function initializeDefaults() {
    const settings = await getSettings();
    await chrome.storage.local.set(settings);
}

function normalizeHostname(targetUrl) {
    try {
        return new URL(targetUrl).hostname.toLowerCase();
    } catch {
        return "";
    }
}

function buildBlockedPageUrl(scanResult) {
    const params = new URLSearchParams({
        url: scanResult.url || "",
        score: String(Math.round((scanResult.risk_score || 0) * 100)),
        message: scanResult.alert_message || "Potentially dangerous site detected.",
        rule: scanResult.matched_rule || "No specific rule",
        status: scanResult.status_code ? String(scanResult.status_code) : "-"
    });

    return `${chrome.runtime.getURL(BLOCKED_PAGE)}?${params.toString()}`;
}

async function isBypassed(targetUrl, settings) {
    const hostname = normalizeHostname(targetUrl);
    if (!hostname) {
        return false;
    }

    if (settings.allowedDomains.includes(hostname)) {
        return true;
    }

    const bypassUntil = Number(settings.temporaryBypasses[targetUrl] || 0);
    return bypassUntil > Date.now();
}

async function showAlertBanner(tabId, scanResult) {
    await chrome.scripting.executeScript({
        target: { tabId },
        args: [scanResult.alert_message || "Potentially dangerous site detected.", Math.round((scanResult.risk_score || 0) * 100)],
        func: (message, score) => {
            const existing = document.getElementById("__zeroscan_alert_banner");
            if (existing) {
                existing.remove();
            }

            const root = document.createElement("div");
            root.id = "__zeroscan_alert_banner";
            root.style.cssText = [
                "position: fixed",
                "top: 0",
                "left: 0",
                "right: 0",
                "z-index: 2147483647",
                "display: flex",
                "align-items: center",
                "justify-content: space-between",
                "gap: 12px",
                "padding: 14px 18px",
                "background: linear-gradient(90deg, #7f1d1d, #b91c1c)",
                "color: #fff",
                "font: 600 14px/1.4 'Segoe UI', sans-serif",
                "box-shadow: 0 10px 30px rgba(0,0,0,0.35)"
            ].join(";");

            const text = document.createElement("div");
            text.textContent = `ZeroScan alert: ${message} (risk ${score}%)`;

            const button = document.createElement("button");
            button.textContent = "Dismiss";
            button.style.cssText = [
                "border: 0",
                "border-radius: 999px",
                "padding: 8px 12px",
                "cursor: pointer",
                "font: inherit",
                "background: rgba(255,255,255,0.16)",
                "color: #fff"
            ].join(";");
            button.addEventListener("click", () => root.remove());

            root.appendChild(text);
            root.appendChild(button);
            document.documentElement.appendChild(root);
        }
    });
}

async function scanAndHandle(details) {
    if (details.frameId !== 0) return;

    const targetUrl = details.url;
    if (
        targetUrl.startsWith("chrome://") ||
        targetUrl.startsWith("http://localhost") ||
        targetUrl.startsWith("https://localhost") ||
        targetUrl.startsWith("http://127.0.0.1") ||
        targetUrl.startsWith("https://127.0.0.1") ||
        targetUrl.startsWith(EXTENSION_PREFIX)
    ) {
        return;
    }

    const settings = await getSettings();
    if (await isBypassed(targetUrl, settings)) {
        return;
    }

    try {
        const response = await fetch(WAF_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl })
        });

        if (!response.ok) {
            throw new Error(`WAF API responded with ${response.status}`);
        }

        const data = await response.json();
        if (data.allowed) {
            return;
        }

        if (settings.mode === "block") {
            await chrome.tabs.update(details.tabId, { url: buildBlockedPageUrl(data) });
            return;
        }

        await showAlertBanner(details.tabId, data);
    } catch (error) {
        console.error("[ZeroScan] Failed to reach the local WAF API.", error);
    }
}

chrome.runtime.onInstalled.addListener(() => {
    initializeDefaults().catch((error) => {
        console.error("[ZeroScan] Failed to initialize defaults.", error);
    });
});

chrome.webNavigation.onCommitted.addListener((details) => {
    scanAndHandle(details).catch((error) => {
        console.error("[ZeroScan] Scan handling failed.", error);
    });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        if (message?.type === "getSettings") {
            sendResponse({ ok: true, settings: await getSettings() });
            return;
        }

        if (message?.type === "setMode") {
            const mode = message.mode === "block" ? "block" : "alert";
            await chrome.storage.local.set({ mode });
            sendResponse({ ok: true, settings: await getSettings() });
            return;
        }

        if (message?.type === "continueOnce") {
            const targetUrl = message.url || "";
            const tabId = Number(message.tabId || 0);
            if (!targetUrl || !tabId) {
                sendResponse({ ok: false, error: "Missing tab or URL." });
                return;
            }

            const settings = await getSettings();
            settings.temporaryBypasses[targetUrl] = Date.now() + (5 * 60 * 1000);
            await chrome.storage.local.set({ temporaryBypasses: settings.temporaryBypasses });
            await chrome.tabs.update(tabId, { url: targetUrl });
            sendResponse({ ok: true });
            return;
        }

        if (message?.type === "allowDomain") {
            const targetUrl = message.url || "";
            const tabId = Number(message.tabId || 0);
            const hostname = normalizeHostname(targetUrl);
            if (!hostname || !tabId) {
                sendResponse({ ok: false, error: "Missing tab or hostname." });
                return;
            }

            const settings = await getSettings();
            const allowedDomains = Array.from(new Set([...settings.allowedDomains, hostname]));
            await chrome.storage.local.set({ allowedDomains });
            await chrome.tabs.update(tabId, { url: targetUrl });
            sendResponse({ ok: true, allowedDomains });
            return;
        }

        sendResponse({ ok: false, error: "Unsupported message type." });
    })().catch((error) => {
        console.error("[ZeroScan] Message handling failed.", error);
        sendResponse({ ok: false, error: String(error) });
    });

    return true;
});
