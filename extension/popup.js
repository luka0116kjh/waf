async function loadSettings() {
    const response = await chrome.runtime.sendMessage({ type: "getSettings" });
    if (!response?.ok) {
        throw new Error(response?.error || "Failed to load settings.");
    }

    const settings = response.settings;
    document.getElementById("modeAlert").checked = settings.mode !== "block";
    document.getElementById("modeBlock").checked = settings.mode === "block";
    document.getElementById("allowedDomainsInfo").textContent = `허용된 도메인: ${settings.allowedDomains.length}개`;
    document.getElementById("statusText").textContent = "";
}

async function updateMode(mode) {
    const statusText = document.getElementById("statusText");
    statusText.textContent = "설정을 저장하는 중...";

    const response = await chrome.runtime.sendMessage({ type: "setMode", mode });
    if (!response?.ok) {
        statusText.textContent = response?.error || "설정 저장 실패";
        return;
    }

    statusText.textContent = mode === "block" ? "차단 모드가 활성화되었습니다." : "알림 모드가 활성화되었습니다.";
    await loadSettings();
}

document.getElementById("modeAlert").addEventListener("change", () => updateMode("alert"));
document.getElementById("modeBlock").addEventListener("change", () => updateMode("block"));

loadSettings().catch((error) => {
    document.getElementById("statusText").textContent = error.message;
});
