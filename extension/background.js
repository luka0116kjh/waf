// WAF API 엔드포인트
const WAF_API_URL = "http://localhost:8000/api/scan";

// 페이지 이동 감시
chrome.webNavigation.onCommitted.addListener(async (details) => {
    // 메인 프레임 이동만 체크 (이미지, 프레임 제외)
    if (details.frameId !== 0) return;

    const url = details.url;

    // localhost나 chrome 자체 페이지는 제외
    if (url.startsWith("chrome://") || url.startsWith("http://localhost")) return;

    console.log(`[ZeroScan] 실시간 검사 중: ${url}`);

    try {
        const response = await fetch(WAF_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!data.allowed) {
            console.warn(`[ZeroScan] 위험 감지! 위험 점수: ${data.risk_score}`);

            // 사용자에게 경고 알림 (브라우저 상단)
            chrome.scripting.executeScript({
                target: { tabId: details.tabId },
                func: (msg, score) => {
                    const div = document.createElement('div');
                    div.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; 
            background: #ef4444; color: white; padding: 15px; 
            z-index: 999999; text-align: center; font-weight: bold;
            font-family: sans-serif; box-shadow: 0 4px 10px rgba(0,0,0,0.3);
          `;
                    div.innerHTML = ` ZeroScan 경고: ${msg} (위험 지수: ${Math.round(score * 100)}%) 
                          <button id="close-waf-alert" style="margin-left: 20px; cursor: pointer;">닫기</button>`;
                    document.body.appendChild(div);
                    document.getElementById('close-waf-alert').onclick = () => div.remove();
                },
                args: [data.alert_message, data.risk_score]
            });
        }
    } catch (error) {
        console.error("[ZeroScan] API 접속 오류. 서버가 켜져 있는지 확인하세요.");
    }
});
