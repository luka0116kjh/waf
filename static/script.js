document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const mainLoader = document.getElementById('mainLoader');
    const resultSection = document.getElementById('resultSection');
    
    // UI Elements for results
    const statusBadge = document.getElementById('statusBadge');
    const urlDisplay = document.getElementById('urlDisplay');
    const scorePath = document.getElementById('scorePath');
    const scoreText = document.getElementById('scoreText');
    const resReachable = document.getElementById('resReachable');
    const resAllowed = document.getElementById('resAllowed');
    const resRule = document.getElementById('resRule');
    const resStatus = document.getElementById('resStatus');
    const alertBox = document.getElementById('alertBox');
    const alertMessage = document.getElementById('alertMessage');
    const alertIcon = document.getElementById('alertIcon');

    // Payload testing elements
    const payloadInput = document.getElementById('payloadInput');
    const inspectBtn = document.getElementById('inspectBtn');
    const payloadResult = document.getElementById('payloadResult');

    const updateScoreRing = (score) => {
        const percentage = Math.round(score * 100);
        scorePath.style.strokeDasharray = `${percentage}, 100`;
        scoreText.textContent = `${percentage}%`;
        
        let color = '#10b981'; // safe
        if (score >= 0.8) color = '#ef4444'; // danger
        else if (score >= 0.4) color = '#f59e0b'; // warning
        
        scorePath.style.stroke = color;
    };

    const performScan = async () => {
        const url = urlInput.value.trim();
        if (!url) return alert('URL을 입력해 주세요.');

        // UI Reset
        scanBtn.disabled = true;
        mainLoader.style.display = 'block';
        document.querySelector('.btn-text').style.opacity = '0.5';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();
            
            // Show result section
            resultSection.classList.remove('hidden');
            resultSection.scrollIntoView({ behavior: 'smooth' });

            // Update UI
            urlDisplay.textContent = data.url;
            resReachable.textContent = data.reachable ? '정상 접속됨' : '접속 실패';
            resAllowed.textContent = data.allowed ? '안전함' : '위험 탐지됨';
            resRule.textContent = data.matched_rule || '없음';
            resStatus.textContent = data.status_code || '-';
            alertMessage.textContent = data.alert_message;

            if (data.allowed) {
                statusBadge.textContent = 'SAFE';
                statusBadge.className = 'status-badge status-safe';
                alertIcon.textContent = '✅';
                alertBox.style.borderLeft = '4px solid #10b981';
            } else {
                statusBadge.textContent = 'DANGER';
                statusBadge.className = 'status-badge status-danger';
                alertIcon.textContent = '⚠️';
                alertBox.style.borderLeft = '4px solid #ef4444';
            }

            updateScoreRing(data.risk_score);

        } catch (error) {
            console.error('Scan failed:', error);
            alert('검사 중 네트워크 오류가 발생했습니다.');
        } finally {
            scanBtn.disabled = false;
            mainLoader.style.display = 'none';
            document.querySelector('.btn-text').style.opacity = '1';
        }
    };

    const inspectPayload = async () => {
        const content = payloadInput.value.trim();
        if (!content) return;

        inspectBtn.disabled = true;
        payloadResult.textContent = '분석 중...';

        try {
            const response = await fetch('/api/inspect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content })
            });

            const data = await response.json();
            const color = data.allowed ? '#10b981' : '#ef4444';
            const status = data.allowed ? 'Safe' : 'Malicious';
            
            payloadResult.innerHTML = `<span style="color: ${color}; font-weight: bold;">${status}</span> (Score: ${data.risk_score})`;
        } catch (error) {
            payloadResult.textContent = '오류 발생';
        } finally {
            inspectBtn.disabled = false;
        }
    };

    scanBtn.addEventListener('click', performScan);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performScan();
    });

    inspectBtn.addEventListener('click', inspectPayload);
});
