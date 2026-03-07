# ZeroScan Sentinel

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](README.md)
[![Korean](https://img.shields.io/badge/lang-한국어-red?style=flat-square)](README.ko.md)

ZeroScan Sentinel is a real-time web threat detection project that combines a FastAPI-based WAF (Web Application Firewall) analysis server with a Chrome extension.

The extension operates in `Alert Mode` by default, displaying a warning banner at the top of the page when a threat is detected. If necessary, you can switch to `Block Mode` via the extension popup to redirect malicious sites to a dedicated blocking page.

## Key Features

- **Real-time URL Inspection**: The Chrome extension monitors main frame navigation and requests URL scans from the local WAF API.
- **Alert Mode**: (Default) Displays a warning banner on the page when a threat is detected.
- **Block Mode**: Redirects the user to an internal blocking page when a threat is detected.
- **Whitelisting**: In `Block Mode`, users can choose "Continue once" or "Always allow this domain."
- **Direct Payload Inspection**: Test URLs or text payloads directly through the web dashboard UI.
- **Hybrid Detection**: Combines static pattern matching with a lightweight risk scoring system.

## Quick Start

### 1. Install Python Packages

```powershell
pip install fastapi uvicorn
```

### 2. Run API Server

```powershell
python app.py
```

The server runs at `http://127.0.0.1:8000` by default.

### 3. Load Chrome Extension

1. Go to `chrome://extensions/` in Chrome.
2. Enable **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `extension` folder of this project.

The extension connects to `http://127.0.0.1:8000/api/scan`. Ensure `python app.py` is running for the extension to work.
After modifying the extension code, click the **refresh icon** on the extension card.

## Usage

### Web Dashboard

- Access `http://127.0.0.1:8000` in your browser.
- Enter a URL to analyze.
- Or paste text/payloads directly to inspect.

### Extension

- Default is **Alert Mode**.
- Toggle to **Block Mode** in the popup.
- In Block Mode, accessing a risky page redirects to the block page.
- Decisions on the block page:
  - `Continue this time`
  - `Always allow this domain`
  - `Go to previous page`
  - `Close tab`

## Recommended Testing Procedure

1. Run `python app.py` in your terminal.
2. Verify access to `http://127.0.0.1:8000`.
3. Ensure the extension is loaded in `chrome://extensions/`.
4. Refresh the extension if needed.
5. Visit a test URL and check for alert or block behavior.

## How It Works

### Backend

- **`app.py`**: Executes the FastAPI server.
  - `/api/scan`: Inspects a website URL.
  - `/api/inspect`: Inspects a text payload.
- **`zeroscan_waf.py`**:
  - Checks for SQLi, XSS, and LFI patterns.
  - Performs URL validation.
  - Detects high-risk active patterns in web responses.

### Frontend

- `static/index.html`
- `static/script.js`
- `static/style.css`

A dashboard where you can manually test URLs and payloads.

### Chrome Extension

- **`extension/background.js`**: Monitors page navigation, handles alerts/blocking, and manages whitelists.
- **`extension/popup.html` / `popup.js`**: UI to switch between Alert and Block modes.
- **`extension/blocked.html` / `blocked.js`**: Redirection page for Block Mode.

## Current Limitations

- `/api/scan` structure is vulnerable to SSRF as the server visits the URL directly.
- Detection accuracy is at a demo level; false positives and false negatives may occur.
- Local API server must be running for the extension to function.

## Project Structure

```text
waf/
|-- app.py
|-- zeroscan_waf.py
|-- README.md
|-- README_KR.md
|-- static/
|   |-- index.html
|   |-- script.js
|   `-- style.css
`-- extension/
    |-- background.js
    |-- blocked.html
    |-- blocked.js
    |-- manifest.json
    |-- popup.html
    `-- popup.js
```

## Disclaimer

This project is a security detection tool for educational and prototyping purposes. For production use, additional features such as SSRF protection, precise policy design, log management, and improved detection accuracy are required.
