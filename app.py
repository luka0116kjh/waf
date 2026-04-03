import ipaddress
import logging
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from zeroscan_waf import ZeroScanWAF

app = FastAPI(title="ZeroScan Sentinel API")
logger = logging.getLogger(__name__)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize WAF
waf = ZeroScanWAF(risk_threshold=0.8)

# Serve static files
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class ScanRequest(BaseModel):
    url: str

class PayloadRequest(BaseModel):
    content: str


def _is_disallowed_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        ]
    )


def _validate_public_scan_target(raw_url: str) -> str:
    normalized_url = raw_url.strip()
    parsed = urlparse(normalized_url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Only valid http/https URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo is not allowed in scan targets.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Could not determine the target host.")
    if hostname.lower() == "localhost":
        raise ValueError("Localhost targets are not allowed.")

    try:
        host_ip = ipaddress.ip_address(hostname)
    except ValueError:
        host_ip = None
    except Exception as exc:
        raise ValueError("Invalid target host.") from exc

    if host_ip and _is_disallowed_ip(str(host_ip)):
        raise ValueError("Private or local network targets are not allowed.")

    default_port = 443 if parsed.scheme == "https" else 80
    try:
        resolved = socket.getaddrinfo(hostname, parsed.port or default_port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target host: {hostname}") from exc

    resolved_ips = {
        item[4][0]
        for item in resolved
        if item[4]
    }
    for address in resolved_ips:
        if _is_disallowed_ip(address):
            raise ValueError("Private or local network targets are not allowed.")

    return normalized_url

@app.get("/")
async def read_index():
    return FileResponse(STATIC_DIR / "index.html")

@app.post("/api/scan")
async def scan_url(request: ScanRequest):
    try:
        target_url = _validate_public_scan_target(request.url)
        result = waf.inspect_website(target_url)
        return {
            "url": result.url,
            "reachable": result.reachable,
            "allowed": result.allowed,
            "alert_message": result.alert_message,
            "matched_rule": result.matched_rule,
            "status_code": result.status_code,
            "risk_score": round(result.risk_score, 3)
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        logger.exception("Unexpected error while scanning URL")
        raise HTTPException(status_code=500, detail="Internal server error while scanning URL.")

@app.post("/api/inspect")
async def inspect_payload(request: PayloadRequest):
    try:
        if not request.content.strip():
            raise HTTPException(status_code=400, detail="Payload content must not be empty.")
        result = waf.inspect(request.content)
        return {
            "allowed": result.allowed,
            "reason": result.reason,
            "risk_score": round(result.risk_score, 3),
            "matched_rule": result.matched_rule
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error while inspecting payload")
        raise HTTPException(status_code=500, detail="Internal server error while inspecting payload.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
