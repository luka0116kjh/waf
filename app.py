from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import os
from zeroscan_waf import ZeroScanWAF

app = FastAPI(title="ZeroScan Sentinel API")

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
if not os.path.exists("static"):
    os.makedirs("static")

app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    url: str

class PayloadRequest(BaseModel):
    content: str

@app.get("/")
async def read_index():
    return FileResponse("static/index.html")

@app.post("/api/scan")
async def scan_url(request: ScanRequest):
    try:
        result = waf.inspect_website(request.url)
        return {
            "url": result.url,
            "reachable": result.reachable,
            "allowed": result.allowed,
            "alert_message": result.alert_message,
            "matched_rule": result.matched_rule,
            "status_code": result.status_code,
            "risk_score": round(result.risk_score, 3)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/inspect")
async def inspect_payload(request: PayloadRequest):
    try:
        result = waf.inspect(request.content)
        return {
            "allowed": result.allowed,
            "reason": result.reason,
            "risk_score": round(result.risk_score, 3),
            "matched_rule": result.matched_rule
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
