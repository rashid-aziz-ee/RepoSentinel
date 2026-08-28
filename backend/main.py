from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sys
import os
import uvicorn
from pydantic import BaseModel
from datetime import datetime

# Add root folder to sys.path so we can import detection_engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection_engine.analyzer import analyze_input

app = FastAPI(title="RepoSentinel API")

# Allow Dashboard to connect to API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for dashboard logs (Person C requirement)
intercept_logs = []

class AnalyzeRequest(BaseModel):
    source_type: str
    content: str

@app.post("/api/analyze")
async def analyze_endpoint(request: AnalyzeRequest):
    """
    Main endpoint for Person B (Interception Layer) to call.
    Analyzes the text and logs the event for the dashboard.
    """
    # Call Person A's Detection Engine
    result = analyze_input(request.source_type, request.content)
    
    # Save to logs for the dashboard
    log_entry = {
        "id": len(intercept_logs) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_type": request.source_type,
        "content_snippet": request.content[:100] + "..." if len(request.content) > 100 else request.content,
        "risk_score": result["risk_score"],
        "verdict": result["verdict"],
        "flags": result["flags"],
        "explanation": result["explanation"]
    }
    intercept_logs.insert(0, log_entry) # Add to beginning of list
    
    return result

@app.get("/api/logs")
async def get_logs():
    """
    Endpoint for Dashboard (Person C) to fetch live interception logs.
    """
    return {"logs": intercept_logs}

if __name__ == "__main__":
    print("Starting RepoSentinel Backend API on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
