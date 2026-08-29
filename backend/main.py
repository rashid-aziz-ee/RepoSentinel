from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sys
import os
import sqlite3
import uvicorn
from pydantic import BaseModel
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection_engine.analyzer import analyze_input

app = FastAPI(title="RepoSentinel API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reposentinel.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_type TEXT,
            content_snippet TEXT,
            risk_score INTEGER,
            verdict TEXT,
            flags TEXT,
            explanation TEXT,
            sanitized_content TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize Database on startup
init_db()

class AnalyzeRequest(BaseModel):
    source_type: str
    content: str

@app.post("/api/analyze")
async def analyze_endpoint(request: AnalyzeRequest):
    result = analyze_input(request.source_type, request.content)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    snippet = request.content[:100] + "..." if len(request.content) > 100 else request.content
    flags_str = ",".join(result["flags"])
    sanitized = result.get("sanitized_content", request.content)
    
    # Save to SQLite Database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, source_type, content_snippet, risk_score, verdict, flags, explanation, sanitized_content)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, request.source_type, snippet, result["risk_score"], result["verdict"], flags_str, result["explanation"], sanitized))
    conn.commit()
    conn.close()
    
    return result

@app.get("/api/logs")
async def get_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 100')
    rows = c.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_type": row["source_type"],
            "content_snippet": row["content_snippet"],
            "risk_score": row["risk_score"],
            "verdict": row["verdict"],
            "flags": row["flags"].split(",") if row["flags"] else [],
            "explanation": row["explanation"],
            "sanitized_content": row["sanitized_content"]
        })
        
    return {"logs": logs}

@app.delete("/api/logs/{log_id}")
async def delete_log(log_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM logs WHERE id = ?', (log_id,))
    conn.commit()
    conn.close()
    return {"message": "Log deleted"}

@app.delete("/api/logs")
async def clear_all_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM logs')
    conn.commit()
    conn.close()
    return {"message": "All logs cleared"}

if __name__ == "__main__":
    print("Starting RepoSentinel Backend API on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)

