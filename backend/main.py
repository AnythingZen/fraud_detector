"""
main.py — FastAPI server. Wires data loading, fraud scoring, and AI explanation
together into HTTP endpoints.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd

from engine import FraudEngine
from agent import FraudAgent

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATA_PATH = "data/rba-dataset.csv"
NROWS = 3000  # sample size

# ---------------------------------------------------------------------------
# Shared state (module-level singletons)
# ---------------------------------------------------------------------------

engine = FraudEngine()
fraud_agent = FraudAgent()

decisions: dict[str, str] = {}   # { user_id: "block" | "approve" }
_scored_rows: list[dict] = []     # populated once at startup

# ---------------------------------------------------------------------------
# App + CORS
# ---------------------------------------------------------------------------

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request body schema
# ---------------------------------------------------------------------------

class ReviewBody(BaseModel):
    decision: str   # "block" or "approve"

# ---------------------------------------------------------------------------
# Startup: load + score once
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    """
    load CSV and score every row, store results in _scored_rows.
    """
    df = pd.read_csv(DATA_PATH, nrows=NROWS, dtype=str)
    df = df.fillna("")
    all_rows = df.to_dict("records")
    global _scored_rows

    for row in all_rows:
        score_dict = engine.score_user(row, all_rows)
        row_and_score_dict = {**row, **score_dict}
        _scored_rows.append(row_and_score_dict)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/signups")
def get_signups():
    """
    return the scored rows list.
    FastAPI auto-serializes lists and dicts to JSON.
    """
    global _scored_rows
    return _scored_rows

@app.post("/review/{user_id}")
def post_review(user_id: str, body: ReviewBody):
    """
    save a block/approve decision for a user.
    """
    if body.decision not in ("block", "approve"):
        raise HTTPException(status_code=400, detail="Invalid decision")
    decisions[user_id] = body.decision
    return {"ok": True}

@app.post("/agent/explain/{row_index}")
def post_explain(row_index: str):
    """
    find the specific row by its CSV index and return a Gemini explanation.
    """
    global _scored_rows
    user_row = next((r for r in _scored_rows if r["index"] == row_index), None)
    if user_row is None:
        raise HTTPException(status_code=404, detail="Row not found")
    explanation = fraud_agent.explain(user_row, user_row["triggers"])
    return {"explanation": explanation}

@app.get("/stats")
def get_stats():
    """
    return aggregate fraud stats.
    """
    global _scored_rows
    total = len(_scored_rows)
    flagged = sum(1 for r in _scored_rows if r["status"] == "flagged")
    blocked = sum(1 for r in _scored_rows if r["status"] == "blocked")
    fraud_rate = round((flagged + blocked)/total, 2) if total > 0 else 0

    return {"total": total, "flagged": flagged, "blocked": blocked, "fraud_rate": fraud_rate}