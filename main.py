"""
main.py — FastAPI entry point for the Anti-Phishing App.

Endpoints
---------
POST /check          – score a single URL
POST /check/batch    – score multiple URLs in one request
GET  /history        – retrieve recent analysis history
GET  /stats          – summary statistics over history
DELETE /history      – clear the history cache
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, validator
from typing import List, Optional

from model import PhishingScorer

# App & scorer

app = FastAPI(
    title="Anti-Phishing App",
    description="Heuristic-based phishing URL detector with confidence scoring.",
    version="2.0.0",
)
scorer = PhishingScorer(history_size=500)

# Request / response models

class URLRequest(BaseModel):
    url: str

    @validator("url")
    def normalise_url(cls, v: str) -> str:
        """Ensure the URL has a scheme so urlparse works correctly."""
        if not v:
            raise ValueError("URL must not be empty")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


class BatchRequest(BaseModel):
    urls: List[str]

    @validator("urls")
    def must_have_urls(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one URL is required")
        if len(v) > 100:
            raise ValueError("Maximum 100 URLs per batch request")
        return v


class AnalysisResponse(BaseModel):
    url: str
    verdict: str
    confidence: float
    signals: List[dict]
    recommendation: str


class BatchResponse(BaseModel):
    results: List[AnalysisResponse]
    summary: dict


class HistoryResponse(BaseModel):
    results: List[AnalysisResponse]


class StatsResponse(BaseModel):
    total: int
    verdicts: dict
    average_confidence: float

# Endpoints

@app.post("/check", response_model=AnalysisResponse)
def check_url(request: URLRequest):
    """Analyse a single URL and return a verdict with confidence score."""
    result = scorer.score(request.url)
    return AnalysisResponse(**vars(result))


@app.post("/check/batch", response_model=BatchResponse)
def check_batch(request: BatchRequest):
    """Analyse up to 100 URLs in a single request."""
    results = scorer.score_batch(request.urls)
    verdicts = {}
    for r in results:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1

    return BatchResponse(
        results=[AnalysisResponse(**vars(r)) for r in results],
        summary={"total": len(results), "verdicts": verdicts},
    )


@app.get("/history", response_model=HistoryResponse)
def get_history(limit: Optional[int] = None):
    """Return recent analysis results (most recent first)."""
    history = scorer.history(limit)
    history.reverse()
    return HistoryResponse(results=[AnalysisResponse(**vars(r)) for r in history])


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Return summary statistics over all cached analyses."""
    s = scorer.stats()
    return StatsResponse(**s)


@app.delete("/history")
def clear_history():
    """Discard all cached analysis results."""
    scorer.clear_history()
    return {"detail": "History cleared"}
