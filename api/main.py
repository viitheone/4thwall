"""
FastAPI service for WAF scoring.
Loads WAFClassifier on startup; validates input; CORS for local testing.
"""

import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.dashboard import router as dashboard_router
from api.schemas import BatchScoreRequest, BatchScoreResponse, ScoreRequest, ScoreResponse
from ml.infer import WAFClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="4thwall WAF API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

classifier: WAFClassifier | None = None

app.include_router(dashboard_router)


@app.on_event("startup")
def startup():
    global classifier
    model_path = os.environ.get("MODEL_PATH", "./models/waf_model")
    if os.path.exists(model_path):
        classifier = WAFClassifier(model_path)
        logger.info("WAFClassifier loaded from %s", model_path)
    else:
        classifier = None
        logger.warning("Model path %s not found; /score endpoints will return 503", model_path)
    app.state.waf_classifier = classifier


@app.get("/health")
def health():
    """Returns model status."""
    return {
        "status": "ok",
        "model_loaded": classifier is not None,
    }


@app.post("/score", response_model=ScoreResponse)
def score(request: ScoreRequest):
    """Score a single serialized request."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    try:
        result = classifier.predict(request.request_text)
        logger.info("score request -> %s (score=%.4f)", result["label"], result["score"])
        return ScoreResponse(**result)
    except Exception as e:
        logger.exception("score error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/score_batch", response_model=BatchScoreResponse)
def score_batch(request: BatchScoreRequest):
    """Score a batch of serialized requests."""
    if classifier is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    try:
        results = classifier.predict_batch(request.requests)
        for i, r in enumerate(results):
            logger.info("score_batch[%d] -> %s (score=%.4f)", i, r["label"], r["score"])
        return BatchScoreResponse(results=[ScoreResponse(**r) for r in results])
    except Exception as e:
        logger.exception("score_batch error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
