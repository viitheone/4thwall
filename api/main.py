import logging
import os

import json
import time
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

from api.dashboard import router as dashboard_router
from api.schemas import BatchScoreRequest, BatchScoreResponse, ScoreRequest, ScoreResponse
from ml.infer import WAFClassifier
from ml.preprocess import serialize_request
from policy.decision import make_decision

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



DVWA_URL = os.environ.get("DVWA_URL", "http://dvwa:80")
DECISION_LOG_PATH = os.environ.get("DECISION_LOG", "logs/decision_log.json")

def append_decision(entry: dict) -> None:
    os.makedirs(os.path.dirname(DECISION_LOG_PATH), exist_ok=True)
    with open(DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

http_client = httpx.AsyncClient(timeout=30.0)

@app.on_event("shutdown")
async def shutdown():
    await http_client.aclose()


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def reverse_proxy(request: Request, path: str):
    """Inline WAF blocking and proxying."""
    start_time = time.time()
    
    query_string = request.url.query
    user_agent = request.headers.get("user-agent", "")
    method = request.method
    uri = "/" + path
    if query_string:
        uri += "?" + query_string
        
    start_time_iso = datetime.utcnow().isoformat() + "Z"
    
    row = {
        "method": method,
        "path": uri,
        "query": query_string,
        "status": 200, 
        "user_agent": user_agent,
        "request_time": 0.0,
    }
    
    request_text = serialize_request(row)
    
    ml_score = 0.0
    if classifier is not None:
        try:
            result = classifier.predict(request_text)
            ml_score = result["score"]
        except Exception as e:
            logger.error(f"Error scoring request: {e}")
            
    decision = make_decision(modsecurity_blocked=False, ml_score=ml_score)
    action = decision["action"]
    reason = decision["reason"]
    
    if action == "BLOCK":
        row["status"] = 403
        row["request_time"] = time.time() - start_time
        entry = {
            "timestamp": start_time_iso,
            "request_text": serialize_request(row),
            "modsecurity_blocked": False,
            "ml_score": ml_score,
            "action": action,
            "reason": reason,
        }
        append_decision(entry)
        
        nginx_403 = (
            "<html>\r\n"
            "<head><title>403 Forbidden</title></head>\r\n"
            "<body>\r\n"
            "<center><h1>403 Forbidden</h1></center>\r\n"
            "<hr><center>nginx</center>\r\n"
            "</body>\r\n"
            "</html>\r\n"
        )
        return HTMLResponse(status_code=403, content=nginx_403)

    target_url = f"{DVWA_URL}/{path}"
    if query_string:
         target_url += "?" + query_string
         
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    
    try:
        proxy_resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body
        )
    except httpx.RequestError as exc:
        logger.error(f"Proxy error connecting to {exc.request.url}: {exc}")
        return JSONResponse(status_code=502, content={"error": "Bad Gateway"})
        
    row["status"] = proxy_resp.status_code
    row["request_time"] = time.time() - start_time
    
    entry = {
        "timestamp": start_time_iso,
        "request_text": serialize_request(row),
        "modsecurity_blocked": False,
        "ml_score": ml_score,
        "action": action,
        "reason": reason,
    }
    append_decision(entry)
    
    resp_headers = dict(proxy_resp.headers)
    resp_headers.pop("content-encoding", None)
    resp_headers.pop("content-length", None)
    
    return Response(
        content=proxy_resp.content,
        status_code=proxy_resp.status_code,
        headers=resp_headers
    )
