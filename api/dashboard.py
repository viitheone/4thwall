"""
Dashboard API: summary, live traffic, attack distribution, top attackers, AI status.
Serves the React dashboard; can read from decision_log when mounted, else returns mock data.
"""

import json
import os
from collections import defaultdict
from pathlib import Path

from fastapi import APIRouter, Request

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

DECISION_LOG_PATH = os.environ.get("DECISION_LOG", "logs/decision_log.json")


def _read_decision_log(max_lines: int = 200) -> list[dict]:
    """Read last max_lines from decision_log.json (one JSON object per line)."""
    path = Path(DECISION_LOG_PATH)
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        lines = lines[-max_lines:] if len(lines) > max_lines else lines
        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
    except OSError:
        return []


def _parse_request_text(text: str) -> dict:
    """Parse serialized request_text into method, path, etc."""
    result = {"method": "GET", "path": "/", "status": 200}
    for part in text.split("\n"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().upper()
            if k == "METHOD":
                result["method"] = v.strip()
            elif k == "PATH":
                result["path"] = v.strip() or "/"
            elif k == "STATUS":
                try:
                    result["status"] = int(v.strip())
                except ValueError:
                    pass
    return result


@router.get("/summary")
def get_summary():
    """Total requests, benign/malicious counts, accuracy (for dashboard)."""
    entries = _read_decision_log()
    if not entries:
        return {
            "totalRequests": 0,
            "benignRequests": 0,
            "maliciousRequests": 0,
            "accuracy": 0.0,
        }
    total = len(entries)
    benign = sum(1 for e in entries if e.get("action") == "ALLOW" and (e.get("ml_score") or 0) < 0.6)
    malicious = total - benign
    correct = sum(
        1 for e in entries
        if (e.get("action") == "BLOCK" and (e.get("ml_score") or 0) > 0.6)
        or (e.get("action") == "ALLOW" and (e.get("ml_score") or 0) < 0.6)
    )
    accuracy = (correct / total) if total else 0.0
    return {
        "totalRequests": total,
        "benignRequests": benign,
        "maliciousRequests": malicious,
        "accuracy": round(accuracy, 2),
    }


@router.get("/live-traffic")
def get_live_traffic():
    """Last N decisions as live traffic entries for the dashboard."""
    entries = _read_decision_log(max_lines=50)
    result = []
    for i, e in enumerate(reversed(entries)):
        parsed = _parse_request_text(e.get("request_text", ""))
        action = e.get("action", "ALLOW")
        score = e.get("ml_score") or 0.0
        verdict = "malicious" if action == "BLOCK" or score > 0.6 else "benign"
        result.append({
            "id": f"live-{len(entries)-i}",
            "timestamp": e.get("timestamp", ""),
            "method": parsed["method"],
            "path": parsed["path"],
            "ip": "0.0.0.0",
            "verdict": verdict,
            "statusCode": parsed["status"],
            "attackType": "SQLi" if "OR" in (e.get("request_text") or "") else None,
            "aiConfidence": round(score, 2),
        })
    return result


@router.get("/attack-distribution")
def get_attack_distribution():
    """Count by attack type / action for chart."""
    entries = _read_decision_log()
    if not entries:
        return [{"type": "None", "count": 0}]
    by_action = defaultdict(int)
    for e in entries:
        by_action[e.get("action", "ALLOW")] += 1
    return [{"type": k, "count": v} for k, v in sorted(by_action.items())]


@router.get("/attacks-by-hour")
def get_attacks_by_hour():
    """Count malicious/blocked by hour for chart."""
    entries = _read_decision_log()
    by_hour = defaultdict(int)
    for e in entries:
        ts = e.get("timestamp", "")[:13]
        if ts:
            by_hour[ts] += 1
    return [{"hour": h, "count": c} for h, c in sorted(by_hour.items())][-24:]


@router.get("/top-attackers")
def get_top_attackers():
    """Placeholder: no IP in decision_log; return empty or mock."""
    entries = _read_decision_log()
    blocked = [e for e in entries if e.get("action") == "BLOCK"]
    if not blocked:
        return []
    return [{"ip": "0.0.0.0", "attempts": len(blocked)}]


@router.get("/ai-status")
def get_ai_status(request: Request):
    """AI model status for dashboard; uses app state if available."""
    classifier = getattr(request.app.state, "waf_classifier", None)
    loaded = classifier is not None
    return {
        "architecture": "DistilBERT" if loaded else "N/A",
        "version": "1.0",
        "parameters": "WAF classifier",
        "trainingProgress": 100 if loaded else 0,
        "accuracy": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "lastUpdated": "2026-02-01T00:00:00Z",
    }
