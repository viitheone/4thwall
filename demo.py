"""
Integration demo: read Nginx logs -> serialize -> score via API -> policy -> decision_log.json
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ml.preprocess import serialize_request
from policy.decision import make_decision
from utils.log_parser import batch_read_logs

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except ImportError:
    urlopen = Request = URLError = HTTPError = None


API_BASE = os.environ.get("WAF_API_URL", "http://localhost:8000")
DECISION_LOG_PATH = os.environ.get("DECISION_LOG", "logs/decision_log.json")


def score_request(request_text: str) -> dict | None:
    """Call FastAPI /score endpoint. Returns {'score': ..., 'label': ..., 'confidence': ...} or None."""
    if urlopen is None:
        return None
    try:
        req = Request(
            f"{API_BASE}/score",
            data=json.dumps({"request_text": request_text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (URLError, HTTPError, OSError, json.JSONDecodeError):
        return None


def run_demo(log_path: str, n_lines: int = 10):
    """Read last n_lines from log, score each, apply policy, append to decision_log.json."""
    parsed = batch_read_logs(log_path, n_lines)
    if not parsed:
        print(f"No parsed lines from {log_path} (or file missing)")
        return

    Path(DECISION_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    log_entries = []

    for row in parsed:
        request_text = serialize_request(row)
        result = score_request(request_text)
        if result is None:
            ml_score = 0.0
            print("API unreachable; using ml_score=0.0")
        else:
            ml_score = result["score"]

        modsecurity_blocked = False
        decision = make_decision(modsecurity_blocked, ml_score)

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "request_text": request_text,
            "modsecurity_blocked": modsecurity_blocked,
            "ml_score": ml_score,
            "action": decision["action"],
            "reason": decision["reason"],
        }
        log_entries.append(entry)
        print(f"{entry['action']} | ml_score={ml_score:.2f} | {decision['reason']}")

    with open(DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        for entry in log_entries:
            f.write(json.dumps(entry) + "\n")
    print(f"Appended {len(log_entries)} entries to {DECISION_LOG_PATH}")


if __name__ == "__main__":
    log_file = os.environ.get("NGINX_ACCESS_LOG", "logs/access.log")
    n = int(os.environ.get("DEMO_N_LINES", "10"))
    run_demo(log_file, n_lines=n)
