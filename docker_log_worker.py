"""
Docker helper: tail nginx JSON access.log -> score via API -> append decision_log.json.

The dashboard reads decision_log.json; nothing wrote it automatically in compose before.
Run as the `log-worker` service (see docker-compose.yml).
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ml.preprocess import serialize_request
from policy.decision import make_decision
from utils.log_parser import parse_nginx_log_line

try:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
except ImportError:
    urlopen = Request = URLError = HTTPError = None  # type: ignore

API_BASE = os.environ.get("WAF_API_URL", "http://localhost:8000")
DECISION_LOG_PATH = os.environ.get("DECISION_LOG", "logs/decision_log.json")
ACCESS_LOG_PATH = os.environ.get("NGINX_ACCESS_LOG", "logs/access.log")
OFFSET_PATH = os.environ.get("WORKER_OFFSET_FILE", "logs/.waf_log_worker_offset")
POLL_SEC = float(os.environ.get("WORKER_POLL_SEC", "2"))


def score_request(request_text: str) -> dict | None:
    if urlopen is None:
        return None
    try:
        req = Request(
            f"{API_BASE}/score",
            data=json.dumps({"request_text": request_text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except (URLError, HTTPError, OSError, json.JSONDecodeError):
        return None


def load_offset() -> int:
    p = Path(OFFSET_PATH)
    if not p.exists():
        # Start at EOF so we don't replay an old huge log on first boot
        log = Path(ACCESS_LOG_PATH)
        if log.exists():
            return log.stat().st_size
        return 0
    try:
        return int(p.read_text(encoding="utf-8").strip() or "0")
    except (OSError, ValueError):
        return 0


def save_offset(pos: int) -> None:
    Path(OFFSET_PATH).parent.mkdir(parents=True, exist_ok=True)
    Path(OFFSET_PATH).write_text(str(pos), encoding="utf-8")


def append_decision(entry: dict) -> None:
    Path(DECISION_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def main() -> None:
    print(
        f"log-worker: watching {ACCESS_LOG_PATH} -> {DECISION_LOG_PATH} (API {API_BASE})",
        flush=True,
    )
    pos = load_offset()

    while True:
        log_path = Path(ACCESS_LOG_PATH)
        if not log_path.exists():
            time.sleep(POLL_SEC)
            continue

        try:
            size = log_path.stat().st_size
        except OSError:
            time.sleep(POLL_SEC)
            continue

        if pos > size:
            pos = 0

        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    row = parse_nginx_log_line(line)
                    if not row:
                        continue
                    request_text = serialize_request(row)
                    result = score_request(request_text)
                    if result is None:
                        ml_score = 0.0
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
                    append_decision(entry)
                    print(
                        f"{entry['action']} | ml={ml_score:.3f} | {decision['reason'][:60]}",
                        flush=True,
                    )
                pos = f.tell()
        except OSError as e:
            print(f"log-worker read error: {e}", flush=True)

        save_offset(pos)
        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
