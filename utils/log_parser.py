"""
Log parsing utilities for Nginx WAF logs.
"""

import json
from pathlib import Path


def parse_nginx_log_line(line: str) -> dict | None:
    """
    Parse custom Nginx JSON/CSV format.
    Extract method, path, query, status, user_agent, request_time.
    Return dict.
    """
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return {
                "method": data.get("method", "NA"),
                "path": data.get("path", data.get("uri", "NA")),
                "query": data.get("query", data.get("args", "NA")),
                "status": data.get("status", "NA"),
                "user_agent": data.get("user_agent", "NA"),
                "request_time": data.get("request_time", "NA"),
            }
        except json.JSONDecodeError:
            return None
    parts = line.split("\t")
    if len(parts) >= 6:
        return {
            "method": parts[0].strip(),
            "path": parts[1].strip(),
            "query": parts[2].strip(),
            "status": parts[3].strip(),
            "user_agent": parts[4].strip(),
            "request_time": parts[5].strip(),
        }
    return None


def tail_log_file(filepath: str, callback):
    """
    Read new lines as they appear.
    Call callback for each line.
    """
    path = Path(filepath)
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                callback(line)
            else:
                import time
                time.sleep(0.1)


def batch_read_logs(filepath: str, n_lines: int) -> list[dict]:
    """
    Read last n lines for demo purposes.
    Returns list of parsed log dicts.
    """
    path = Path(filepath)
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    lines = lines[-n_lines:] if len(lines) > n_lines else lines
    result = []
    for line in lines:
        parsed = parse_nginx_log_line(line)
        if parsed:
            result.append(parsed)
    return result
