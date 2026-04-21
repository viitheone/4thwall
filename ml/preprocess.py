import re


def clean_text(text: str) -> str:
    if text is None or (isinstance(text, float) and str(text) == "nan"):
        return ""
    s = str(text).strip().lower()
    s = re.sub(r"[^\w\s\-./?=&]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def truncate_field(text: str, max_len: int = 200) -> str:
    if text is None or (isinstance(text, float) and str(text) == "nan"):
        return "NA"
    s = str(text).strip()
    if len(s) > max_len:
        return s[:max_len]
    return s


def _get_field(row, *keys, default="NA", max_len=200):
    for key in keys:
        if key in row:
            val = row[key]
            if val is None or (isinstance(val, float) and str(val) == "nan"):
                return default
            cleaned = clean_text(str(val))
            return truncate_field(cleaned, max_len) if cleaned else default
    return default


def serialize_request(row) -> str:
    if hasattr(row, "to_dict"):
        row = row.to_dict()
    row = dict(row)

    method = _get_field(row, "method", "METHOD")
    path = _get_field(row, "path", "url", "uri")
    query = _get_field(row, "query", "args", "query_string")
    status = _get_field(row, "status", "status_code")
    ua = _get_field(row, "user_agent", "ua", "user-agent")
    time_val = _get_field(row, "request_time", "time", "duration")

    return (
        f"METHOD={method}\n"
        f"PATH={path}\n"
        f"QUERY={query}\n"
        f"STATUS={status}\n"
        f"UA={ua}\n"
        f"TIME={time_val}"
    )
