"""
Dataset loader for WAF training.
Expects CSV with: method, path/url, query/args, status, user_agent, request_time, label.
Also supports alternate column names: target (benign/malicious), action→method, resource→path.
"""

import pandas as pd
from sklearn.model_selection import train_test_split

from ml.preprocess import serialize_request


def _normalize_row_to_request(row):
    """
    Map CSV columns to expected request fields for serialize_request.
    Supports standard WAF columns and activity/audit log columns:
    action→method, resource→path, protocol+anomaly_score+anomaly_bin→query,
    access_result→status, device_type+location→user_agent, session_duration→request_time.
    """
    r = dict(row)
    if "method" not in r and "action" in r:
        r["method"] = r["action"]
    if "path" not in r and "url" not in r and "resource" in r:
        r["path"] = r["resource"]
    if "query" not in r and "args" not in r:
        parts = []
        if "protocol" in r and pd.notna(r.get("protocol")):
            parts.append(str(r["protocol"]))
        if "anomaly_score" in r and pd.notna(r.get("anomaly_score")):
            parts.append(f"anomaly={r['anomaly_score']}")
        if "anomaly_bin" in r and pd.notna(r.get("anomaly_bin")):
            parts.append(f"bin={r['anomaly_bin']}")
        if "resource_category" in r and pd.notna(r.get("resource_category")):
            parts.append(f"cat={r['resource_category']}")
        r["query"] = " ".join(parts) if parts else "NA"
    if "status" not in r and "access_result" in r:
        r["status"] = r["access_result"]
    if "user_agent" not in r:
        parts = []
        if "device_type" in r and pd.notna(r.get("device_type")):
            parts.append(str(r["device_type"]))
        if "location" in r and pd.notna(r.get("location")):
            parts.append(str(r["location"]))
        r["user_agent"] = " ".join(parts) if parts else "NA"
    if "request_time" not in r and "session_duration" in r:
        r["request_time"] = r["session_duration"]
    return r


def _labels_to_int(df, label_col):
    """Convert label column to 0/1. Supports 'label' (0/1) or 'target' (benign/malicious)."""
    series = df[label_col].astype(str).str.strip().str.lower()
    if all(v in ("0", "1") for v in series.unique()):
        return df[label_col].astype(int).tolist()
    return [1 if v in ("malicious", "1") else 0 for v in series]


def load_and_preprocess_dataset(csv_path: str):
    """
    Read CSV, drop rows with missing labels, serialize each row.
    Label column: 'label' (0/1) or 'target' (benign=0, malicious=1).
    Returns (texts list, labels list).
    """
    df = pd.read_csv(csv_path)
    label_col = "label" if "label" in df.columns else "target"
    if label_col not in df.columns:
        raise KeyError(
            f"CSV must have a 'label' or 'target' column. Found columns: {list(df.columns)}"
        )
    df = df.dropna(subset=[label_col])

    labels = _labels_to_int(df, label_col)
    df = df.reset_index(drop=True)

    texts = []
    for i, row in df.iterrows():
        row_dict = _normalize_row_to_request(row)
        texts.append(serialize_request(row_dict))

    return texts, labels


def create_train_val_split(texts, labels, split_ratio=0.8):
    """
    Stratified split.
    Returns train_texts, val_texts, train_labels, val_labels.
    """
    (
        train_texts,
        val_texts,
        train_labels,
        val_labels,
    ) = train_test_split(
        texts,
        labels,
        train_size=split_ratio,
        stratify=labels,
        random_state=42,
    )
    return train_texts, val_texts, train_labels, val_labels
