# 4thwall – Transformer-based Hybrid WAF

A hybrid Web Application Firewall that combines **ModSecurity** (rule-based) with a **Transformer (DistilBERT)** classifier. Fixed architecture: no online learning, training and inference are separate.

## Architecture (ASCII)

```
                    ┌─────────────────┐
                    │   Client        │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Nginx         │
                    │ + ModSecurity   │
                    │ (JSON logs)     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
       access.log     ModSec audit    proxy to app
              │              │         (e.g. DVWA)
              ▼              │
       ┌──────────────┐      │
       │ demo.py      │      │
       │ log_parser   │      │
       │ serialize    │      │
       └──────┬───────┘      │
              │              │
              ▼              ▼
       ┌─────────────────────────────┐
       │  FastAPI /score              │
       │  WAFClassifier (infer.py)    │
       └──────────────┬───────────────┘
                      │
                      ▼
       ┌─────────────────────────────┐
       │  policy/decision.py          │
       │  make_decision(ModSec, ML)  │
       └──────────────┬───────────────┘
                      │
                      ▼
       decision_log.json (BLOCK/ALERT/ALLOW)
```

## Prerequisites

- Python 3.10+
- Nginx (optional, for full pipeline)
- ModSecurity (optional)

## Installation

1. Clone and enter the project:
   ```bash
   cd 4thwall
   ```

2. Create a virtualenv and install dependencies:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   # source .venv/bin/activate   # Linux/macOS
   pip install -r requirements.txt
   ```

3. Copy environment template:
   ```bash
   copy .env.example .env
   ```
   Edit `.env` if you need different paths or ports.

## Training

1. Place your training CSV in `data/` (columns: `method`, `path` or `url`, `query` or `args`, `status`, `user_agent`, `request_time`, `label` with label 0=benign, 1=malicious).

2. Run training:
   ```bash
   python -m ml.train --data_path data/train.csv
   ```
   Optional: `--output_dir ./models/waf_model` and `--epochs 3`.

3. Model and tokenizer are saved under `MODEL_SAVE_PATH` (default `./models/waf_model`). Best model is chosen by validation F1.

## Running the System

1. Start the API (after training):
   ```bash
   set MODEL_PATH=./models/waf_model
   uvicorn api.main:app --host 0.0.0.0 --port 8000
   ```

2. Health check:
   ```bash
   curl http://localhost:8000/health
   ```

3. Score a request (body = serialized request string):
   ```bash
   curl -X POST http://localhost:8000/score -H "Content-Type: application/json" -d "{\"request_text\": \"METHOD=get\nPATH=/login\nQUERY=id=1\nSTATUS=200\nUA=curl\nTIME=0.01\"}"
   ```

## Running with Docker

Run the full stack (API, dashboard frontend, Nginx WAF, and optional DVWA) with Docker Compose.

**Prerequisites:** Docker and Docker Compose.

1. **Train a model first** (if you have not already), so the API can load it:
   ```bash
   python -m ml.train --data_path data/train.csv
   ```
   This writes the model under `./models/waf_model` (mounted into the API container).

2. **Build and start all services:**
   ```bash
   docker compose up --build -d
   ```

3. **Access the stack:**
   | Service        | URL                      | Notes |
   |----------------|--------------------------|--------|
   | **Dashboard UI** | http://localhost:3000   | Proxies `/api` → WAF API |
   | **WAF API**     | http://localhost:8000   | Open `/health` and `/docs` |
   | **Nginx (WAF)** | http://localhost:80     | **Use this** to hit DVWA *through* ModSecurity (traffic is logged to `logs/access.log`). |
   | **DVWA (direct)** | http://localhost:8080 | Bypasses the WAF container — requests **do not** appear in `logs/access.log`. |

   The **`log-worker`** service tails `logs/access.log`, calls `/score`, and appends `logs/decision_log.json` so the **dashboard** shows traffic. It starts after the API is healthy (~model load).

4. **Useful commands:**
   - View logs: `docker compose logs -f`
   - Stop: `docker compose down`
   - Run only API + frontend (no Nginx/DVWA): `docker compose up -d api frontend`

## Demo

1. Ensure Nginx is writing JSON access logs to `logs/access.log` (see `nginx/nginx.conf`).

2. Run the demo (reads last N lines, scores via API, applies policy, appends to `logs/decision_log.json`):
   ```bash
   set NGINX_ACCESS_LOG=logs/access.log
   set DECISION_LOG=logs/decision_log.json
   set WAF_API_URL=http://localhost:8000
   python demo.py
   ```
   Optional: `DEMO_N_LINES=20` to process more lines.

## Demo Scenarios

- **No API**: If the model is not loaded or the API is down, demo uses `ml_score=0.0` and logs accordingly.
- **Sample log**: You can create a minimal `logs/access.log` with one JSON line per request (see `log_format waf_json` in `nginx.conf`) and run the demo.
- **Policy**: ModSecurity blocked → BLOCK; ML score > 0.9 → BLOCK; > 0.6 → ALERT; else ALLOW.

## Troubleshooting

- **503 on /score**: Model not found at `MODEL_PATH`. Train first or set `MODEL_PATH` to a valid path.
- **Import errors**: Run from project root and ensure `requirements.txt` is installed.
- **Nginx not starting**: Check paths in `nginx.conf` (e.g. `logs/` relative to Nginx prefix). Create `logs` directory if needed.
- **Empty decision log**: Ensure `logs/access.log` exists and has lines in the expected JSON format.
- **Port 80 or 8000 not loading**: Run `docker compose ps` — all services should be `Up`. The CRS **nginx** image listens on **8080 inside the container**; compose maps **host `80` → container `8080`**. If you mapped `80:80` by mistake, nothing listens and the browser hangs. For the API, open `http://localhost:8000/health` (JSON). If **nginx** is restarting, run `docker compose logs nginx --tail 80`.
- **Nginx `Restarting` + bind-mount conf**: If `nginx/conf.d/99-waf-host-access-log.conf` **did not exist** the first time you ran Compose, Docker may have created a **directory** with that name. Nginx then fails. Remove that folder, ensure the path is a **regular file** (see repo), then `docker compose up -d --force-recreate nginx`.
- **Dashboard empty**: Traffic must go through **http://localhost:80** (WAF), not **:8080** (direct DVWA). Ensure `log-worker` is running; it writes `logs/decision_log.json`. Check `docker compose logs -f log-worker`.
- **“WAF doesn’t block”**: **ModSecurity** can block at the proxy (compose sets `MODSEC_RULE_ENGINE=On`). The **ML model is not inline with Nginx** — it only runs in the API when `log-worker` / `demo.py` scores log lines. Obvious CRS matches (e.g. SQLi probes) should still get **403** from ModSecurity when score ≥ anomaly threshold.
- **Docker – dashboard can’t reach API**: Ensure both `api` and `frontend` services are running; the frontend proxies `/api` to the API container. Run `docker compose ps` to confirm.
- **Docker – API has no model**: Train locally first so `./models/waf_model` exists, then start with `docker compose up`; the compose file mounts `./models` into the API container.
- **Docker build: `Read timed out` / huge `nvidia-*` / `cudnn` downloads**: PyPI’s default Linux `torch` wheel includes CUDA and is multi‑GB. The API image installs **CPU-only** PyTorch from PyTorch’s wheel index first (see `Dockerfile.api`). If a build still times out, retry `docker compose build --no-cache api` or use a faster network; local `pip install -r requirements.txt` is unchanged.

## Limitations

- No online learning; model is fixed after training.
- Docker Compose sets **`MODSEC_RULE_ENGINE=On`** on the CRS nginx proxy; local `nginx/nginx.conf` samples may still be detection-only if you run Nginx manually.
- Policy engine has exactly the specified rules (ModSec block, then ML thresholds 0.9 / 0.6).
- Demo assumes ModSecurity blocked flag is false when not integrated with a real ModSec audit log.
