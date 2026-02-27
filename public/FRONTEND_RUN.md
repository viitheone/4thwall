# 4thwall WAF Dashboard Frontend

This directory contains the React + Vite + Tailwind dashboard UI that visualises real WAF metrics from the backend.

## Prerequisites

- Node.js 18+ (recommended) and npm
- Backend API running (FastAPI/uvicorn or your stack) and reachable from this app

## Install dependencies

From the project root:

```bash
cd public
npm install
```

## Configure API base URL (optional)

By default, the frontend sends requests to `/api/...` and the Vite dev server proxies to `http://localhost:8000`.

If your backend lives elsewhere, create a `.env` file in `public`:

```bash
VITE_API_BASE_URL=http://localhost:8000/api
VITE_API_PROXY_TARGET=http://localhost:8000
```

Adjust the URLs to match your backend.

## Run the development server

```bash
cd public
npm run dev
```

Then open the printed URL in your browser (typically `http://localhost:5173`).

## Build for production

```bash
cd public
npm run build
```

The static assets will be output to `dist/` and can be served by any static file server or reverse-proxy in front of your backend.

