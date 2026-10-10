# Adaptive Intrusion Detection Backend
**Topic:** Adaptive Intrusion Detection Using Sliding-Window Algorithms, Hash Tables, and Graph-Based Threat Correlation.

Educational FastAPI backend using a time-based sliding window (`deque`), hash-table tracking (`dict`/`Counter`), adjacency-list graph with BFS correlation, rule-based alerts, and a conservative adaptive threshold mechanism. It processes synthetic event records; it does not capture live network traffic and does not prove an attack occurred.

## Requirements
Python 3.10+, pip, VS Code optional. No database, API key, Docker, or external service required.

## Chromebook Linux / Debian / Ubuntu
Open a terminal in this folder:
```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python run.py
```
If venv creation fails, install `python3-venv` with your package manager. Stop server with Ctrl+C. Change port with `PORT=8001 python run.py`.

## Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
python run.py
```

## URLs
- Health: http://127.0.0.1:8000/api/health
- Swagger: http://127.0.0.1:8000/docs
- Graph: http://127.0.0.1:8000/api/graph

## Example commands
```bash
curl http://127.0.0.1:8000/api/health
curl -X POST http://127.0.0.1:8000/api/events -H 'Content-Type: application/json' -d '{"source_ip":"192.0.2.10","event_type":"failed_login","username":"demo"}'
curl http://127.0.0.1:8000/api/alerts
curl http://127.0.0.1:8000/api/stats
curl -X POST http://127.0.0.1:8000/api/demo/reset
```
Sample payloads are under `sample_data/`. `python demo.py` submits the brute-force sample. `python benchmark.py` measures API event-processing time on your machine.

## Endpoints
`GET /api/health`; `POST /api/events`; `POST /api/events/batch` (max 1,000); `GET /api/alerts`; `GET /api/alerts/{alert_id}`; `GET /api/stats`; `GET /api/graph`; `GET /api/ip/{ip_address}`; `GET /api/config`; `PATCH /api/config`; `POST /api/demo/reset`.

## DSA and complexity notes
- Deque append is O(1); expired-head removal is amortized O(1). Current rule counting scans the source IP's active window, O(k) per event for k recent events.
- Dictionary/Counter average lookup and update are O(1). The per-IP recent tracker currently filters retained events, O(k).
- Adjacency list stores O(V+E) graph data; BFS/connected-component traversal is O(V+E).
- Event history is capped at 10,000; graph retention is 1 hour and capped at 5,000 nodes. Per-IP trackers are pruned when that IP is accessed.
- Adaptive thresholds are intentionally simple, only raise static thresholds and use static fallback before enough samples. This is an educational baseline, not a robust production anomaly detector.

## Limitations and safety
In-memory state resets on restart. Do not expose this demo to the public internet. Before production use, add authentication/authorization, persistent storage, rate limiting, monitoring, stronger adaptive statistics, and systematic evaluation. Alerts mean suspicious behavior, not confirmed intrusion.
