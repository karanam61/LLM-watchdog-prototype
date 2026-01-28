# AI-SOC Watchdog

## Commands
- **Backend**: `python app.py` (Flask + SocketIO on port 5000)
- **Frontend**: `cd soc-dashboard && npm run dev` (Vite on port 5173)
- **Install deps**: `pip install -r requirements.txt` and `cd soc-dashboard && npm install`
- **Tests**: `python tests/run_all_tests.py` (all), `--quick` (no API), `--api` (API only), `--ai` (AI components)
- **Health check**: `curl http://localhost:5000/api/health`

## Authentication
- **Default login**: `analyst` / `watchdog123`
- Configure via `.env`: `AUTH_USERNAME`, `AUTH_PASSWORD`, `SESSION_SECRET`
- Session-based auth with timing-safe credential comparison

## Architecture
- **Backend**: Flask + SocketIO + Supabase (PostgreSQL) + ChromaDB (RAG) + Claude AI
- **Frontend**: React + Vite + TailwindCSS + Socket.IO client in `soc-dashboard/`
- **Core modules**: `backend/core/` (parser, mitre_mapping, Severity, Queue_manager)
- **AI pipeline**: `backend/ai/` (alert_analyzer_final.py, rag_system.py, security_guard.py)
- **Storage**: `backend/storage/` (database.py for Supabase, s3_failover.py)
- **Monitoring**: `backend/monitoring/` (system_monitor, live_logger, API blueprints)

## Code Style
- Python: snake_case functions/variables, PascalCase classes, type hints encouraged
- Use `live_logger.log()` for structured logging with `_explanation` field
- Use `secrets.compare_digest()` for credential comparisons (timing-safe)
- Return generic error messages to clients; log full errors internally
- Environment vars via `python-dotenv`; secrets in `.env` (never commit)
- API endpoints return JSON; use Flask blueprints for modularity
- Frontend: JSX components in `src/pages/`, API calls via `src/utils/api.js`
