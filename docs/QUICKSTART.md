# AI-SOC Watchdog - Quick Start

## Install

```bash
pip install -r requirements.txt
cd soc-dashboard && npm install
```

## Environment Setup

Create `.env` in project root:

```
ANTHROPIC_API_KEY=sk-ant-...
SUPABASE_URL=https://...
SUPABASE_KEY=...
SUPABASE_SERVICE_KEY=...
```

## Run

Terminal 1 (backend):
```bash
python app.py
```

Terminal 2 (frontend):
```bash
cd soc-dashboard
npm run dev
```

Or use the launcher:
```bash
python scripts/utilities/master_launch.py
```

## Generate Test Data

After backend is running:
```bash
python scripts/data/generate_test_data.py
```

## Open

http://localhost:5173
