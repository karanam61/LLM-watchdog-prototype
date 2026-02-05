# Getting Started

## Prerequisites

- Python 3.8+
- Node.js 18+
- Anthropic API key (for AI analysis)

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
cd soc-dashboard && npm install
```

### 2. Configure environment

Copy `.env.example` to `.env` and add your API keys:

```
ANTHROPIC_API_KEY=your_key_here
SUPABASE_URL=your_url
SUPABASE_KEY=your_key
```

### 3. Start the backend

```bash
python app.py
```

Backend runs on http://localhost:5000

### 4. Start the frontend

In a new terminal:

```bash
cd soc-dashboard
npm run dev
```

Frontend runs on http://localhost:5173

### 5. Open the dashboard

Go to http://localhost:5173 in your browser.

Default login: `analyst` / `watchdog123`

## Quick Launch (Alternative)

To start everything at once:

```bash
python scripts/utilities/master_launch.py
```

This validates the system, generates test data, and starts both servers.

## Troubleshooting

**Blank screen:** Frontend not running. Check `npm run dev` is active.

**No alerts:** Backend not running or no data. Run `python scripts/data/generate_test_data.py` to create test alerts.

**AI stuck on "Analyzing":** Check that `ANTHROPIC_API_KEY` is set in `.env`.
