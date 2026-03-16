# ScamCheck — Cybercrime Intelligence Search Engine

A full-stack cybercrime intelligence platform that helps Indian citizens verify whether a phone number, UPI ID, bank account, email, or website is linked to cyber fraud.

## Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│   React Frontend    │────▶│   FastAPI Backend    │────▶│   SQLite /   │
│   (Port 3000)       │     │   (Port 8000)        │     │  PostgreSQL  │
└─────────────────────┘     └─────────────────────┘     └──────────────┘
```

## Quick Start

### 1. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

pip install -r requirements.txt
python seed_database.py         # Seed initial data
uvicorn main:app --reload --port 8000
```

Backend runs at: http://localhost:8000
API docs at: http://localhost:8000/docs

### 2. Frontend Setup

```bash
cd frontend
npm install
npm start
```

Frontend runs at: http://localhost:3000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/search?q=...` | Search indicators |
| GET | `/api/indicators` | List all indicators |
| GET | `/api/indicators/{id}` | Get indicator detail + linked intel |
| POST | `/api/reports` | Submit a scam report |
| GET | `/api/reports/pending` | Get pending reports (admin) |
| POST | `/api/reports/{id}/approve` | Approve a report (admin) |
| POST | `/api/reports/{id}/reject` | Reject a report (admin) |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/trends` | Fraud trend analytics |

## Switching to PostgreSQL

In `backend/config.py`, change:
```python
DATABASE_URL = "postgresql://user:password@localhost:5432/scamcheck"
```

Then run:
```bash
python seed_database.py
```

## Deployment

Recommended: Deploy backend on **Railway/Render**, frontend on **Vercel/Netlify**.

For production, set these environment variables:
```
DATABASE_URL=postgresql://...
SECRET_KEY=your-secret-key
ADMIN_PASSWORD=your-admin-password
CORS_ORIGINS=https://your-frontend-domain.com
```
