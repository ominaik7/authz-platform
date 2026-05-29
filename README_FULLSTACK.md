
# Authorization Intelligence Platform

## Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run API server:

```bash
uvicorn app.api.server:app --reload
```

Backend:
http://localhost:8000

---

## Run Existing Auth Intelligence Engine

```bash
python -m app.main --burp ./burp3.xml
```

---

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Frontend:
http://localhost:5173

---

## Included Components

- Burp XML parser
- JWT intelligence
- Role inference
- Capability mapping
- Tenant detection
- Resource extraction
- Replay engine scaffold
- FastAPI backend
- React dashboard
