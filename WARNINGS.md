# SENTINEL Interface Layer

This package is an **additive interface layer** for the existing SENTINEL project you supplied.

It does not modify your existing detector files, schema, CVSS engine, OCR module, or CLI `main.py`.

## What is added

- `backend/api.py` — FastAPI backend exposing the existing engine.
- `frontend/index.html` — browser dashboard.
- `frontend/styles.css` — responsive dark security-console UI.
- `frontend/app.js` — text analysis, OCR image upload, result rendering, copy-JSON, samples, API status.
- `requirements-interface.txt` — only the web/API dependencies.
- `scripts/run_api.bat` and `scripts/run_api.sh` — local launch helpers.

## Expected placement

Copy these additions into the **root of your existing SENTINEL project** so the structure becomes:

```text
SENTINEL TLN Gemini/
├─ main.py                    # existing
├─ app/                       # existing — leave unchanged
│  ├─ schema.py
│  ├─ detectors/...
│  ├─ risk/...
│  └─ preprocessing/...
├─ backend/
│  └─ api.py                 # added
├─ frontend/
│  ├─ index.html              # added
│  ├─ styles.css              # added
│  └─ app.js                  # added
├─ scripts/
│  ├─ run_api.bat             # added
│  └─ run_api.sh              # added
└─ requirements-interface.txt # added
```

## Run on Windows

Activate your existing `.venv`, then install the interface dependencies:

```powershell
python -m pip install -r requirements-interface.txt
```

Start the API/UI:

```powershell
python -m uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload
```

Then open:

```text
http://127.0.0.1:8000/
```

The interactive API documentation is available at `/docs`.

## API endpoints

### Health
`GET /api/health`

### Engine metadata
`GET /api/info`

### Text analysis
`POST /api/analyze/text`

Body:

```json
{
  "text": "URGENT: verify your account immediately..."
}
```

### Image / OCR analysis
`POST /api/analyze/image`

Multipart field: `file`

The backend validates the uploaded image, stores it temporarily, sends it through your existing OCR + detector pipeline, and deletes the temporary file afterward.

## Design goal

The UI intentionally sits **outside** the detector logic. Your current detection behavior stays the source of truth; this layer only turns its existing output into a local web API and a visual console.

## Optional future extensions

The current interface is deliberately dependency-light, so it is easy to demo locally and easy to replace later with React, Next.js, or another frontend without rewriting the SENTINEL engine.
