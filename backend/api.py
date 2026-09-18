from __future__ import annotations

import sys
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from PIL import Image

# The interface layer is additive: the existing app/ package is left untouched.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from main import analyze_image, analyze_text  # noqa: E402

FRONTEND_DIR = PROJECT_ROOT / "frontend"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_IMAGE_TYPES = {
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/webp",
    "image/bmp",
    "image/tiff",
}

app = FastAPI(
    title="SENTINEL API",
    description="Interface API for the SENTINEL threat-analysis engine.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=25_000)


def _serialize_risk(risk: dict[str, Any]) -> dict[str, Any]:
    """Convert the existing Pydantic detector objects to API-safe JSON."""
    serialized = dict(risk)
    serialized["detections"] = [
        detection.model_dump(mode="json") for detection in risk.get("detections", [])
    ]
    return serialized


def _with_metadata(risk: dict[str, Any], started: float, source: str) -> dict[str, Any]:
    result = _serialize_risk(risk)
    result["meta"] = {
        "source": source,
        "processing_ms": round((time.perf_counter() - started) * 1000, 2),
        "engine": "SENTINEL threat analysis engine",
        "api_version": app.version,
    }
    return result


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-api", "version": app.version}


@app.get("/api/info")
def info() -> dict[str, Any]:
    return {
        "name": "SENTINEL",
        "version": app.version,
        "detectors": [
            "social_engineering",
            "phishing",
            "privacy",
            "abuse",
        ],
        "inputs": ["text", "image_ocr"],
        "limits": {"max_image_bytes": MAX_UPLOAD_BYTES, "max_text_chars": 25_000},
    }


@app.post("/api/analyze/text")
def analyze_text_api(payload: TextAnalysisRequest) -> dict[str, Any]:
    started = time.perf_counter()
    text = payload.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text cannot be empty.")

    try:
        risk = analyze_text(text)
        return _with_metadata(risk, started, "text")
    except Exception as exc:  # keep internal engine details out of the browser response
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc


@app.post("/api/analyze/image")
async def analyze_image_api(file: UploadFile = File(...)) -> dict[str, Any]:
    started = time.perf_counter()

    if file.content_type not in ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported image type. Use PNG, JPG, WEBP, BMP, or TIFF.",
        )

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds the 10 MB upload limit.")

    suffix = Path(file.filename or "upload.png").suffix or ".png"
    temp_path: str | None = None

    try:
        # Validate the image before OCR.
        with NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            temp_path = tmp.name

        with Image.open(temp_path) as image:
            image.verify()

        risk = analyze_image(temp_path)
        return _with_metadata(risk, started, "image_ocr")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {exc}") from exc
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


if FRONTEND_DIR.exists():
    app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="ui")


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="Frontend not installed.")
    return FileResponse(index)
