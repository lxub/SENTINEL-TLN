# SENTINEL Security Console & Engine

This repository provides both a **Command Line Interface (CLI)** and a **Web Dashboard (GUI)** for analyzing security threats, text prompts, and OCR image payloads using the SENTINEL detection engine.

---

## 🛑 Critical Requirement: Tesseract OCR Native Installation

SENTINEL uses `pytesseract` for image OCR analysis. **`pytesseract` is only a Python wrapper** — you must install the native Tesseract OCR engine on your system for image processing to work.

### Installation Steps

* **Windows:**
  1. Download the installer from the [UB-Mannheim Tesseract Wiki](https://github.com/UB-Mannheim/tesseract/wiki).
  2. Run the installer and add Tesseract to your System PATH (default path: `C:\Program Files\Tesseract-OCR`).
* **macOS:**
  ```bash
  brew install tesseract
  ```
* **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt update && sudo apt install -y tesseract-ocr
  ```

> ⚠️❗️ **Important:** Verify installation by running `tesseract --version` in your terminal before running OCR image analysis.

---

## 📁 Repository Structure

```text
SENTINEL/
├─ main.py                    # CLI entry point
├─ app/                       # SENTINEL Detection Engine & Core Logic
│  ├─ schema.py
│  ├─ detectors/
│  ├─ risk/
│  └─ preprocessing/
├─ backend/
│  └─ api.py                  # FastAPI Backend Server
├─ frontend/
│  ├─ index.html              # Security Console Dashboard UI
│  ├─ styles.css              # Security Console Styles
│  └─ app.js                  # Frontend Application Logic
├─ scripts/
│  ├─ run_api.bat             # Windows Startup Helper
│  └─ run_api.sh              # Linux/macOS Startup Helper
├─ requirements.txt           # Core/CLI Dependencies
└─ requirements-interface.txt # GUI/Web API Dependencies
```

---

## 🚀 Usage & Execution Guide

### 1. CLI Version (Command Line)

To interpret and analyze threats using the command line:

1. Install the base core requirements:
   ```bash
   python -m pip install -r requirements.txt
   ```
2. Run the CLI interpreter:
   ```bash
   python main.py
   ```

---

### 2. GUI Version (Web Dashboard)

To launch the web interface and interact via your browser:

1. Install the interface & API dependencies:
   ```bash
   python -m pip install -r requirements-interface.txt
   ```
2. Run the activation/startup script for your operating system:

   * **Windows:**
     ```cmd
     scripts\run_api.bat
     ```
   * **Linux / macOS:**
     ```bash
     chmod +x scripts/run_api.sh
     ./scripts/run_api.sh
     ```

3. Open your browser and navigate to:
   ```text
   http://127.0.0.1:8000
   ```

---

## 🌐 API Endpoints & Documentation

When running the GUI version, SENTINEL exposes interactive API documentation via Swagger UI at **`http://127.0.0.1:8000/docs`**.

### Endpoints Overview

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check and backend status |
| `/api/info` | `GET` | Engine metadata and active detectors |
| `/api/analyze/text` | `POST` | Analyze plain text or security prompts |
| `/api/analyze/image` | `POST` | Upload image (`multipart/form-data`) for OCR + threat analysis |

#### Sample Text Payload (`POST /api/analyze/text`):
```json
{
  "text": "URGENT: Verify your account immediately..."
}
```

---

## 💡 Important Notes & Tips

1. **Virtual Environments:** It is strongly recommended to use a virtual environment (`python -m venv .venv`) before installing any `requirements.txt` file to prevent dependency conflicts.
2. **Additive Design:** The web backend (`backend/api.py`) acts purely as a wrapper around the `app/` engine. Modifying UI files will not alter underlying threat detection logic or scoring rules.
3. **Environment Variables:** If Tesseract is installed in a non-standard path on Windows, you may need to explicitly set `pytesseract.pytesseract.tesseract_cmd` inside your environment or script.
