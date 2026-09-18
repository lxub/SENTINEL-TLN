from pathlib import Path

from PIL import Image
import pytesseract

pytesseract.pytesseract.tesseract_cmd = str(
    Path.home() / "tesseract.exe"
)

def extract_text_from_image(image_path: str) -> str:
    """
    Extract text from an image using Tesseract OCR.
    """

    path = Path(image_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Image not found: {image_path}"
        )

    image = Image.open(path)

    text = pytesseract.image_to_string(image)

    return text.strip()