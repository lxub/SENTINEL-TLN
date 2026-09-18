from app.detectors.social_engineering import detect_social_engineering
from app.detectors.phishing import detect_phishing
from app.detectors.privacy import detect_privacy
from app.detectors.abuse import detect_abuse

from app.risk.cvss_engine import assess_risk
from app.preprocessing.ocr import extract_text_from_image


# ============================================================
# ANALYSIS PIPELINE
# ============================================================

def analyze_text(text: str) -> dict:

    detections = [
        detect_social_engineering(text),
        detect_phishing(text),
        detect_privacy(text),
        detect_abuse(text),
    ]

    return assess_risk(detections)


def analyze_image(image_path: str) -> dict:

    text = extract_text_from_image(image_path)

    risk = analyze_text(text)

    risk["extracted_text"] = text

    return risk


# ============================================================
# OUTPUT
# ============================================================

def print_results(risk: dict):

    print("\n================ SENTINEL THREAT ANALYSIS ================\n")

    if "extracted_text" in risk:
        print("Extracted Text:")
        print(risk["extracted_text"])

    print("\n================ DETECTOR RESULTS ================\n")

    for result in risk["detections"]:

        print(f"[{result.category.value.upper()}]")

        print("Detected:")
        print("YES" if result.detected else "NO")

        print("Confidence:")
        print(f"{result.confidence * 100:.0f}%")

        print("CVSS Base Score:")
        print(f"{result.cvss_score} / 10.0")

        print("Severity:")
        print(result.severity.value.upper())

        if result.cvss_metrics and result.cvss_metrics.vector_string:
            print("CVSS Vector:")
            print(result.cvss_metrics.vector_string)

        if result.indicators:
            print("Indicators:")
            for indicator in result.indicators:
                print(
                    f"- {indicator.name}: "
                    f"{indicator.confidence * 100:.0f}%"
                )

        if result.evidence:
            print("Evidence:")
            for evidence in result.evidence:
                print(f'- "{evidence.text}"')
                print(
                    f"  Position: "
                    f"{evidence.start}-{evidence.end}"
                )

        print()

    print("================ OVERALL RISK ================\n")

    print("Overall CVSS Score:")
    print(f"{risk['overall_cvss']} / 10.0")

    print("\nOverall Severity:")
    print(risk["overall_severity"].upper())

    print("\nDetected Categories:")

    if risk["detected_categories"]:
        for category in risk["detected_categories"]:
            print("-", category)
    else:
        print("- None")

    print("\nCorrelations:")

    if risk["correlations"]:
        for correlation in risk["correlations"]:
            print("-", correlation)
    else:
        print("- None")

    print("\nExplanation:")
    print(risk["explanation"])

    print("\nRecommendations:")

    if risk["recommendations"]:
        for recommendation in risk["recommendations"]:
            print("-", recommendation)
    else:
        print("- None")


# ============================================================
# TEST INPUT
# ============================================================

if __name__ == "__main__":

    print("================ SENTINEL INPUT ================\n")
    print("1. Analyze text")
    print("2. Analyze image")

    choice = input("\nSelect input type (1/2): ")

    if choice == "1":

        text = input("\nEnter text to analyze:\n\n")

        risk = analyze_text(text)

        print_results(risk)

    elif choice == "2":

        image_path = input("\nEnter image path:\n\n")

        risk = analyze_image(image_path)

        print_results(risk)

    else:

        print("\nInvalid choice.")