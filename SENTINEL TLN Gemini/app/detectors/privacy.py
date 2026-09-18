import re
from app.schema import (
    DetectionResult, ThreatCategory, Severity, Indicator, Evidence, CVSSMetrics, VectorImpact
)
from app.risk.cvss_engine import calculate_cvss_score

PATTERNS = {
    "credentials": [r"\bpassword\b", r"\blogin details\b"],
    "otp": [r"\botp\b", r"\bverification code\b"],
    "financial_information": [r"\bbank account\b", r"\bcard number\b"],
    "government_id": [r"\bnik\b", r"\bktp\b", r"\bpassport number\b"],
}

RECOMMENDATIONS = {
    "credentials": "Never share login credentials.",
    "financial_information": "Do not share bank or credit card info.",
}

def detect_privacy(text: str) -> DetectionResult:
    if not text or not text.strip():
        return DetectionResult(
            category=ThreatCategory.PRIVACY, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No text provided.", recommendations=[]
        )

    indicators, all_evidence, detected_names = [], [], []

    for name, patterns in PATTERNS.items():
        matches = [m for p in patterns for m in re.finditer(p, text, flags=re.IGNORECASE)]
        if not matches:
            continue

        detected_names.append(name)
        evidence = [Evidence(text=m.group(0), source="text", start=m.start(), end=m.end()) for m in matches]
        indicators.append(Indicator(name=name, confidence=0.90, evidence=evidence))
        all_evidence.extend(evidence)

    if not indicators:
        return DetectionResult(
            category=ThreatCategory.PRIVACY, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No privacy exposure detected.", recommendations=[]
        )

    # Privacy impact strictly maps to Confidentiality loss
    has_high_impact_pii = any(x in detected_names for x in ["credentials", "otp", "financial_information", "government_id"])

    metrics = CVSSMetrics(
        attack_complexity=VectorImpact.LOW,
        user_interaction=VectorImpact.HIGH,
        confidentiality_impact=VectorImpact.HIGH if has_high_impact_pii else VectorImpact.LOW,
        integrity_impact=VectorImpact.NONE,
        availability_impact=VectorImpact.NONE,
    )
    metrics.vector_string = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:H/C:{metrics.confidentiality_impact.value}/I:N/A:N"

    cvss_score, severity = calculate_cvss_score(metrics)

    return DetectionResult(
        category=ThreatCategory.PRIVACY,
        detected=True,
        confidence=min(0.70 + (0.05 * len(indicators)), 0.99),
        severity=severity,
        cvss_score=cvss_score,
        cvss_metrics=metrics,
        indicators=indicators,
        evidence=all_evidence,
        explanation=f"Sensitive PII requested or exposed. Confidentiality CVSS Score: {cvss_score}.",
        recommendations=list(dict.fromkeys(RECOMMENDATIONS.get(n, "Protect personal data.") for n in detected_names))
    )