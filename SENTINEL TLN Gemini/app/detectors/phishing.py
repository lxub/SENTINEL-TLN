import re
from app.schema import (
    DetectionResult, ThreatCategory, Severity, Indicator, Evidence, CVSSMetrics, VectorImpact
)
from app.risk.cvss_engine import calculate_cvss_score

PATTERNS = {
    "suspicious_link": [r"https?://[^\s]+", r"\bwww\.[^\s]+", r"\bclick (?:this|the) link\b"],
    "fake_verification": [r"\bverify your account\b", r"\bconfirm your identity\b"],
    "credential_request": [r"\benter your password\b", r"\bprovide your password\b"],
    "otp_request": [r"\benter (?:your )?otp\b", r"\bsend (?:me )?(?:your )?otp\b"],
    "fake_login": [r"\blog in here\b", r"\bsecure login\b"],
    "brand_impersonation": [r"\b(?:we are|this is) (?:from )?(?:paypal|microsoft|google)\b"],
}

RECOMMENDATIONS = {
    "suspicious_link": "Do not click the link until verified.",
    "credential_request": "Never provide passwords through unsolicited messages.",
    "otp_request": "Never share OTPs or verification codes.",
}

def detect_phishing(text: str) -> DetectionResult:
    if not text or not text.strip():
        return DetectionResult(
            category=ThreatCategory.PHISHING, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No text provided.", recommendations=[]
        )

    indicators, all_evidence, detected_names = [], [], []

    for name, patterns in PATTERNS.items():
        matches = [m for p in patterns for m in re.finditer(p, text, flags=re.IGNORECASE)]
        if not matches:
            continue

        detected_names.append(name)
        evidence = [Evidence(text=m.group(0), source="text", start=m.start(), end=m.end()) for m in matches]
        indicators.append(Indicator(name=name, confidence=0.85, evidence=evidence))
        all_evidence.extend(evidence)

    if not indicators:
        return DetectionResult(
            category=ThreatCategory.PHISHING, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No phishing detected.", recommendations=[]
        )

    # CVSS Vector Mapping
    metrics = CVSSMetrics(
        attack_complexity=VectorImpact.LOW,
        user_interaction=VectorImpact.HIGH,
        confidentiality_impact=VectorImpact.HIGH if any(x in detected_names for x in ["credential_request", "otp_request"]) else VectorImpact.LOW,
        integrity_impact=VectorImpact.HIGH if "fake_login" in detected_names or "fake_verification" in detected_names else VectorImpact.LOW,
        availability_impact=VectorImpact.NONE,
    )
    metrics.vector_string = f"CVSS:3.1/AV:N/AC:{metrics.attack_complexity.value}/PR:N/UI:{metrics.user_interaction.value}/C:{metrics.confidentiality_impact.value}/I:{metrics.integrity_impact.value}/A:N"

    cvss_score, severity = calculate_cvss_score(metrics)

    return DetectionResult(
        category=ThreatCategory.PHISHING,
        detected=True,
        confidence=min(0.60 + (0.10 * len(indicators)), 0.98),
        severity=severity,
        cvss_score=cvss_score,
        cvss_metrics=metrics,
        indicators=indicators,
        evidence=all_evidence,
        explanation=f"Phishing indicators detected. Measured CVSS Score: {cvss_score} ({severity.value.upper()}).",
        recommendations=list(dict.fromkeys(RECOMMENDATIONS.get(n, "Exercise caution.") for n in detected_names))
    )