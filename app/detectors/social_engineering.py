import re
from app.schema import (
    DetectionResult, ThreatCategory, Severity, Indicator, Evidence, CVSSMetrics, VectorImpact
)
from app.risk.cvss_engine import calculate_cvss_score

PATTERNS = {
    "urgency": [r"\burgent\b", r"\bimmediately\b", r"\bact now\b"],
    "fear": [r"\bsuspended\b", r"\bblocked\b", r"\bcompromised\b"],
    "authority_impersonation": [r"\b(?:we are|this is) (?:bank security|police|admin)\b"],
    "secrecy": [r"\bdo not tell anyone\b", r"\bkeep this secret\b"],
}

RECOMMENDATIONS = {
    "urgency": "Do not act immediately; take time to verify.",
    "fear": "Do not make decisions based on threats.",
}

def detect_social_engineering(text: str) -> DetectionResult:
    if not text or not text.strip():
        return DetectionResult(
            category=ThreatCategory.SOCIAL_ENGINEERING, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No text provided.", recommendations=[]
        )

    indicators, all_evidence, detected_names = [], [], []

    for name, patterns in PATTERNS.items():
        matches = [m for p in patterns for m in re.finditer(p, text, flags=re.IGNORECASE)]
        if not matches:
            continue

        detected_names.append(name)
        evidence = [Evidence(text=m.group(0), source="text", start=m.start(), end=m.end()) for m in matches]
        indicators.append(Indicator(name=name, confidence=0.80, evidence=evidence))
        all_evidence.extend(evidence)

    if not indicators:
        return DetectionResult(
            category=ThreatCategory.SOCIAL_ENGINEERING, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No social engineering detected.", recommendations=[]
        )

    # Social engineering relies on manipulation (Integrity & Confidentiality vector threat)
    metrics = CVSSMetrics(
        attack_complexity=VectorImpact.LOW,
        user_interaction=VectorImpact.HIGH,
        confidentiality_impact=VectorImpact.LOW,
        integrity_impact=VectorImpact.HIGH if "authority_impersonation" in detected_names else VectorImpact.LOW,
        availability_impact=VectorImpact.NONE,
    )
    metrics.vector_string = f"CVSS:3.1/AV:N/AC:{metrics.attack_complexity.value}/PR:N/UI:{metrics.user_interaction.value}/C:{metrics.confidentiality_impact.value}/I:{metrics.integrity_impact.value}/A:N"

    cvss_score, severity = calculate_cvss_score(metrics)

    return DetectionResult(
        category=ThreatCategory.SOCIAL_ENGINEERING,
        detected=True,
        confidence=min(0.65 + (0.08 * len(indicators)), 0.95),
        severity=severity,
        cvss_score=cvss_score,
        cvss_metrics=metrics,
        indicators=indicators,
        evidence=all_evidence,
        explanation=f"Social engineering tactics detected. CVSS Impact: {cvss_score}.",
        recommendations=list(dict.fromkeys(RECOMMENDATIONS.get(n, "Verify independently.") for n in detected_names))
    )