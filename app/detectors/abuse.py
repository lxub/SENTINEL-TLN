import re
from app.schema import (
    DetectionResult, ThreatCategory, Severity, Indicator, Evidence, CVSSMetrics, VectorImpact
)
from app.risk.cvss_engine import calculate_cvss_score

PATTERNS = {
    "insult": [r"\bidiot\b", r"\bstupid\b", r"\bpathetic\b"],
    "harassment": [r"\bleave me alone\b", r"\bshut up\b"],
    "threat": [r"\bi will hurt you\b", r"\byou will regret this\b"],
    "intimidation": [r"\bdo what i say\b", r"\byou better obey\b"],
}

RECOMMENDATIONS = {
    "threat": "Preserve message and notify support/authorities.",
    "insult": "Block and report sender.",
}

def detect_abuse(text: str) -> DetectionResult:
    if not text or not text.strip():
        return DetectionResult(
            category=ThreatCategory.ABUSE, detected=False, confidence=0.0,
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
            category=ThreatCategory.ABUSE, detected=False, confidence=0.0,
            severity=Severity.NONE, cvss_score=0.0, explanation="No abuse detected.", recommendations=[]
        )

    # Abuse/harassment threats map to Safety/Integrity & Availability vectors
    has_threats = any(x in detected_names for x in ["threat", "intimidation"])

    metrics = CVSSMetrics(
        attack_complexity=VectorImpact.LOW,
        user_interaction=VectorImpact.NONE,
        confidentiality_impact=VectorImpact.NONE,
        integrity_impact=VectorImpact.HIGH if has_threats else VectorImpact.LOW,
        availability_impact=VectorImpact.LOW,
    )
    metrics.vector_string = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:N/I:{metrics.integrity_impact.value}/A:{metrics.availability_impact.value}"

    cvss_score, severity = calculate_cvss_score(metrics)

    return DetectionResult(
        category=ThreatCategory.ABUSE,
        detected=True,
        confidence=min(0.70 + (0.05 * len(indicators)), 0.98),
        severity=severity,
        cvss_score=cvss_score,
        cvss_metrics=metrics,
        indicators=indicators,
        evidence=all_evidence,
        explanation=f"Abusive or threatening content detected. Calculated CVSS Risk: {cvss_score}.",
        recommendations=list(dict.fromkeys(RECOMMENDATIONS.get(n, "Do not engage.") for n in detected_names))
    )