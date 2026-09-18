from app.schema import (
    CVSSMetrics,
    DetectionResult,
    Severity,
    VectorImpact,
)


# ============================================================
# SIMPLIFIED CVSS WEIGHTS
# ============================================================

WEIGHTS = {
    VectorImpact.NONE: 0.0,
    VectorImpact.LOW: 0.22,
    VectorImpact.HIGH: 0.56,
}


# ============================================================
# SEVERITY RANK
# ============================================================

SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ============================================================
# CVSS SCORE CALCULATION
# ============================================================

def calculate_cvss_score(
    metrics: CVSSMetrics,
) -> tuple[float, Severity]:
    """
    Calculate SENTINEL's simplified CVSS-inspired score.

    This follows the simplified scoring model used by
    SENTINEL. It is not a full official CVSS implementation.
    """

    impact_sub_score = 1 - (
        (1 - WEIGHTS[metrics.confidentiality_impact])
        *
        (1 - WEIGHTS[metrics.integrity_impact])
        *
        (1 - WEIGHTS[metrics.availability_impact])
    )

    # Convert impact to a 0-10 scale
    base_impact = impact_sub_score * 10.0

    # --------------------------------------------------------
    # Exploitability adjustment
    # --------------------------------------------------------

    exploitability = 1.0

    if metrics.attack_complexity == VectorImpact.HIGH:
        exploitability -= 0.15

    if metrics.user_interaction == VectorImpact.HIGH:
        exploitability -= 0.10

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    score = round(
        min(
            max(
                base_impact * exploitability,
                0.0,
            ),
            10.0,
        ),
        1,
    )

    # --------------------------------------------------------
    # Score -> Severity
    # --------------------------------------------------------

    if score == 0.0:
        severity = Severity.NONE

    elif score < 4.0:
        severity = Severity.LOW

    elif score < 7.0:
        severity = Severity.MEDIUM

    elif score < 9.0:
        severity = Severity.HIGH

    else:
        severity = Severity.CRITICAL

    return score, severity


# ============================================================
# CORRELATIONS
# ============================================================

def calculate_correlations(
    categories: set[str],
) -> list[str]:

    correlations = []

    if (
        "phishing" in categories
        and "social_engineering" in categories
    ):
        correlations.append(
            "Phishing combined with social engineering manipulation"
        )

    if (
        "phishing" in categories
        and "privacy" in categories
    ):
        correlations.append(
            "Phishing combined with sensitive information exposure"
        )

    if (
        "social_engineering" in categories
        and "privacy" in categories
    ):
        correlations.append(
            "Social engineering combined with targeted privacy risk"
        )

    if (
        "abuse" in categories
        and "social_engineering" in categories
    ):
        correlations.append(
            "Abusive language combined with social manipulation"
        )

    return correlations


# ============================================================
# RISK ENGINE
# ============================================================

def assess_risk(
    detections: list[DetectionResult],
) -> dict:

    detected = [
        detection
        for detection in detections
        if detection.detected
    ]

    # --------------------------------------------------------
    # No threats
    # --------------------------------------------------------

    if not detected:

        return {
            "overall_severity": Severity.NONE.value,
            "overall_cvss": 0.0,
            "detected_categories": [],
            "correlations": [],
            "explanation": (
                "No significant threats were detected."
            ),
            "recommendations": [],
            "detections": detections,
        }

    # --------------------------------------------------------
    # Calculate CVSS for EVERY detected category
    # --------------------------------------------------------

    detection_scores = []

    for detection in detected:

        score, severity = calculate_cvss_score(
            detection.cvss_metrics
        )

        # Keep the DetectionResult synchronized with the
        # calculated CVSS result.
        detection.cvss_score = score
        detection.severity = severity

        detection_scores.append(score)

    # --------------------------------------------------------
    # Overall score
    #
    # Use the highest individual threat score rather than
    # summing scores together.
    # --------------------------------------------------------

    overall_cvss = max(detection_scores)

    # --------------------------------------------------------
    # Overall severity comes FROM the overall CVSS score.
    # --------------------------------------------------------

    if overall_cvss == 0.0:
        overall_severity = Severity.NONE

    elif overall_cvss < 4.0:
        overall_severity = Severity.LOW

    elif overall_cvss < 7.0:
        overall_severity = Severity.MEDIUM

    elif overall_cvss < 9.0:
        overall_severity = Severity.HIGH

    else:
        overall_severity = Severity.CRITICAL

    # --------------------------------------------------------
    # Categories
    # --------------------------------------------------------

    detected_categories = [
        detection.category.value
        for detection in detected
    ]

    categories = set(detected_categories)

    # --------------------------------------------------------
    # Correlations
    # --------------------------------------------------------

    correlations = calculate_correlations(
        categories
    )

    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    recommendations = []

    for detection in detected:

        for recommendation in detection.recommendations:

            if recommendation not in recommendations:
                recommendations.append(
                    recommendation
                )

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    explanation = (
        f"SENTINEL detected {len(detected)} "
        f"threat category(ies): "
        + ", ".join(detected_categories)
        + f". Maximum CVSS threat score: "
        f"{overall_cvss:.1f} "
        f"({overall_severity.value.upper()})."
    )

    if correlations:
        explanation += (
            " Multiple threat vectors were correlated "
            "during the assessment."
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "overall_severity": overall_severity.value,
        "overall_cvss": round(overall_cvss, 1),
        "detected_categories": detected_categories,
        "correlations": correlations,
        "explanation": explanation,
        "recommendations": recommendations,
        "detections": detections,
    }