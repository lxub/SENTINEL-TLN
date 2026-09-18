from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, Enum):
    SOCIAL_ENGINEERING = "social_engineering"
    PHISHING = "phishing"
    PRIVACY = "privacy"
    ABUSE = "abuse"


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VectorImpact(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSMetrics(BaseModel):
    attack_complexity: VectorImpact = VectorImpact.LOW  # LOW = Easy to execute
    user_interaction: VectorImpact = VectorImpact.HIGH   # Needs victim action
    confidentiality_impact: VectorImpact = VectorImpact.NONE
    integrity_impact: VectorImpact = VectorImpact.NONE
    availability_impact: VectorImpact = VectorImpact.NONE
    vector_string: str = ""


class Evidence(BaseModel):
    text: str
    source: str = "text"
    start: Optional[int] = None
    end: Optional[int] = None


class Indicator(BaseModel):
    name: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[Evidence] = Field(default_factory=list)


class DetectionResult(BaseModel):
    category: ThreatCategory
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    cvss_score: float = 0.0
    cvss_metrics: Optional[CVSSMetrics] = None
    indicators: List[Indicator] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    explanation: str = ""
    recommendations: List[str] = Field(default_factory=list)