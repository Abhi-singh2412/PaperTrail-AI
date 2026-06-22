"""
core/risk_scorer.py
───────────────────
Risk score calculation from forensic flags.

Scoring logic:
    Each forensic flag has a severity: HIGH, MEDIUM, or LOW.
    We assign weights and sum them up, capped at 100.

    HIGH   = 40 points  (one HIGH flag alone = HIGH risk level)
    MEDIUM = 20 points
    LOW    =  5 points

Risk levels:
    CRITICAL  ≥ 70  → Do NOT process. Escalate immediately.
    HIGH      ≥ 40  → Serious concern. Manual review required.
    MEDIUM    ≥ 20  → Suspicious. Flag for further review.
    LOW       >  0  → Minor anomalies. Note and proceed cautiously.
    CLEAN     =  0  → No anomalies detected.
"""

SEVERITY_WEIGHTS = {
    "HIGH":   40,
    "MEDIUM": 20,
    "LOW":     5,
}


def compute_risk_score(metadata: dict) -> dict:
    """
    Compute a 0–100 risk score from all forensic flags in metadata.

    Args:
        metadata: The full dict returned by any extract_*_metadata() function.

    Returns:
        dict with: risk_score, risk_level, flags_count, high_flags,
                   medium_flags, low_flags
    """
    flags     = metadata.get("forensic_flags", [])
    raw_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in flags)
    capped    = min(raw_score, 100)

    if capped >= 70:
        level = "CRITICAL"
    elif capped >= 40:
        level = "HIGH"
    elif capped >= 20:
        level = "MEDIUM"
    elif capped > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return {
        "risk_score":   capped,
        "risk_level":   level,
        "flags_count":  len(flags),
        "high_flags":   sum(1 for f in flags if f["severity"] == "HIGH"),
        "medium_flags": sum(1 for f in flags if f["severity"] == "MEDIUM"),
        "low_flags":    sum(1 for f in flags if f["severity"] == "LOW"),
    }
