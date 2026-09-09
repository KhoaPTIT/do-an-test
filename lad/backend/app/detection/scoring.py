"""Gộp điểm rule và điểm ML thành một điểm rủi ro và một quyết định."""
from app.config import (ML_WEIGHT, RULE_WEIGHT, THRESHOLD_BLOCK,
                        THRESHOLD_CHALLENGE)
from app.detection.features import EventData
from app.detection.ml_model import predict_anomaly
from app.detection.rules import run_rules


def decide(score: float) -> str:
    if score >= THRESHOLD_BLOCK:
        return "block"
    if score >= THRESHOLD_CHALLENGE:
        return "challenge"
    return "allow"


def severity_of(score: float, decision: str) -> str:
    if score >= 85:
        return "critical"
    if decision == "block":
        return "high"
    if decision == "challenge":
        return "medium"
    return "low"


def assess(event: EventData, ctx: dict) -> dict:
    """Chấm điểm một sự kiện đăng nhập.

    Cơ chế lai: rule chiếm trọng số lớn hơn vì giải thích được và ổn định,
    ML bổ sung khả năng bắt các bất thường không viết thành luật được.
    Khi ML không dùng được (chưa có mô hình, hoặc user còn quá ít lịch sử),
    hệ thống lùi về dùng riêng rule thay vì đoán bừa.
    """
    hits = run_rules(event, ctx)
    rule_score = min(sum(h.score for h in hits), 100.0)

    ml_score = predict_anomaly(event, ctx)

    if ml_score is None:
        final = rule_score
        mode = "rule_only"
    else:
        final = RULE_WEIGHT * rule_score + ML_WEIGHT * ml_score
        mode = "hybrid"

    decision = decide(final)

    return {
        "risk_score": round(final, 2),
        "rule_score": round(rule_score, 2),
        "ml_score": round(ml_score, 2) if ml_score is not None else None,
        "decision": decision,
        "severity": severity_of(final, decision),
        "mode": mode,
        "rule_hits": [h.to_dict() for h in hits],
    }
