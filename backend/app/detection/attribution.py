"""Quy kết cảnh báo (Phase 3, Milestone A): tách rõ luật nào KHỚP, luật nào GÓP ĐIỂM, detector nào là CHÍNH, và VÌ SAO
cảnh báo được tạo — hàm THUẦN, không đụng DB (pipeline gọi, test gọi thẳng).

Trước đây luồng thật (MR12) chỉ tạo alert `hybrid_risk` khi điểm hybrid vượt ngưỡng (`ActionBands.alert_at`), còn
`rule_id` là luật có TRỌNG SỐ cao nhất. Hệ quả đo được ở audit Phase 1: luật `enforce` khớp đúng nhưng trọng số thấp
(0,0–0,10) không bao giờ tạo alert, và khi nhiều luật cùng khớp thì `rule_id` chỉ phản ánh trọng số hiệu chỉnh trên
RBA chứ không phải hành vi đang diễn ra. Module này khôi phục đúng nghĩa đã ghi ở `app/detection/engine/registry.py`:

  - `enforce` + `verified` (`RuleSpec.verification`, Milestone B — B0.1): luật khớp thì TẠO CẢNH BÁO
    (`alert_reason="rule_enforced"`) — nhưng KHÔNG đổi hành động: `step_up`/`lock` vẫn chỉ do điểm hybrid quyết định
    (pipeline giữ nguyên `RiskResult.action`), ngưỡng toàn cục không đổi;
  - `enforce` + `experimental` (chưa qua kiểm chứng) hoặc `shadow`: luật khớp chỉ được GHI vào `matched_rules` /
    `secondary_signals` (và vẫn góp điểm qua trọng số như trước), không tự tạo cảnh báo. Lý do (đo được ở Milestone A):
    luật chưa kiểm chứng như `scripted_client` sinh hàng trăm cảnh báo phụ trong một đợt rải mật khẩu.

`primary_detector` chọn theo THỨ TỰ ƯU TIÊN CỐ ĐỊNH (`PRIORITY`), KHÔNG theo trọng số: luật mô tả HÀNH VI (đoán/dò mật
khẩu, ngữ cảnh tài khoản) đứng trước luật ĐÁNH DẤU (tự động hoá, danh tiếng hạ tầng) — rải mật khẩu kèm User-Agent kịch
bản thì hành vi là "rải mật khẩu", UA chỉ là chi tiết; trong cùng vai trò, luật đặc hiệu hơn đứng trước (dò phân tán
trước dò một tài khoản, vì mọi lần khớp `distributed_bruteforce` cũng thoả phần "nhiều lần sai" của `brute_force`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from app.detection.engine.registry import REGISTRY, RuleSpec
from app.detection.engine.types import RuleHit
from app.detection.hybrid import RiskResult

# Thứ tự ưu tiên chọn detector chính (đầu danh sách = ưu tiên cao nhất). `blocklist_hit` đứng đầu vì là quyết định của
# con người và là luật GHI ĐÈ điểm (xem `RuleWeights.override_rule_ids`).
PRIORITY: tuple[str, ...] = (
    "blocklist_hit",
    # --- hành vi: đoán/dò mật khẩu (đặc hiệu trước, tổng quát sau)
    "success_after_failures",
    "distributed_bruteforce",
    "credential_stuffing",
    "password_spray_slow",
    "username_enumeration",
    "brute_force",
    # --- hành vi: ngữ cảnh tài khoản
    "impossible_travel",
    "multi_context_simultaneous",
    "dormant_account_login",
    "country_hop",
    "rare_network_login",
    # --- đánh dấu: danh tiếng hạ tầng / tự động hoá
    "tor_exit",
    "ua_rotation",
    "regular_rhythm",
    "scripted_client",
    "bot_user_agent",
    "datacenter_ip",
    "vpn_ip",
)
_RANK = {rule_id: i for i, rule_id in enumerate(PRIORITY)}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

# Tên hành vi (dùng trong báo cáo/dashboard) của từng detector.
BEHAVIOR_OF: dict[str, str] = {
    "blocklist_hit": "blocklisted_source",
    "success_after_failures": "success_after_failures",
    "distributed_bruteforce": "distributed_brute_force",
    "credential_stuffing": "credential_stuffing",
    "password_spray_slow": "password_spraying",
    "username_enumeration": "username_enumeration",
    "brute_force": "brute_force",
    "impossible_travel": "impossible_travel",
    "multi_context_simultaneous": "multi_country_simultaneous_login",
    "dormant_account_login": "dormant_account_reactivation",
    "country_hop": "country_hopping",
    "rare_network_login": "rare_network_login",
    "tor_exit": "tor_login",
    "ua_rotation": "user_agent_rotation",
    "regular_rhythm": "machine_like_timing",
    "scripted_client": "scripted_client",
    "bot_user_agent": "bot_user_agent",
    "datacenter_ip": "datacenter_login",
    "vpn_ip": "vpn_login",
}
ML_ONLY_DETECTOR = "hybrid_ml"
ML_ONLY_BEHAVIOR = "ml_anomaly"

ALERT_REASON_OVERRIDE = "override"
ALERT_REASON_SCORE = "score_threshold"
ALERT_REASON_RULE = "rule_enforced"


def _sort_key(hit: RuleHit, registry: Mapping[str, RuleSpec]) -> tuple:
    """Luật ngoài `PRIORITY` (thêm sau này mà quên xếp hạng) xếp SAU mọi luật đã xếp, rồi theo mức nghiêm trọng giảm dần."""
    spec = registry.get(hit.rule_id)
    severity = _SEVERITY_RANK.get(hit.severity or (spec.severity if spec else "low"), 0)
    return (_RANK.get(hit.rule_id, len(PRIORITY)), -severity, hit.rule_id)


def choose_primary(hits: Iterable[RuleHit], registry: Mapping[str, RuleSpec] | None = None) -> RuleHit | None:
    registry = REGISTRY if registry is None else registry
    ordered = sorted(hits, key=lambda h: _sort_key(h, registry))
    return ordered[0] if ordered else None


@dataclass(frozen=True)
class Verdict:
    """Kết quả quy kết của MỘT lần thử. `alert=False` nghĩa là không có lý do nào để tạo cảnh báo (vẫn trả về đầy đủ
    `matched_rules` để ghi vết)."""

    alert: bool
    alert_reason: str | None
    primary_detector: str | None  # mã luật, `ML_ONLY_DETECTOR` nếu chỉ ML vượt ngưỡng, None nếu không cảnh báo
    behavior: str | None
    severity: str | None  # mức nghiêm trọng của CHÍNH luật detector (None nếu chỉ ML)
    matched_rules: tuple[str, ...]
    enforced_rules: tuple[str, ...]  # chế độ enforce (kể cả experimental)
    shadow_rules: tuple[str, ...]
    contributing_rules: tuple[dict[str, Any], ...]
    standalone_rules: tuple[str, ...] = ()  # enforce + verified: đủ tư cách TỰ tạo cảnh báo
    experimental_rules: tuple[str, ...] = ()  # enforce nhưng chưa kiểm chứng
    evidence: dict[str, Any] = field(default_factory=dict)
    primary_message: str | None = None
    primary_weight: float | None = None

    @property
    def is_rule_primary(self) -> bool:
        return self.primary_detector is not None and self.primary_detector != ML_ONLY_DETECTOR

    @property
    def secondary_signals(self) -> tuple[str, ...]:
        """Mọi luật đã khớp TRỪ detector chính — tín hiệu bổ trợ, không tạo cảnh báo riêng."""
        return tuple(r for r in self.matched_rules if r != self.primary_detector)

    def to_explanation(self, risk_result: RiskResult) -> dict[str, Any]:
        """Các khoá mới ghi vào `Alert.explanation` (JSON sẵn có — không cần migration). Không bao giờ chứa mật khẩu:
        `evidence` chỉ là `Finding.evidence` của luật (số đếm, IP, tên đăng nhập, ngưỡng)."""
        return {
            "behavior": self.behavior,
            "primary_detector": self.primary_detector,
            "matched_rules": list(self.matched_rules),
            "secondary_signals": list(self.secondary_signals),
            "enforced_rules": list(self.enforced_rules),
            "standalone_rules": list(self.standalone_rules),
            "experimental_rules": list(self.experimental_rules),
            "shadow_rules": list(self.shadow_rules),
            "contributing_rules": [dict(c) for c in self.contributing_rules],
            "risk_score": risk_result.score,
            "ml_probability": None if risk_result.ml_probability is None else round(risk_result.ml_probability, 4),
            "alert_reason": self.alert_reason,
            "evidence": dict(self.evidence),
        }


def build_verdict(hits: Iterable[RuleHit], risk_result: RiskResult, registry: Mapping[str, RuleSpec] | None = None) -> Verdict:
    """Quyết định CÓ tạo cảnh báo không và quy kết cho detector nào.

    Thứ tự lý do (`alert_reason`): luật ghi đè (`override`) > điểm hybrid đã vượt ngưỡng (`score_threshold`, tức
    `risk_result.action != "allow"`) > có luật `enforce` ĐÃ KIỂM CHỨNG khớp (`rule_enforced`). Detector chính: luật ghi
    đè nếu có; nếu không thì luật ưu tiên cao nhất trong nhóm đủ tư cách tự cảnh báo (enforce + verified); điểm vượt
    ngưỡng mà nhóm đó rỗng thì lần lượt xét luật enforce chưa kiểm chứng rồi luật shadow; không luật nào khớp mà điểm
    vượt ngưỡng thì là `ML_ONLY_DETECTOR`."""
    registry = REGISTRY if registry is None else registry
    hits = list(hits)
    enforced = [h for h in hits if not h.is_shadow]
    shadow = [h for h in hits if h.is_shadow]
    standalone = [h for h in enforced if (spec := registry.get(h.rule_id)) is not None and spec.is_verified]
    experimental = [h for h in enforced if h not in standalone]
    weights = {c.source: c.weight for c in risk_result.contributions}
    contributing = tuple(
        {"rule": c.source, "weight": round(c.weight, 4), "group": c.group}
        for c in risk_result.contributions
        if c.group != "ml" and c.weight > 0
    )
    common = dict(
        matched_rules=tuple(h.rule_id for h in hits),
        enforced_rules=tuple(h.rule_id for h in enforced),
        shadow_rules=tuple(h.rule_id for h in shadow),
        contributing_rules=contributing,
        standalone_rules=tuple(h.rule_id for h in standalone),
        experimental_rules=tuple(h.rule_id for h in experimental),
    )

    if risk_result.overridden_by is not None:
        reason = ALERT_REASON_OVERRIDE
        primary = next((h for h in hits if h.rule_id == risk_result.overridden_by), None)
    elif risk_result.action != "allow":
        reason = ALERT_REASON_SCORE
        primary = choose_primary(standalone, registry) or choose_primary(experimental, registry) or choose_primary(shadow, registry)
    elif standalone:
        reason = ALERT_REASON_RULE
        primary = choose_primary(standalone, registry)
    else:
        return Verdict(alert=False, alert_reason=None, primary_detector=None, behavior=None, severity=None, **common)

    if primary is None:  # chỉ ML (hoặc danh tiếng không có luật) đẩy điểm vượt ngưỡng
        return Verdict(alert=True, alert_reason=reason, primary_detector=ML_ONLY_DETECTOR, behavior=ML_ONLY_BEHAVIOR, severity=None, **common)
    return Verdict(
        alert=True, alert_reason=reason, primary_detector=primary.rule_id, behavior=BEHAVIOR_OF.get(primary.rule_id, primary.rule_id),
        severity=primary.severity, evidence=dict(primary.evidence), primary_message=primary.message,
        primary_weight=weights.get(primary.rule_id), **common,
    )


def max_severity(*severities: str | None) -> str:
    """Mức nghiêm trọng cao nhất trong các giá trị (bỏ qua None); mặc định "low"."""
    known = [s for s in severities if s in _SEVERITY_RANK]
    return max(known, key=_SEVERITY_RANK.__getitem__) if known else "low"
