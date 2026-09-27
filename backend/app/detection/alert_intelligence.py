"""MR13 — "Cảnh báo thông minh v2": so lần đăng nhập với lịch sử tài khoản (novelty), gán họ tấn công GỢI Ý (không
khẳng định), chống trùng lặp và xếp hạng ưu tiên cho cảnh báo `hybrid_risk` (MR12). Đo bằng kịch bản có nhãn tự tạo
(RBA không có nhãn "họ tấn công", chỉ có ATO nhị phân — xem project_rba_dataset.md): `backend/scripts/alert_intelligence_sim.py`.

Bốn mảnh, cố ý THUẦN (không đụng DB) để test được không cần DB thật — orchestration (đọc/ghi `Alert`, tra cứu chống
trùng lặp) nằm ở `app/detection/pipeline.py`, chỉ dùng lại `DEDUP_WINDOW`/`action_escalated` khai ở đây:
  1. `compute_novelty`       — khía cạnh MỚI so với lịch sử THÀNH CÔNG của tài khoản (quốc gia/nhà mạng/thiết bị).
  2. `suggest_attack_family` — GỢI Ý họ tấn công + độ tin cậy, từ bằng chứng DẪN ĐẦU của `RiskResult` (MR11).
  3. `priority_score`        — novelty × độ tin cậy × `User.importance`, dùng để sắp `GET /alerts`.
  4. `build_alert_message`   — câu tiếng Việt gộp cả ba, giữ ngắn gọn (D4: vẫn top-3 lý do như hybrid_risk hiện có).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta

from app.detection.engine.registry import REGISTRY, RuleSpec
from app.detection.hybrid import RiskResult
from ml.rba.explain import COMPONENT_LABELS
from ml.rba.features import EventRecord, HistorySummary

# --------------------------------------------------------------------------------------------------------- novelty

_ATTR_LABELS = {"country": "quốc gia", "asn": "nhà mạng", "device": "thiết bị"}
_DEVICE_LABELS_VI = {"mobile": "di động", "desktop": "máy tính", "tablet": "máy tính bảng", "bot": "bot"}
# Thứ tự ưu tiên khi CHỈ chọn MỘT khía cạnh mới lạ đưa vào message (giữ ngắn gọn — xem build_alert_message); không ảnh
# hưởng priority_score (dùng SỐ LƯỢNG khía cạnh mới, không quan tâm khía cạnh nào).
_NOVELTY_PRIORITY = ("country", "asn", "device")


def _attr_value(event: EventRecord, attr: str) -> str | None:
    if attr == "country":
        return event.country
    if attr == "asn":
        return None if event.asn is None else f"AS{event.asn}"
    if attr == "device":
        if event.device_type in (None, "unknown"):
            return None  # "chưa rõ" không phải là một GIÁ TRỊ để so sánh mới/cũ
        return _DEVICE_LABELS_VI.get(event.device_type, event.device_type)
    raise ValueError(f"thuộc tính novelty không hợp lệ: {attr}")


@dataclass(frozen=True)
class NoveltyFact:
    """Một khía cạnh MỚI so với lịch sử thành công của tài khoản. Khác `new_country`/`new_asn`/`new_device` (nhị phân,
    `ml/rba/features.py`, dùng để TRAIN mô hình): ở đây kèm luôn GIÁ TRỊ quen thuộc nhất và ĐÃ DÙNG BAO NHIÊU LẦN, để
    viết được câu "lần đầu quốc gia này, trước đó dùng X N lần" — đúng bullet đầu của MR13 (docs/checklist.md)."""

    attribute: str  # "country" | "asn" | "device"
    new_value: str  # giá trị lần này
    usual_value: str | None  # giá trị hay gặp nhất trước đó (None nếu tài khoản có lần thành công nhưng chưa từng có giá trị thuộc tính này)
    usual_count: int  # số lần THÀNH CÔNG trước đó mang giá trị usual_value (0 nếu usual_value None)

    @property
    def text(self) -> str:
        label = _ATTR_LABELS[self.attribute]
        if self.usual_value is None:
            return f"lần đầu {label} này ({self.new_value})"
        return f"lần đầu {label} này ({self.new_value}), trước đó dùng {self.usual_value} {self.usual_count} lần"


def compute_novelty(event: EventRecord, summary: HistorySummary) -> list[NoveltyFact]:
    """Mọi khía cạnh MỚI của `event` so với lịch sử THÀNH CÔNG của tài khoản — rỗng nếu tài khoản không tồn tại hoặc
    CHƯA từng đăng nhập thành công (khi đó mọi thứ đều "mới", so sánh không có ý nghĩa gì để nói)."""
    successes = [e for e in (summary.user_events or []) if e.success]
    if not successes:
        return []
    facts: list[NoveltyFact] = []
    for attr in _NOVELTY_PRIORITY:
        current = _attr_value(event, attr)
        if current is None:
            continue
        counts = Counter(v for e in successes if (v := _attr_value(e, attr)) is not None)
        if counts.get(current, 0) > 0:
            continue  # đã từng thấy giá trị này — không phải novelty
        usual_value, usual_count = counts.most_common(1)[0] if counts else (None, 0)
        facts.append(NoveltyFact(attr, current, usual_value, usual_count))
    return facts


# ------------------------------------------------------------------------------------------------- gán họ tấn công

# 3 thành phần của HybridMinTail (ml/rba/ensemble.py, mô hình hybrid_cp2 đang active) -> nhãn tiếng Việt. TÁI DÙNG
# COMPONENT_LABELS của ml/rba/explain.py (MR8) thay vì định nghĩa lại — một cái tên không nên có hai bản dịch khác nhau.
ML_COMPONENT_FAMILY: dict[str, str] = dict(COMPONENT_LABELS)


def suggest_attack_family(
    risk_result: RiskResult, *, ml_component: str | None, registry: dict[str, RuleSpec] | None = None
) -> tuple[str | None, float | None]:
    """(họ tấn công GỢI Ý, độ tin cậy 0-1) từ bằng chứng DẪN ĐẦU của `risk_result.contributions` (đã sắp giảm dần theo
    trọng số — xem docstring `RiskResult`). `(None, None)` nếu không có bằng chứng nào (action="allow" thực tế không
    tạo alert nên nhánh này hiếm khi được gọi tới).

    Bằng chứng LUẬT/danh tiếng được ưu tiên hơn ML bất kể trọng số ai cao hơn — CỐ Ý, hai lý do: (1) nhất quán với
    `rule_id` (`app/detection/pipeline.py` đã chọn bằng chứng KHÔNG PHẢI "ml" đầu tiên cho `rule_id` từ MR12; family
    đi cùng nguồn với rule_id thì hai trường không "đá nhau" trên cùng một alert); (2) một luật có điều kiện khớp cụ
    thể, kiểm tra lại được LUÔN đáng tin hơn một điểm ML trên hệ thống demo — đo thật bằng
    backend/scripts/alert_intelligence_sim.py phát hiện: mô hình `hybrid_cp2` một mình có thể vượt ngưỡng "alert" chỉ
    vì ASN/quốc gia Việt Nam CỰC HIẾM so với phân bố huấn luyện RBA (đúng phát hiện PSI drift đã ghi ở MR12/docs/realtime-integration.md,
    ở đây thấy CỤ THỂ: nếu không ưu tiên luật, cảnh báo có luật rõ ràng như blocklist_hit sẽ bị gán nhầm thành "đăng
    nhập bất thường" chỉ vì lúc đó ML tình cờ có trọng số cao hơn). Chỉ dùng ML khi KHÔNG có bằng chứng luật/danh tiếng
    nào — khi đó CHÍNH bằng chứng duy nhất là ML nên không có lựa chọn nào đáng tin hơn để ưu tiên.

    LUÔN LÀ GỢI Ý: đây là MỘT LOOKUP đơn giản (nhóm luật đã khớp hoặc thành phần ML dẫn đầu), KHÔNG PHẢI một mô hình
    phân loại họ tấn công được huấn luyện riêng — chưa có nhãn "họ tấn công" thật để train (RBA chỉ có ATO nhị phân).
    Độ chính xác của gợi ý này được đo trên kịch bản có nhãn tự tạo (backend/scripts/alert_intelligence_sim.py), KHÔNG
    PHẢI trên ATO thật của RBA."""
    if not risk_result.contributions:
        return None, None
    registry = REGISTRY if registry is None else registry
    non_ml = [c for c in risk_result.contributions if c.group != "ml"]
    if non_ml:
        top = non_ml[0]  # contributions đã sắp giảm dần theo weight; lọc bỏ "ml" vẫn giữ đúng thứ tự giữa phần còn lại
        spec = registry.get(top.source)
        return (spec.category if spec is not None else None), top.weight
    top = risk_result.contributions[0]  # chỉ còn "ml" — không có lựa chọn nào khác
    family = ML_COMPONENT_FAMILY.get(ml_component or "") or "đăng nhập bất thường (mô hình học máy)"
    return family, top.weight


# ------------------------------------------------------------------------------------------------------- ưu tiên


def priority_score(novelty_facts: list[NoveltyFact], confidence: float | None, importance: float) -> float:
    """`novelty_level` (1 + số khía cạnh mới, tức 1..4) × độ tin cậy (0 nếu không rõ) × `importance` (User.importance,
    mặc định 1.0 mọi tài khoản). KHÔNG thay `severity`/`risk_score` (vẫn từ `RiskResult.score`, mục 4.2) — chỉ đổi THỨ
    TỰ hiển thị của `GET /alerts`: "lạ" và "nghiêm trọng" là hai trục khác nhau, một alert điểm không quá cao nhưng
    CỰC lạ (quốc gia+nhà mạng+thiết bị đều mới) đáng xem trước một alert điểm hơi cao hơn nhưng chẳng có gì mới."""
    novelty_level = 1 + len(novelty_facts)
    return round(novelty_level * (confidence or 0.0) * importance, 4)


# -------------------------------------------------------------------------------------------------- chống trùng lặp

# Cùng (user_id hoặc IP nếu tài khoản không tồn tại) + attack_family trong cửa sổ này GỘP vào 1 hàng Alert thay vì tạo
# hàng mới (app/detection/pipeline.py). 15 phút: đủ dài để gộp MỘT đợt tấn công liên tục (vd brute_force báo lại ở MỖI
# lần sai từ ngưỡng trở lên — xem ghi chú "gộp cảnh báo trùng là việc của MR13" ở rules_auth.py), đủ ngắn để không gộp
# hai đợt tấn công CÁCH NHAU HÀNG GIỜ thành một — hằng số tự chọn, chưa đối chiếu với dữ liệu tấn công thật (out of
# scope MR13, xem giới hạn ở docs/alert-intelligence-v2.md).
DEDUP_WINDOW = timedelta(minutes=15)

_ACTION_RANK = {"allow": 0, "alert": 1, "step_up": 2, "lock": 3}


def action_escalated(previous_action: str, new_action: str) -> bool:
    """Có nên ghi thêm `response_actions`/`audit_log` khi CẬP NHẬT một alert đã gộp hay không: chỉ khi mức đề xuất
    TĂNG (vd alert -> lock) — không lặp lại đúng đề xuất cũ mỗi lần trùng, đúng tinh thần "chống trùng lặp"."""
    return _ACTION_RANK.get(new_action, 0) > _ACTION_RANK.get(previous_action, 0)


# -------------------------------------------------------------------------------------------------------- message


def build_alert_message(
    risk_result: RiskResult, *, novelty_facts: list[NoveltyFact], family: str | None, confidence: float | None, occurrence_count: int = 1
) -> str:
    """Câu tiếng Việt cho `Alert.message`. D4 (quyết định cùng người dùng ở MR13): vẫn TOP-3 lý do như message
    `hybrid_risk` hiện có (MR12) — KHÔNG rút xuống top-2. Thêm nhiều nhất MỘT khía cạnh mới lạ (khía cạnh đầu theo
    `_NOVELTY_PRIORITY`, nói cả 3 thì quá dài cho danh sách cảnh báo — xem docstring `NoveltyFact`) và tên họ tấn công
    GỢI Ý kèm %, LUÔN kèm chữ "gợi ý" (không bao giờ khẳng định chắc chắn)."""
    reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk_result.contributions[:3])
    parts = [f"Hybrid risk engine: điểm {risk_result.score}/100, đề xuất '{risk_result.action}' — {reasons}."]
    if novelty_facts:
        parts.append(novelty_facts[0].text[0].upper() + novelty_facts[0].text[1:] + ".")
    if family:
        conf_text = f" ({confidence:.0%})" if confidence is not None else ""
        parts.append(f"Họ tấn công gợi ý: {family}{conf_text}.")
    if occurrence_count > 1:
        parts.append(f"Đã lặp lại {occurrence_count} lần trong {int(DEDUP_WINDOW.total_seconds() // 60)} phút gần đây.")
    return " ".join(parts)
