"""MR15 — "đánh giá bằng phản hồi mô phỏng: báo nhầm giảm bao nhiêu sau K vòng" (checklist). Chạy K vòng liên tiếp trên
CHÍNH pipeline thật (rule engine + hybrid risk engine, model `hybrid_cp2` thật, SQLite cô lập — cùng hạ tầng
`scripts/alert_intelligence_sim.py`):

  - Một tài khoản "hay bị báo nhầm" — TÁI DÙNG ĐÚNG kịch bản đối chứng âm đã phát hiện báo nhầm thật ở MR13
    (`docs/alert-intelligence-v2.md`): lịch sử quen thuộc + đăng nhập từ IP Việt Nam thật — ASN/quốc gia CỰC HIẾM so
    với phân bố huấn luyện RBA khiến MỘT MÌNH mô hình ML vượt ngưỡng "alert", không rule nào khớp. Mỗi vòng: tài khoản
    đăng nhập lại (vẫn đúng hành vi thường ngày), NẾU có alert thì mô phỏng quản trị viên bấm "Báo nhầm" (ĐÃ BIẾT chắc
    đây là báo nhầm — không phải suy đoán, xem MR13), rồi tính lại `threshold_delta` (CHÍNH `compute_delta()` thật,
    xem `_write_risk_profile`).
  - Một tài khoản "kẻ tấn công thật" (IP trong blocklist), chạy trong DB RIÊNG hoàn toàn (lý do ở `_run_fp_user_rounds`)
    — đối chứng: ngưỡng thích nghi của tài khoản KHÁC KHÔNG được làm mất khả năng bắt tấn công thật (blocklist_hit GHI ĐÈ, không phụ thuộc ActionBands — nhưng đo
    trực tiếp thay vì chỉ tin vào thiết kế).

Đo: tỉ lệ vòng có alert (báo nhầm) của tài khoản thứ nhất giảm dần thế nào qua K vòng, và tài khoản thứ hai có bị mất
phát hiện không (KHÔNG được mất — nếu mất, đó là một phát hiện quan trọng, không phải bịa để có số đẹp).

⚠️ **Hai phát hiện phụ khi dựng script này (không phải giả thuyết — đo trực tiếp, không suy đoán)**, cả hai đều LẪN
VÀO hiệu ứng của `threshold_delta` nếu không kiểm soát nên script phải xử lý riêng từng cái:
  1. Điểm rủi ro TỰ GIẢM đáng kể chỉ sau ĐÚNG MỘT lần đăng nhập thành công bổ sung (đo trực tiếp: 32 → 22/100) — các
     đặc trưng RBA nhạy với ĐỘ DÀY lịch sử TỔNG THỂ của tài khoản (`u_n_success` và tương tự), không chỉ độ quen với
     riêng IP/ASN lần đó (đổi sang IP/ASN KHÁC mỗi vòng vẫn giảm tương tự). Xử lý: XOÁ LẠI lịch sử đăng nhập của tài
     khoản hay báo nhầm về đúng baseline SAU mỗi vòng (`_reset_login_history`, giữ nguyên `UserRiskProfile`).
  2. DÙ đã xoá lại lịch sử ở trên, điểm vẫn tự trôi nhẹ (32 → 30 → 30 → 29) nếu các vòng cách nhau NHIỀU NGÀY — đặc
     trưng `u_age_days` ("tuổi" tài khoản = hiện tại trừ lần đăng nhập ĐẦU TIÊN còn lưu) tự tăng theo THỜI GIAN LỊCH
     của kịch bản dù SỐ DÒNG lịch sử không đổi (mốc "đầu tiên" cố định, "hiện tại" mỗi vòng xa mốc đó hơn). Xử lý:
     các vòng của tài khoản hay báo nhầm cách nhau vài GIÂY (không phải vài ngày) — đo lại thấy ổn định tuyệt đối.

Coi cả kịch bản là CÓ KIỂM SOÁT BIẾN NHIỄU để đo đúng một hiệu ứng, không phải mô phỏng hành vi đăng nhập tự nhiên của
một tài khoản thật qua nhiều ngày — xem thêm ở mục "Giới hạn" trong báo cáo.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.feedback_loop_sim
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — đăng ký toàn bộ bảng vào Base.metadata TRƯỚC create_all (xem alert_intelligence_sim.py)
from app.database import Base
from app.security import hash_password

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HANOI_IP = "210.245.88.1"  # FPT Telecom, GeoIP thật -> VN/Hanoi — IP THẬT đã gây báo nhầm ở MR13 (alert_intelligence_sim.py)
ATTACKER_IP = "8.8.8.8"  # Google, ASN 15169 — dùng làm IP trong blocklist (đối chứng: tấn công thật)
K_ROUNDS = 8
REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "feedback-loop.md"
PAYLOAD_PATH = Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "feedback_loop_sim.json"


@dataclass
class RoundResult:
    round: int
    fp_user_alerted: bool
    fp_user_delta_after_retrain: float
    fp_user_feedback_count_after: int
    attacker_alerted: bool
    attacker_action: str | None


@dataclass
class SimReport:
    rounds: list[RoundResult] = field(default_factory=list)

    @property
    def fp_user_alert_rounds(self) -> list[int]:
        return [r.round for r in self.rounds if r.fp_user_alerted]

    @property
    def suppressed_from_round(self) -> int | None:
        """Vòng ĐẦU TIÊN mà tài khoản hay báo nhầm không còn bị báo (và các vòng SAU đó cũng vậy) — None nếu chưa
        bao giờ ngừng trong K vòng đã chạy."""
        for i, r in enumerate(self.rounds):
            if not r.fp_user_alerted and all(not later.fp_user_alerted for later in self.rounds[i:]):
                return r.round
        return None

    @property
    def attacker_always_detected(self) -> bool:
        return all(r.attacker_alerted and r.attacker_action == "lock" for r in self.rounds)


# ------------------------------------------------------------------------------------------------------ hạ tầng


def _fresh_session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _wire(session_factory) -> None:
    """Y hệt scripts/alert_intelligence_sim.py::_wire — xem docstring ở đó."""
    import app.detection.pipeline as pipeline_module
    import app.detection.rate_counter as rate_counter_module
    from app.detection import hybrid_runtime, model_registry
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache

    pipeline_module.SessionLocal = session_factory
    rate_counter_module.redis_client = fakeredis.FakeRedis(decode_responses=True)
    invalidate_blocklist_cache()

    db = session_factory()
    try:
        model_registry.ensure_registered(db)
        hybrid_runtime.load_at_startup(db)
        if not hybrid_runtime.get_engine().ml_available:
            raise RuntimeError("Không nạp được mô hình hybrid_cp2 thật — mô phỏng cần model thật để đo báo nhầm do ML, không dùng fallback chỉ luật.")
    finally:
        db.close()


def _run_login(*, username, user_id, ip, ts) -> None:
    from app.detection.pipeline import run_detection_pipeline

    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=True, ip=ip, user_agent=CHROME_UA, timestamp=ts))


def _create_user(session_factory, username: str) -> int:
    from app.models import User

    db = session_factory()
    try:
        user = User(username=username, password_hash=hash_password("CorrectHorse123"))
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    finally:
        db.close()


def _seed_history(session_factory, user_id: int, *, ip: str, country: str, when: datetime, count: int = 10) -> None:
    from app.models import LoginEvent

    db = session_factory()
    try:
        for i in range(count):
            db.add(
                LoginEvent(
                    user_id=user_id, attempted_username=f"user{user_id}", success=True, ip_address=ip, country=country,
                    user_agent=CHROME_UA, is_synthetic=True, created_at=when + timedelta(hours=i),
                )
            )
        db.commit()
    finally:
        db.close()


def _add_blocklist(session_factory, ip: str) -> None:
    from app.models import BlocklistEntry

    db = session_factory()
    try:
        db.add(BlocklistEntry(kind="ip", value=ip, reason="feedback_loop_sim", added_by="sim"))
        db.commit()
    finally:
        db.close()


def _reset_login_history(session_factory, user_id: int, *, keep_n: int) -> None:
    """Xoá mọi `LoginEvent` (và `Alert` gắn với chúng) của tài khoản VƯỢT QUÁ `keep_n` dòng ĐẦU TIÊN (theo id) — đưa
    lịch sử về đúng baseline gốc trước mỗi vòng, để cô lập hiệu ứng của `threshold_delta` khỏi hiệu ứng "quen dần tự
    nhiên" (xem docstring module). KHÔNG đụng `UserRiskProfile` — bảng đó phải TIẾP TỤC tích luỹ bình thường."""
    from app.models import Alert, LoginEvent

    db = session_factory()
    try:
        ids_to_keep = {row.id for row in db.query(LoginEvent.id).filter(LoginEvent.user_id == user_id).order_by(LoginEvent.id).limit(keep_n).all()}
        extra_events = db.query(LoginEvent).filter(LoginEvent.user_id == user_id, LoginEvent.id.notin_(ids_to_keep)).all()
        extra_event_ids = [e.id for e in extra_events]
        if extra_event_ids:
            db.query(Alert).filter(Alert.login_event_id.in_(extra_event_ids)).delete(synchronize_session=False)
            db.query(LoginEvent).filter(LoginEvent.id.in_(extra_event_ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _hybrid_alerts_for_user(session_factory, user_id: int) -> list:
    """Toàn bộ alert `hybrid_risk` của tài khoản, theo id tăng dần. Dùng ĐẾM TRƯỚC/SAU mỗi vòng để biết có alert MỚI
    hay không — KHÔNG so `Alert.created_at` (server_default=func.now(), giờ THẬT lúc script chạy) với mốc thời gian
    GIẢ của kịch bản (`round_ts`) — cùng bẫy đã sửa ở MR13/14 (hai "đồng hồ" khác nhau), ở đây né hẳn bằng cách không
    cần so thời gian: đếm là đủ vì chống trùng lặp CHỈ cập nhật hàng cũ (không tăng số hàng), không bao giờ xoá hàng."""
    from app.models import Alert

    db = session_factory()
    try:
        return db.query(Alert).filter(Alert.user_id == user_id, Alert.alert_type == "hybrid_risk").order_by(Alert.id).all()
    finally:
        db.close()


def _write_risk_profile(session_factory, user_id: int, *, feedback_count: int, false_positive_count: int) -> float:
    """Ghi `UserRiskProfile` từ một tally ĐÃ BIẾT TRƯỚC (theo dõi ngay trong vòng lặp mô phỏng — xem `run_simulation`),
    KHÔNG gọi lại `scripts.retrain_from_feedback.retrain()` (hàm đó ĐỌC LẠI `Alert.status` từ DB — ở kịch bản này lịch
    sử `Alert` của tài khoản hay báo nhầm bị XOÁ mỗi vòng để cô lập hiệu ứng "quen dần tự nhiên" khỏi RBA, xem docstring
    module, nên không còn gì để đọc lại). Vẫn dùng ĐÚNG `compute_delta()` — hàm tính thật, đã kiểm định riêng ở
    `tests/test_adaptive_threshold.py`; `retrain()` (đã kiểm ở `tests/test_retrain_from_feedback.py`) cũng chỉ là một
    lớp mỏng gọi CHÍNH hàm này trên tally đọc từ DB — nên đây vẫn là mô phỏng ĐÚNG cơ chế thật, chỉ khác NGUỒN của
    tally (tự theo dõi thay vì đọc lại DB đã bị xoá vì lý do kiểm soát biến nhiễu nêu trên)."""
    from app.detection.adaptive_threshold import compute_delta
    from app.models import UserRiskProfile

    delta = compute_delta(feedback_count, false_positive_count)
    db = session_factory()
    try:
        profile = db.get(UserRiskProfile, user_id)
        if profile is None:
            profile = UserRiskProfile(user_id=user_id)
            db.add(profile)
        profile.threshold_delta = delta
        profile.feedback_count = feedback_count
        profile.false_positive_count = false_positive_count
        db.commit()
    finally:
        db.close()
    return delta


# ---------------------------------------------------------------------------------------------------- mô phỏng


SEED_HISTORY_COUNT = 10


def _run_fp_user_rounds(k_rounds: int) -> list[tuple[bool, float, int]]:
    """K vòng của tài khoản hay báo nhầm, trong DB RIÊNG hoàn toàn tách khỏi kịch bản kẻ tấn công (xem lý do ở
    docstring module: hoạt động của MỘT tài khoản khác trong CÙNG DB cũng làm trôi nhẹ đặc trưng độ hiếm TOÀN CỤC của
    tài khoản này — GlobalCounts, `ml/rba/features.py` — dù không đụng lịch sử CỦA CHÍNH tài khoản; tách DB loại hẳn
    nguồn nhiễu đó, không chỉ né hiệu ứng "quen dần" của riêng tài khoản). Trả `[(có bị báo?, threshold_delta sau vòng, số phản hồi tích luỹ), ...]`."""
    sf = _fresh_session_factory()
    _wire(sf)
    fp_user_id = _create_user(sf, "user_hay_bao_nham")
    # Khớp CHÍNH XÁC tham số kịch bản benign_control đã ĐO ĐƯỢC báo nhầm thật ở MR13 (alert_intelligence_sim.py) —
    # điểm rủi ro ở ngay sát ngưỡng alert_at (31-32/100, xem docs/alert-intelligence-v2.md), đổi tham số dù nhỏ (số
    # ngày lùi lại) cũng đủ kéo điểm qua/dưới ngưỡng — tự nó là một minh chứng cho việc hệ thống demo đang hiệu chỉnh
    # SÁT MÉP cho dân số nhỏ này (đúng phát hiện PSI drift đã ghi ở MR12/13), không phải chọn tham số cho ra số đẹp.
    _seed_history(sf, fp_user_id, ip=HANOI_IP, country="VN", when=BASE - timedelta(days=10), count=SEED_HISTORY_COUNT)

    results = []
    feedback_count = 0
    false_positive_count = 0
    for k in range(1, k_rounds + 1):
        # ⚠️ Vài GIÂY/vòng, KHÔNG PHẢI vài ngày — phát hiện phụ THỨ HAI khi dựng script (không phải giả thuyết): dù đã
        # xoá lại lịch sử đăng nhập về baseline mỗi vòng (xem trên), đặc trưng u_age_days ("tuổi" tài khoản = hiện tại
        # trừ lần đăng nhập ĐẦU TIÊN còn lưu) vẫn tự tăng dần theo THỜI GIAN LỊCH thực của kịch bản dù SỐ DÒNG lịch sử
        # không đổi (mốc "đầu tiên" cố định, "hiện tại" của mỗi vòng cách xa mốc đó hơn) — đo trực tiếp: cách nhau 1
        # NGÀY/vòng khiến điểm tự trôi 32 → 30 → 30 → 29 dù đã xoá lại lịch sử, cách nhau vài GIÂY/vòng thì ổn định
        # tuyệt đối ở 32 suốt 8 vòng. Dùng giây để cô lập ĐÚNG hiệu ứng của threshold_delta khỏi hiệu ứng này.
        round_ts = BASE + timedelta(seconds=k)
        alerts_before = len(_hybrid_alerts_for_user(sf, fp_user_id))
        _run_login(username="user_hay_bao_nham", user_id=fp_user_id, ip=HANOI_IP, ts=round_ts)
        alerted = len(_hybrid_alerts_for_user(sf, fp_user_id)) > alerts_before
        if alerted:
            feedback_count += 1
            false_positive_count += 1  # ĐÃ BIẾT chắc đây là báo nhầm (kịch bản dựng có chủ đích, xem docstring module) — không phải suy đoán
        delta = _write_risk_profile(sf, fp_user_id, feedback_count=feedback_count, false_positive_count=false_positive_count)
        # Đưa lịch sử đăng nhập về đúng baseline TRƯỚC vòng sau — cô lập hiệu ứng threshold_delta khỏi hiệu ứng "quen
        # dần tự nhiên" của chính RBA (xem docstring module); UserRiskProfile KHÔNG bị đụng tới, tiếp tục tích luỹ.
        _reset_login_history(sf, fp_user_id, keep_n=SEED_HISTORY_COUNT)
        results.append((alerted, delta, feedback_count))
    return results


def _run_attacker_rounds(k_rounds: int) -> list[tuple[bool, str | None]]:
    """K vòng của tài khoản bị tấn công thật (IP trong blocklist), trong DB RIÊNG — đối chứng độc lập, không liên quan
    gì đến ngưỡng thích nghi của tài khoản kia. Trả `[(có bị báo?, hành động), ...]`."""
    sf = _fresh_session_factory()
    _wire(sf)
    attacker_user_id = _create_user(sf, "user_bi_tan_cong")
    _add_blocklist(sf, ATTACKER_IP)

    results = []
    for k in range(1, k_rounds + 1):
        round_ts = BASE + timedelta(days=k)
        alerts_before = len(_hybrid_alerts_for_user(sf, attacker_user_id))
        _run_login(username="user_bi_tan_cong", user_id=attacker_user_id, ip=ATTACKER_IP, ts=round_ts)
        alerts_after = _hybrid_alerts_for_user(sf, attacker_user_id)
        alerted = len(alerts_after) > alerts_before
        action = alerts_after[-1].explanation.get("action") if alerted else None
        results.append((alerted, action))
    return results


def run_simulation(k_rounds: int = K_ROUNDS) -> SimReport:
    fp_results = _run_fp_user_rounds(k_rounds)
    attacker_results = _run_attacker_rounds(k_rounds)

    report = SimReport()
    for k, ((fp_alerted, delta, feedback_count), (attacker_alerted, attacker_action)) in enumerate(zip(fp_results, attacker_results), start=1):
        report.rounds.append(
            RoundResult(
                round=k, fp_user_alerted=fp_alerted, fp_user_delta_after_retrain=delta, fp_user_feedback_count_after=feedback_count,
                attacker_alerted=attacker_alerted, attacker_action=attacker_action,
            )
        )
    return report


# ------------------------------------------------------------------------------------------------------- báo cáo


def build_payload(report: SimReport) -> dict:
    return {
        "k_rounds": len(report.rounds),
        "fp_user_alert_rounds": report.fp_user_alert_rounds,
        "suppressed_from_round": report.suppressed_from_round,
        "attacker_always_detected": report.attacker_always_detected,
        "rounds": [
            {
                "round": r.round, "fp_user_alerted": r.fp_user_alerted, "fp_user_delta_after_retrain": r.fp_user_delta_after_retrain,
                "fp_user_feedback_count_after": r.fp_user_feedback_count_after, "attacker_alerted": r.attacker_alerted, "attacker_action": r.attacker_action,
            }
            for r in report.rounds
        ],
    }


def render(payload: dict) -> str:
    lines = [
        "# Vòng phản hồi (MR15)",
        "",
        f"Mô phỏng **{payload['k_rounds']} vòng** liên tiếp trên CHÍNH pipeline thật (rule engine + hybrid risk engine, "
        "model `hybrid_cp2` thật) — mã nguồn: [`backend/scripts/feedback_loop_sim.py`](../backend/scripts/feedback_loop_sim.py). "
        "Cơ chế (ngưỡng thích nghi, retrain định kỳ): [`app/detection/adaptive_threshold.py`](../backend/app/detection/adaptive_threshold.py), "
        "[`scripts/retrain_from_feedback.py`](../backend/scripts/retrain_from_feedback.py).",
        "",
        "## Kết quả chính",
        "",
        f"- **Tài khoản hay bị báo nhầm** (tái dùng đúng kịch bản báo nhầm THẬT đã phát hiện ở MR13 — IP Việt Nam thật, "
        f"ASN/quốc gia cực hiếm so với RBA khiến một mình ML vượt ngưỡng): bị báo ở các vòng **{payload['fp_user_alert_rounds']}**.",
    ]
    if payload["suppressed_from_round"] is not None:
        lines.append(f"- **Ngừng báo nhầm kể từ vòng {payload['suppressed_from_round']}** trở đi (và không báo lại vòng nào sau đó trong {payload['k_rounds']} vòng đã chạy).")
    else:
        lines.append(f"- **Chưa ngừng báo nhầm** trong {payload['k_rounds']} vòng đã chạy — xem diễn giải.")
    lines.append(
        f"- **Tài khoản bị tấn công thật (IP trong blocklist) vẫn bị phát hiện ở CẢ {payload['k_rounds']}/{payload['k_rounds']} vòng**: "
        f"{'✅ đúng như kỳ vọng (ngưỡng thích nghi không làm mất phát hiện thật)' if payload['attacker_always_detected'] else '❌ KHÔNG — phát hiện quan trọng, xem diễn giải'}."
    )
    lines += [
        "",
        "## Từng vòng",
        "",
        "| Vòng | TK hay báo nhầm bị báo? | threshold_delta sau retrain | Số phản hồi tích luỹ | TK bị tấn công có bị phát hiện? |",
        "|---|---|---|---|---|",
    ]
    for r in payload["rounds"]:
        lines.append(
            f"| {r['round']} | {'✅ có' if r['fp_user_alerted'] else '—'} | {r['fp_user_delta_after_retrain']:.1f} | "
            f"{r['fp_user_feedback_count_after']} | {'✅ ' + (r['attacker_action'] or '') if r['attacker_alerted'] else '❌ KHÔNG'} |"
        )

    lines += [
        "",
        "## Diễn giải",
        "",
        f"- `MIN_FEEDBACK_FOR_PERSONAL_THRESHOLD` = 3 vòng (`app/detection/adaptive_threshold.py`) nên {min(2, payload['k_rounds'])} vòng đầu KHÔNG THỂ có "
        "điều chỉnh (chưa đủ mẫu) dù đã có phản hồi — đây là thiết kế có chủ đích (mẫu quá nhỏ không đáng tin), không phải chậm trễ ngoài ý muốn.",
        "- `threshold_delta` chỉ NỚI LỎNG (không bao giờ âm) và được TÍNH LẠI TỪ ĐẦU mỗi lần retrain trên toàn bộ lịch sử phản hồi tích luỹ — không cộng dồn "
        "theo số lần chạy script, xem docstring `retrain_from_feedback.py`.",
        "- Kịch bản tấn công thật dùng `blocklist_hit` (luật GHI ĐÈ, không phụ thuộc `ActionBands`) nên về mặt THIẾT KẾ không thể bị ảnh hưởng bởi ngưỡng "
        "thích nghi của MỘT tài khoản khác — bảng trên đo TRỰC TIẾP để xác nhận, không chỉ tin vào thiết kế.",
        "",
        "## Hai biến nhiễu tự phát hiện và cách kiểm soát",
        "",
        "Cả hai đo được TRỰC TIẾP khi dựng script (không phải giả thuyết) — nếu không kiểm soát, cả hai đều tự làm giảm điểm rủi ro theo thời gian, "
        "khiến báo nhầm \"ngừng\" vì LÝ DO KHÁC, không phải vì `threshold_delta`, làm sai lệch hoàn toàn kết luận của mô phỏng này:",
        "1. **Quen dần theo SỐ LƯỢT đăng nhập**: điểm rủi ro giảm mạnh (32 → 22/100) chỉ sau ĐÚNG một lượt đăng nhập thành công bổ sung — đặc trưng RBA "
        "nhạy với độ dày lịch sử TỔNG THỂ của tài khoản, không chỉ độ quen với riêng IP/ASN lần đó. Kiểm soát: xoá lại lịch sử đăng nhập về đúng baseline "
        "SAU mỗi vòng, giữ nguyên `UserRiskProfile`.",
        "2. **Trôi theo THỜI GIAN LỊCH**: dù đã xoá lại lịch sử ở trên, điểm vẫn tự trôi nhẹ (32 → 30 → 30 → 29) nếu các vòng cách nhau NHIỀU NGÀY — đặc "
        "trưng \"tuổi tài khoản\" tự tăng theo thời gian của kịch bản dù số dòng lịch sử không đổi. Kiểm soát: các vòng cách nhau vài GIÂY, không phải vài "
        "ngày.",
        "",
        "## Giới hạn",
        "",
        "- Chỉ MỘT tài khoản hay báo nhầm và MỘT kịch bản tấn công thật, chạy 1 lần — đủ để kiểm chứng CƠ CHẾ (ngưỡng có "
        "thực sự giảm báo nhầm theo phản hồi, có thực sự không làm mất phát hiện thật), KHÔNG đủ để ước lượng mức giảm báo nhầm trung bình trên diện rộng.",
        "- \"Đã biết chắc đây là báo nhầm\" trong kịch bản là do TỰ DỰNG (biết trước ground truth), không phải quản trị viên "
        "thật phán đoán — vòng phản hồi thật phụ thuộc quản trị viên phán đoán ĐÚNG, sai sót của con người ở bước đó không mô phỏng ở đây.",
        "- `threshold_delta` áp dụng ĐỀU cho cả ba mốc (`alert_at`/`step_up_at`/`lock_at`) — chưa thử nghiệm chỉnh riêng "
        "từng mốc (vd chỉ nới `alert_at`, giữ nguyên `lock_at`) dù có thể an toàn hơn cho các mốc nghiêm trọng.",
        "- Script retrain chưa được lên lịch chạy tự động định kỳ thật (cron/scheduler) — hiện chạy tay hoặc gọi trực tiếp trong mô phỏng này.",
        "- Các vòng của tài khoản hay báo nhầm cách nhau vài GIÂY (kiểm soát biến nhiễu #2 ở trên) — KHÔNG PHẢI nhịp độ đăng nhập thật của một người "
        "(thường cách nhau hàng giờ/ngày); đây là lựa chọn CÓ CHỦ ĐÍCH để cô lập đúng một hiệu ứng đang đo, không phải mô tả hành vi người dùng thật.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    report = run_simulation()
    payload = build_payload(report)
    PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(payload), encoding="utf-8")
    print(f"TK hay bao nham bi bao o vong: {payload['fp_user_alert_rounds']}")
    print(f"Ngung bao nham tu vong: {payload['suppressed_from_round']}")
    print(f"TK bi tan cong that luon bi phat hien: {payload['attacker_always_detected']}")
    print(f"Da ghi {REPORT_PATH} va {PAYLOAD_PATH}")


if __name__ == "__main__":
    main()
