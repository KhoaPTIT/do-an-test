"""MR18 — checklist "runner chạy tất cả [9 kịch bản] và ghi: có phát hiện không, thời gian phát hiện, bằng rule/ML/
hybrid, số cảnh báo" + "scorecard đưa vào báo cáo, kể cả các ca hệ thống không bắt được".

Chạy MỖI kịch bản (`ml/attack_scenarios.py`) MỘT LẦN qua CHÍNH pipeline thật (rule engine v2 [MR9-10] + hybrid risk
engine thật [MR11], model `hybrid_cp2`) trên hạ tầng cô lập của `tests/conftest.py` (SQLite in-memory + fakeredis) —
DB MỚI TINH cho MỖI kịch bản, không đụng Postgres/Redis dev thật, không kịch bản nào ảnh hưởng kịch bản khác (cùng kỷ
luật `scripts/alert_intelligence_sim.py`, MR13).

Chỉ chạy 1 lần/kịch bản (không phải K "trial" ngẫu nhiên) — mỗi kịch bản đã được HIỆU CHỈNH có chủ đích để vượt hẳn
(không sát ngưỡng) thông số thật của luật nó nhắm tới (kiểm bằng test THUẦN riêng, `tests/test_attack_scenarios.py`,
đối chiếu trực tiếp với `REGISTRY`) — không có nguồn ngẫu nhiên nào thật sự khiến chạy lại cho số khác, "K trial giống
hệt nhau" sẽ chỉ là số đẹp giả tạo, không phải bằng chứng thống kê thật.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.attack_scenario_runner
"""

from __future__ import annotations

import asyncio
import json
import random
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import fakeredis
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — đăng ký toàn bộ bảng vào Base.metadata TRƯỚC create_all (xem alert_intelligence_sim.py)
from app.database import Base
from app.security import hash_password
from ml.attack_scenarios import ScenarioSpec, all_scenarios

BASE_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "attack-scenarios-v2.md"
PAYLOAD_PATH = Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "attack_scenario_runner.json"


@dataclass
class ScenarioOutcome:
    id: str
    title: str
    rule_hint: str
    expect_detectable: bool
    total_attack_steps: int
    detected: bool
    first_detected_step: int | None  # 1-based, vị trí trong attack_attempts (KHÔNG tính bước baseline)
    total_alerts: int
    mechanisms: list[str] = field(default_factory=list)  # vd ["hybrid_risk (rule=password_spray_slow)", "ml_anomaly"]


# ------------------------------------------------------------------------------------------------------- hạ tầng


def _fresh_session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _wire(session_factory) -> None:
    """Y HỆT scripts/alert_intelligence_sim.py::_wire — xem docstring ở đó. Thêm invalidate_rule_config_cache (MR17,
    không tồn tại khi alert_intelligence_sim.py được viết) để không đọc nhầm rule_overrides cache từ lần chạy DB khác."""
    import app.detection.pipeline as pipeline_module
    import app.detection.rate_counter as rate_counter_module
    from app.detection import hybrid_runtime, model_registry
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache, invalidate_rule_config_cache

    pipeline_module.SessionLocal = session_factory
    rate_counter_module.redis_client = fakeredis.FakeRedis(decode_responses=True)
    invalidate_blocklist_cache()
    invalidate_rule_config_cache()

    db = session_factory()
    try:
        model_registry.ensure_registered(db)
        hybrid_runtime.load_at_startup(db)
        if not hybrid_runtime.get_engine().ml_available:
            raise RuntimeError("Không nạp được mô hình hybrid_cp2 thật — runner cần model thật để đo, không dùng fallback chỉ luật.")
    finally:
        db.close()


def _create_victims(session_factory, usernames: tuple[str, ...]) -> None:
    from app.models import User

    if not usernames:
        return
    db = session_factory()
    try:
        for u in usernames:
            db.add(User(username=u, password_hash=hash_password("CorrectHorse123!")))
        db.commit()
    finally:
        db.close()


def _insert_baseline(session_factory, spec: ScenarioSpec) -> None:
    """Bước BASELINE (is_attack_step=False) — chèn THẲNG thành LoginEvent (không qua pipeline, không cần chấm điểm cho
    NÓ, chỉ cần TỒN TẠI làm lịch sử) để thiết lập lịch sử/thiết bị/vị trí quen thuộc TRƯỚC kịch bản.

    ⚠️ Bug thật tự phát hiện khi dựng MR18: PHẢI tính GeoIP (`lookup_ip`) và device_fingerprint
    (`compute_device_fingerprint`) THẬT cho từng dòng baseline — y hệt những gì pipeline SỐNG sẽ tự làm cho một lần
    đăng nhập thật — chứ không chỉ ghi mỗi `ip_address`/`user_agent` thô. Thiếu bước này (bản đầu tiên của hàm này,
    và `_seed_history` gốc ở scripts/alert_intelligence_sim.py, MR13, có CÙNG thiếu sót): `country`/`city`/`latitude`/
    `longitude`/`device_fingerprint` của MỌI dòng baseline đều NULL, khiến `is_known_location`/`is_known_device`
    (`ml/features.py`, tầng 3) luôn thấy "chưa từng biết" dù đã có hàng chục dòng lịch sử TRÙNG HỆT — xác nhận trực
    tiếp: một tài khoản có 35 lần đăng nhập baseline THÀNH CÔNG rồi đăng nhập lại GIỐNG HỆT (cùng IP/UA/giờ) vẫn bị
    `ml_anomaly` báo động trước khi sửa, KHÔNG còn báo sau khi sửa."""
    from app.detection.geoip import lookup_ip
    from app.models import LoginEvent, User
    from app.utils.device import compute_device_fingerprint

    baseline = [a for a in spec.attempts if not a.is_attack_step]
    if not baseline:
        return
    db = session_factory()
    try:
        users_by_name = {u.username: u.id for u in db.query(User).filter(User.username.in_(spec.victim_usernames)).all()}
        for a in baseline:
            geo = lookup_ip(a.ip)
            db.add(LoginEvent(
                user_id=users_by_name.get(a.username), attempted_username=a.username, success=a.success, ip_address=a.ip,
                user_agent=a.user_agent, device_fingerprint=compute_device_fingerprint(a.user_agent),
                country=geo.country if geo else None, city=geo.city if geo else None,
                latitude=geo.latitude if geo else None, longitude=geo.longitude if geo else None,
                is_synthetic=True, created_at=BASE_TS + timedelta(seconds=a.offset_s),
            ))
        db.commit()
    finally:
        db.close()


def _alert_count(session_factory) -> int:
    from app.models import Alert

    db = session_factory()
    try:
        return db.query(Alert).count()
    finally:
        db.close()


def _all_alert_mechanisms(session_factory) -> list[str]:
    from app.models import Alert

    db = session_factory()
    try:
        mechanisms = []
        for a in db.execute(select(Alert)).scalars():
            if a.alert_type == "hybrid_risk":
                mechanisms.append(f"hybrid_risk (rule={a.rule_id})" if a.rule_id else "hybrid_risk (chỉ ML, không luật nào khớp)")
            else:
                mechanisms.append(a.alert_type)
        return mechanisms
    finally:
        db.close()


def _run_login(*, username, user_id, success, ip, ts, user_agent) -> None:
    from app.detection.pipeline import run_detection_pipeline

    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=ts))


# ---------------------------------------------------------------------------------------------------- chạy 1 kịch bản


def run_scenario(spec: ScenarioSpec) -> ScenarioOutcome:
    sf = _fresh_session_factory()
    _wire(sf)
    _create_victims(sf, spec.victim_usernames)
    _insert_baseline(sf, spec)

    from app.models import User

    db = sf()
    try:
        user_ids = {u.username: u.id for u in db.query(User).filter(User.username.in_(spec.victim_usernames)).all()}
    finally:
        db.close()

    attack_attempts = spec.attack_attempts
    first_detected_step: int | None = None
    for step, attempt in enumerate(attack_attempts, start=1):
        before = _alert_count(sf)
        _run_login(
            username=attempt.username, user_id=user_ids.get(attempt.username), success=attempt.success, ip=attempt.ip,
            ts=BASE_TS + timedelta(seconds=attempt.offset_s), user_agent=attempt.user_agent,
        )
        if first_detected_step is None and _alert_count(sf) > before:
            first_detected_step = step

    total_alerts = _alert_count(sf)
    return ScenarioOutcome(
        id=spec.id, title=spec.title, rule_hint=spec.rule_hint, expect_detectable=spec.expect_detectable,
        total_attack_steps=len(attack_attempts), detected=total_alerts > 0, first_detected_step=first_detected_step,
        total_alerts=total_alerts, mechanisms=_all_alert_mechanisms(sf),
    )


# ------------------------------------------------------------------------------------------------------- báo cáo


def build_payload(outcomes: list[ScenarioOutcome]) -> dict:
    return {"scenarios": [asdict(o) for o in outcomes]}


def render(payload: dict) -> str:
    scenarios = payload["scenarios"]
    n_expected_detectable = sum(1 for s in scenarios if s["expect_detectable"])
    n_detected_among_expected = sum(1 for s in scenarios if s["expect_detectable"] and s["detected"])
    n_missed_unexpectedly = [s["title"] for s in scenarios if s["expect_detectable"] and not s["detected"]]

    lines = [
        "# Thư viện tấn công mô phỏng v2 — scorecard (MR18)",
        "",
        "9 kịch bản mới, mỗi kịch bản hiệu chỉnh có chủ đích để vượt hẳn ngưỡng THẬT của một luật cụ thể "
        "(`docs/rule-catalog.md`), chạy qua CHÍNH pipeline thật (rule engine v2 + hybrid risk engine, model `hybrid_cp2` "
        "thật) — mã nguồn: [`ml/attack_scenarios.py`](../backend/ml/attack_scenarios.py) (đặc tả) + "
        "[`scripts/attack_scenario_runner.py`](../backend/scripts/attack_scenario_runner.py) (chạy + đo). "
        "Mỗi kịch bản chạy **đúng 1 lần** (không phải nhiều 'trial' — xem docstring runner: các kịch bản xác định, "
        "không có nguồn ngẫu nhiên nào để lấy trung bình một cách có ý nghĩa).",
        "",
        "## Kết quả chính",
        "",
        f"- **{n_detected_among_expected}/{n_expected_detectable}** kịch bản được kỳ vọng phát hiện được đã thực sự có alert.",
    ]
    if n_missed_unexpectedly:
        lines.append(f"- ⚠️ **Bỏ sót NGOÀI dự kiến** (đáng chú ý, không phải kịch bản `targeted_mimic` cố ý khó): {', '.join(n_missed_unexpectedly)}.")
    else:
        lines.append("- Không có kịch bản nào bị bỏ sót NGOÀI dự kiến (chỉ `targeted_mimic`, cố ý khó, có thể bị bỏ sót — xem bảng dưới).")
    lines += ["", "## Scorecard", "", "| Kịch bản | Luật nhắm tới | Phát hiện? | Bước phát hiện | Số alert | Cơ chế |", "|---|---|---|---|---|---|"]
    for s in scenarios:
        detected_mark = "✅" if s["detected"] else ("➖ (cố ý khó)" if not s["expect_detectable"] else "❌")
        step = f"{s['first_detected_step']}/{s['total_attack_steps']}" if s["first_detected_step"] else "—"
        mechanisms = "; ".join(sorted(set(s["mechanisms"]))) or "—"
        lines.append(f"| {s['title']} | `{s['rule_hint']}` | {detected_mark} | {step} | {s['total_alerts']} | {mechanisms} |")

    lines += [
        "",
        "## Diễn giải",
        "",
        "- \"Bước phát hiện\" là vị trí (1-based) trong CHUỖI TẤN CÔNG (không tính các lần đăng nhập nền thiết lập lịch "
        "sử quen thuộc trước đó) mà lần ĐẦU TIÊN xuất hiện alert — không phải \"giây\" vì tốc độ demo không phản ánh tốc "
        "độ tấn công thật.",
        "- ⚠️ **`ml_anomaly` (tầng 3, Tuần 7) gần như LUÔN xuất hiện, kể cả khi đăng nhập KHỚP HỆT thói quen đã thiết lập** "
        "— xác nhận trực tiếp bằng đối chứng riêng (tài khoản có 10-35 lần đăng nhập baseline giống hệt nhau, lần tiếp "
        "theo CÙNG IP/UA/giờ vẫn bị báo). Mô hình tầng 3 huấn luyện TOÀN CỤC trên user101-140 (`ml/generate_dataset.py`), "
        "không huấn luyện lại riêng cho từng tài khoản mới trong kịch bản — một tài khoản hoàn toàn mới có thể tự nhiên "
        "\"trông lạ\" so với phân bố đã học dù hành vi nội tại nhất quán. Vì vậy cột \"Cơ chế\" ở trên KHÔNG coi `ml_anomaly` "
        "là bằng chứng phát hiện ĐÚNG KIỂU tấn công — chỉ các cơ chế CÒN LẠI (luật tầng 1/2 cụ thể, `hybrid_risk` có "
        "`rule=`) mới phản ánh tín hiệu THỰC SỰ đặc trưng cho kịch bản. Đây là đặc tính đã biết của tầng 3 (ngoài phạm vi "
        "sửa của MR18 — sửa được cần huấn luyện lại/hiệu chỉnh lại ngưỡng, việc của MR6/Tuần 7), không phải bug.",
        "- ⚠️ **Bug thật tự phát hiện khi dựng baseline cho kịch bản**: chèn lịch sử \"quen thuộc\" bằng cách ghi thẳng "
        "`LoginEvent` (không qua pipeline) mà QUÊN tính `device_fingerprint`/GeoIP (`country`/`city`/`latitude`/"
        "`longitude`) — giống HỆT cách `scripts/alert_intelligence_sim.py::_seed_history` (MR13) làm — khiến MỌI dòng "
        "baseline trông \"chưa từng thấy thiết bị/vị trí này\" dù được lặp lại hàng chục lần, làm sai lệch `is_new_device`/"
        "`is_new_location` (tầng 3) một cách có hệ thống. Đã sửa trong `_insert_baseline()` (tính GeoIP + "
        "`compute_device_fingerprint` THẬT, y hệt pipeline sống sẽ làm) — CHƯA sửa ngược lại `alert_intelligence_sim.py` "
        "(ngoài phạm vi MR18, để lại ghi chú cho lần sau).",
        "- **`rare_network_login` một mình KHÔNG đủ để tạo alert** (trả lời câu hỏi để ngỏ ở `docs/rule-catalog.md` — "
        "\"giá trị thật đo bằng kịch bản mô phỏng ở MR18\"): kịch bản `same_country_proxy` (cùng nước, cùng thiết bị, "
        "CHỈ đổi ASN) chỉ còn `ml_anomaly` (xem caveat trên) — trọng số hiệu chỉnh của `rare_network_login` (2,6%, "
        "`app/detection/hybrid/profiles/rba_calibrated.json`) một mình không đủ vượt ngưỡng `alert_at=32`. Rule ở chế độ "
        "`shadow` là hợp lý: một tín hiệu yếu, cần corroborate bởi tín hiệu khác mới đáng báo.",
        "- **`distributed_bruteforce` được hiệu chỉnh với trọng số 0,0** (mẫu val chỉ 2 dòng — "
        "`rba_calibrated.json`), nghĩa là rule này KHÔNG ĐÓNG GÓP GÌ cho điểm hybrid dù khớp rõ ràng. Kịch bản "
        "`distributed_botnet` vẫn được phát hiện — nhưng qua `impossible_travel` (tầng 1), một hệ quả CỦA VIỆC chọn IP "
        "botnet cách xa nhau về địa lý, KHÔNG PHẢI vì `distributed_bruteforce` được nhận diện. Một botnet dùng hạ tầng "
        "CÙNG khu vực địa lý (vẫn nhiều IP/ASN khác nhau nhưng không kích hoạt di chuyển bất khả thi) nhiều khả năng sẽ "
        "KHÔNG bị bắt qua đường này — chưa kiểm chứng trực tiếp (xem Giới hạn).",
        "- **`username_enumeration` (weight mặc định 0,05, chưa hiệu chỉnh) không tạo alert nào** dù vượt hẳn ngưỡng "
        "riêng của rule (10 tên >> 8) — không có luật tầng 1 nào dự phòng cho việc dò danh sách tài khoản (khác "
        "`impossible_travel`/`brute_force`/`credential_stuffing`, đều có bản gốc tầng 1). Đây là BỎ SÓT THẬT, đáng để ý "
        "khi ưu tiên hiệu chỉnh lại rule ở các MR sau.",
        "- `targeted_mimic` CỐ Ý thiết kế khó (không luật enforce nào có lý do khớp, chỉ còn tín hiệu ML yếu) — đây là "
        "kịch bản \"ML dẫn đầu\" mà MR13 (`scripts/alert_intelligence_sim.py`) đã để ngỏ cho MR18. Bị gắn cờ (qua "
        "`ml_anomaly`/`hybrid_risk` chỉ ML) — nhưng xem caveat `ml_anomaly` ở trên: KHÔNG thể khẳng định chắc đây là "
        "phát hiện ĐÚNG kiểu mô phỏng tinh vi, hay lại là hiệu ứng tài khoản mới. Kết quả mơ hồ này TỰ NÓ là một phát "
        "hiện trung thực đáng ghi nhận, không phải một câu trả lời gọn gàng.",
        "",
        "## Giới hạn",
        "",
        "- Mỗi kịch bản chạy 1 lần với tham số đã hiệu chỉnh để vượt HẲN ngưỡng (không sát ngưỡng) — KHÔNG đo được độ "
        "NHẠY ở biên (vd `password_spray_slow` với đúng 15 tài khoản thay vì 18 có còn bắt được không).",
        "- Chưa kiểm chứng biến thể \"botnet CÙNG khu vực địa lý\" cho `distributed_botnet` (xem Diễn giải) — nghi ngờ "
        "có căn cứ (trọng số 0,0 + không có rule dự phòng) nhưng chưa đo trực tiếp bằng một kịch bản chính thức.",
        "- `ml_anomaly` (tầng 3) báo động gần như luôn luôn cho tài khoản MỚI bất kể có tấn công hay không (xem Diễn "
        "giải) — làm giảm giá trị của cột \"Cơ chế\" cho những kịch bản CHỈ có `ml_anomaly`; cần tài khoản có lịch sử "
        "SÂU hơn (bằng hoặc hơn phạm vi huấn luyện tầng 3, 30-55 lần/user) hoặc hiệu chỉnh lại ngưỡng tầng 3 mới đo được "
        "chính xác — ngoài phạm vi MR18.",
        "- IP CÔNG KHAI THẬT nhưng KHÔNG PHẢI hạ tầng tấn công thật — GeoIP/ASN thật, hành vi tấn công là dàn dựng.",
        "- Không đo trên nhiều tài khoản nạn nhân/hồ sơ lịch sử khác nhau cho mỗi kịch bản — 1 nạn nhân mẫu/kịch bản.",
        "- Dùng làm dữ liệu cho \"mô hình B\" (địa lý-thời gian): xem mục riêng trong "
        "[`docs/model-b-geo-time.md`](model-b-geo-time.md).",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    rng = random.Random(0)
    outcomes = [run_scenario(spec) for spec in all_scenarios(rng)]
    payload = build_payload(outcomes)

    PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(payload), encoding="utf-8")

    for o in outcomes:
        print(f"{o.id}: detected={o.detected} step={o.first_detected_step}/{o.total_attack_steps} alerts={o.total_alerts}")
    print(f"Da ghi {REPORT_PATH} va {PAYLOAD_PATH}")


if __name__ == "__main__":
    main()
