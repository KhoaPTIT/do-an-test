"""MR16 — "Phản ứng tự động (mô phỏng)": checklist yêu cầu tường minh "test toàn bộ luồng". Chạy qua HTTP THẬT
(`fastapi.testclient.TestClient`, giống `tests/conftest.py::client`) — KHÁC với `feedback_loop_sim.py`/
`alert_intelligence_sim.py` (gọi thẳng `run_detection_pipeline`, bỏ qua router) — vì logic MỚI đáng kiểm của MR16 nằm
CHÍNH ở `app/routers/auth.py` (chặn trước khi xác thực mật khẩu, tạo OTP, endpoint xác thực OTP), không phải ở pipeline.

Hai kịch bản, trên CHÍNH pipeline + hybrid risk engine thật (model `hybrid_cp2` thật), DB SQLite in-memory + fakeredis
riêng (không đụng Postgres/Redis dev):

  1. **Khoá (lock)** — xác định qua `blocklist_hit` (luật GHI ĐÈ, không phụ thuộc hiệu chỉnh — như MR12-15). Kịch bản kể
     câu chuyện ĐẦY ĐỦ: nạn nhân có tài khoản thật đăng nhập bình thường trước → kẻ tấn công (từ ASN đã bị chặn, có
     MẬT KHẨU ĐÚNG — vd rò rỉ từ nơi khác) đăng nhập thành công AS nạn nhân → MR16 khoá TÀI KHOẢN (không phải IP, vì
     tài khoản có thật — `lock_kind_and_value`) → ⚠️ HỆ QUẢ: chính nạn nhân cũng bị khoá theo cho tới khi admin mở
     khoá (đây là đánh đổi CÓ CHỦ Ý — bảo vệ tài khoản khi có dấu hiệu bị lộ mật khẩu quan trọng hơn để chủ tài khoản
     đăng nhập được ngay — nhưng vẫn là một CHI PHÍ thật, ghi nhận rõ ở "Giới hạn").
  2. **Xác thực thêm (step_up/OTP)** — KHÔNG có "cửa" xác định nào như `blocklist_hit` (không luật nào ghi đè ra
     step_up) nên ép thẳng qua `hybrid_runtime.get_engine().evaluate` (đúng kỹ thuật `_spy_on_evaluate` đã dùng ở
     `tests/test_pipeline_mr15.py` — dựng một kịch bản điểm số chính xác qua toàn bộ rule engine + mô hình thật để RƠI
     ĐÚNG vào dải step_up [58, 70) là mong manh, phụ thuộc hiệu chỉnh có thể đổi sau, không đáng làm cho một script minh
     hoạ CƠ CHẾ).

Số đo ĐỘ TRỄ (HTTP thật, Postgres dev thật) nằm Ở TÀI LIỆU (docs/automated-response.md), đo riêng bằng
`scripts/benchmark_login.py` — script NÀY chỉ đo chức năng (đúng/sai), không đo thời gian.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.automated_response_sim
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import fakeredis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401 — đăng ký toàn bộ bảng vào Base.metadata TRƯỚC create_all (xem alert_intelligence_sim.py)
from app.database import Base
from app.security import hash_password

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
VICTIM_PASSWORD = "MatKhauNanNhan123!"
GOOGLE_DNS = "8.8.8.8"  # ASN 15169 thật (GeoLite2-ASN.mmdb) — như test_pipeline_mr12.py
VICTIM_OWN_IP = "203.0.113.10"
REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "automated-response.md"
PAYLOAD_PATH = Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "automated_response_sim.json"


@dataclass
class LockScenarioResult:
    victim_baseline_login_ok: bool
    attacker_login_status: int
    attacker_login_locked_field: bool
    lock_targeted_username: bool  # True nếu BlocklistEntry mới là kind="username" (không phải "ip")
    victim_locked_out_after_attack: bool
    admin_sees_entry_in_list: bool
    admin_unlock_status: int
    victim_login_after_unlock_ok: bool


@dataclass
class StepUpScenarioResult:
    login_status: int
    step_up_required: bool
    otp_challenge_created: bool
    wrong_code_rejected: bool
    wrong_code_message: str
    correct_code_status: int
    correct_code_success: bool


@dataclass
class SimReport:
    lock: LockScenarioResult
    step_up: StepUpScenarioResult


# ------------------------------------------------------------------------------------------------------ hạ tầng


def _fresh_env():
    """DB SQLite in-memory + fakeredis + model hybrid thật, gắn vào app THẬT qua TestClient — giống hệt
    `tests/conftest.py` (`db_session` + `client` fixtures) nhưng dựng tay cho một script độc lập, không phải pytest."""
    import app.detection.pipeline as pipeline_module
    import app.detection.rate_counter as rate_counter_module
    import app.main as main_module
    from app.database import get_db
    from app.detection import hybrid_runtime, model_registry
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache
    from app.main import app as fastapi_app

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    pipeline_module.SessionLocal = session_factory
    main_module.SessionLocal = session_factory
    rate_counter_module.redis_client = fakeredis.FakeRedis(decode_responses=True)
    invalidate_blocklist_cache()

    db = session_factory()
    try:
        model_registry.ensure_registered(db)
        hybrid_runtime.load_at_startup(db)
        if not hybrid_runtime.get_engine().ml_available:
            raise RuntimeError("Không nạp được mô hình hybrid_cp2 thật — script cần model thật, không dùng fallback chỉ luật.")
    finally:
        db.close()

    def _override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    fastapi_app.dependency_overrides[get_db] = _override_get_db
    client = TestClient(fastapi_app)
    return client, session_factory


def _create_user(session_factory, username: str, password: str) -> int:
    from app.models import User

    db = session_factory()
    try:
        user = User(username=username, password_hash=hash_password(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id
    finally:
        db.close()


def _add_blocklist(session_factory, *, kind: str, value: str) -> None:
    from app.models import BlocklistEntry

    db = session_factory()
    try:
        db.add(BlocklistEntry(kind=kind, value=value, reason="automated_response_sim", added_by="sim"))
        db.commit()
    finally:
        db.close()


def _latest_blocklist_entry(session_factory):
    from app.models import BlocklistEntry

    db = session_factory()
    try:
        return db.query(BlocklistEntry).order_by(BlocklistEntry.id.desc()).first()
    finally:
        db.close()


# ---------------------------------------------------------------------------------------------------- kịch bản 1: lock


def run_lock_scenario(client: TestClient, session_factory) -> LockScenarioResult:
    victim_id = _create_user(session_factory, "nan_nhan_that", VICTIM_PASSWORD)

    baseline = client.post("/login", json={"username": "nan_nhan_that", "password": VICTIM_PASSWORD}, headers={"user-agent": CHROME_UA, "x-forwarded-for": VICTIM_OWN_IP})
    victim_baseline_login_ok = baseline.status_code == 200

    # Kẻ tấn công có MẬT KHẨU ĐÚNG (vd rò rỉ nơi khác) nhưng đến từ hạ tầng (ASN) đã biết xấu — blocklist_hit ghi đè
    # ra lock CHẮC CHẮN, không phụ thuộc hiệu chỉnh (như MR12-15).
    _add_blocklist(session_factory, kind="asn", value="15169")
    attacker = client.post("/login", json={"username": "nan_nhan_that", "password": VICTIM_PASSWORD}, headers={"user-agent": "curl/8.0", "x-forwarded-for": GOOGLE_DNS})

    lock_entry = _latest_blocklist_entry(session_factory)
    lock_targeted_username = lock_entry is not None and lock_entry.kind == "username" and lock_entry.value == "nan_nhan_that"

    # Hệ quả: chính nạn nhân (IP RIÊNG của họ, không liên quan gì tới ASN của kẻ tấn công) giờ CŨNG bị khoá, vì MR16
    # khoá TÀI KHOẢN chứ không phải IP khi tài khoản có thật.
    victim_retry = client.post("/login", json={"username": "nan_nhan_that", "password": VICTIM_PASSWORD}, headers={"user-agent": CHROME_UA, "x-forwarded-for": VICTIM_OWN_IP})
    victim_locked_out_after_attack = victim_retry.status_code == 423

    admin_token = _admin_token(client, session_factory)
    listing = client.get("/blocklist", headers={"Authorization": f"Bearer {admin_token}"})
    admin_sees_entry_in_list = listing.status_code == 200 and any(e["id"] == lock_entry.id for e in listing.json()["items"])

    unlock = client.delete(f"/blocklist/{lock_entry.id}", headers={"Authorization": f"Bearer {admin_token}"})

    victim_after_unlock = client.post("/login", json={"username": "nan_nhan_that", "password": VICTIM_PASSWORD}, headers={"user-agent": CHROME_UA, "x-forwarded-for": VICTIM_OWN_IP})

    return LockScenarioResult(
        victim_baseline_login_ok=victim_baseline_login_ok,
        attacker_login_status=attacker.status_code,
        attacker_login_locked_field=attacker.json().get("locked", False),
        lock_targeted_username=lock_targeted_username,
        victim_locked_out_after_attack=victim_locked_out_after_attack,
        admin_sees_entry_in_list=admin_sees_entry_in_list,
        admin_unlock_status=unlock.status_code,
        victim_login_after_unlock_ok=victim_after_unlock.status_code == 200,
    )


def _admin_token(client: TestClient, session_factory) -> str:
    from app.models import Admin

    db = session_factory()
    try:
        db.add(Admin(username="admin_sim", password_hash=hash_password("MatKhauQuanTri123!")))
        db.commit()
    finally:
        db.close()
    login = client.post("/admin/login", json={"username": "admin_sim", "password": "MatKhauQuanTri123!"})
    return login.json()["access_token"]


# ------------------------------------------------------------------------------------------------- kịch bản 2: step_up


def _force_step_up_action(monkeypatch_target) -> None:
    """Ép hybrid risk engine trả `action="step_up"` cố định — như `_spy_on_evaluate` ở test_pipeline_mr15.py (xem
    docstring module: không có luật GHI ĐÈ nào ra step_up như blocklist_hit ra lock)."""
    from app.detection import hybrid_runtime
    from app.detection.hybrid import Contribution, RiskResult

    engine = hybrid_runtime.get_engine()
    result = RiskResult(
        score=60, action="step_up", probability=0.6, ml_probability=None, rule_probability=0.6, reputation_probability=0.0,
        overridden_by=None, contributions=(Contribution(source="sim", label="ép hành động cho script minh hoạ", weight=0.6, group="rule"),),
    )
    engine.evaluate = lambda features, hits, bands=None: result  # noqa: ARG005 — chữ ký phải khớp evaluate() thật


def run_step_up_scenario(client: TestClient, session_factory) -> StepUpScenarioResult:
    _create_user(session_factory, "can_xac_thuc_them", "MatKhauBinhThuong123!")
    _force_step_up_action(None)

    login = client.post("/login", json={"username": "can_xac_thuc_them", "password": "MatKhauBinhThuong123!"}, headers={"user-agent": CHROME_UA})
    body = login.json()
    step_up_required = body.get("step_up_required", False)
    challenge_id = body.get("challenge_id")
    real_code = body.get("demo_otp_code")

    wrong_code = "000000" if real_code != "000000" else "111111"
    wrong_attempt = client.post("/login/verify-otp", json={"challenge_id": challenge_id, "code": wrong_code})

    correct_attempt = client.post("/login/verify-otp", json={"challenge_id": challenge_id, "code": real_code})

    return StepUpScenarioResult(
        login_status=login.status_code,
        step_up_required=step_up_required,
        otp_challenge_created=challenge_id is not None and real_code is not None,
        wrong_code_rejected=wrong_attempt.json().get("success") is False,
        wrong_code_message=wrong_attempt.json().get("message", ""),
        correct_code_status=correct_attempt.status_code,
        correct_code_success=correct_attempt.json().get("success") is True,
    )


# ------------------------------------------------------------------------------------------------------- báo cáo


def build_payload(report: SimReport) -> dict:
    return {"lock": asdict(report.lock), "step_up": asdict(report.step_up)}


def render(payload: dict) -> str:
    lock, step_up = payload["lock"], payload["step_up"]
    ok = lambda b: "✅" if b else "❌"  # noqa: E731

    lines = [
        "# Phản ứng tự động — mô phỏng toàn bộ luồng (MR16)",
        "",
        "Chạy qua HTTP thật (`TestClient`, không bỏ qua router như các script MR13-15) — mã nguồn: "
        "[`backend/scripts/automated_response_sim.py`](../backend/scripts/automated_response_sim.py). Cơ chế: "
        "[`app/detection/response_execution.py`](../backend/app/detection/response_execution.py), "
        "[`app/routers/auth.py`](../backend/app/routers/auth.py), "
        "[`app/routers/blocklist.py`](../backend/app/routers/blocklist.py).",
        "",
        "## Kịch bản 1 — Khoá tự động (lock)",
        "",
        "Nạn nhân có tài khoản thật; kẻ tấn công có MẬT KHẨU ĐÚNG (rò rỉ từ nơi khác) nhưng đến từ một ASN đã biết xấu.",
        "",
        f"| Bước | Kết quả |",
        f"|---|---|",
        f"| 1. Nạn nhân đăng nhập bình thường (trước khi bị tấn công) | {ok(lock['victim_baseline_login_ok'])} thành công |",
        f"| 2. Kẻ tấn công đăng nhập ĐÚNG mật khẩu từ ASN đã bị chặn | HTTP {lock['attacker_login_status']}, `locked={lock['attacker_login_locked_field']}` {ok(lock['attacker_login_status'] == 423)} |",
        f"| 3. Mục khoá mới nhắm vào TÀI KHOẢN (không phải IP kẻ tấn công) | {ok(lock['lock_targeted_username'])} |",
        f"| 4. ⚠️ Nạn nhân đăng nhập lại (IP RIÊNG của họ, mật khẩu đúng) | {'bị khoá theo (423)' if lock['victim_locked_out_after_attack'] else 'KHÔNG bị khoá theo'} {ok(lock['victim_locked_out_after_attack'])} |",
        f"| 5. Admin thấy mục khoá trong `GET /blocklist` | {ok(lock['admin_sees_entry_in_list'])} |",
        f"| 6. Admin mở khoá (`DELETE /blocklist/{{id}}`) | HTTP {lock['admin_unlock_status']} {ok(lock['admin_unlock_status'] == 204)} |",
        f"| 7. Nạn nhân đăng nhập lại SAU khi admin mở khoá | {ok(lock['victim_login_after_unlock_ok'])} thành công |",
        "",
        "## Kịch bản 2 — Xác thực thêm (step_up / OTP giả lập)",
        "",
        "Không có luật GHI ĐÈ nào ra `step_up` như `blocklist_hit` ra `lock` — ép thẳng qua `hybrid_runtime` (kỹ thuật "
        "`_spy_on_evaluate` đã dùng ở `tests/test_pipeline_mr15.py`), xem docstring script.",
        "",
        "| Bước | Kết quả |",
        "|---|---|",
        f"| 1. Đăng nhập đúng mật khẩu, hành động bị ép = step_up | HTTP {step_up['login_status']}, `step_up_required={step_up['step_up_required']}` {ok(step_up['step_up_required'])} |",
        f"| 2. OTP giả lập được tạo (challenge_id + mã demo) | {ok(step_up['otp_challenge_created'])} |",
        f"| 3. Xác thực với mã SAI | từ chối, message: \"{step_up['wrong_code_message']}\" {ok(step_up['wrong_code_rejected'])} |",
        f"| 4. Xác thực với mã ĐÚNG | HTTP {step_up['correct_code_status']}, thành công {ok(step_up['correct_code_success'])} |",
        "",
        "## Diễn giải",
        "",
        "- **Phát hiện đáng chú ý (bước 4, kịch bản 1)**: khoá tự động MR16 khoá TÀI KHOẢN khi tài khoản có thật "
        "(`lock_kind_and_value`, `app/detection/response_execution.py`) — nghĩa là SAU một lần bị dò trúng mật khẩu từ "
        "hạ tầng khả nghi, chính CHỦ tài khoản cũng không đăng nhập được (từ BẤT KỲ IP nào, kể cả IP quen thuộc của họ) "
        "cho tới khi admin mở khoá hoặc hết `LOCK_TTL` (30 phút). Đây là đánh đổi AN TOÀN > TIỆN LỢI có chủ đích (nếu "
        "mật khẩu đã lộ, phải ngăn TẤT CẢ các lần đăng nhập cho tới khi xác minh qua kênh khác) — nhưng là một CHI PHÍ "
        "thật cho người dùng hợp lệ, không phải tác dụng phụ nên bỏ qua.",
        "- Precheck (`app/routers/auth.py`) không tra ASN (đắt) nên bước 2 CHỈ bị bắt SAU khi mật khẩu đã được xác thực "
        "và pipeline chấm điểm xong — khác bước 4 (bị bắt NGAY ở precheck, vì lần này là khoá THEO TÊN TÀI KHOẢN, "
        "loại precheck CÓ kiểm) — cả hai đường đều đúng, chỉ khác chỗ chặn.",
        "- `step_up` không có \"cửa\" xác định nào để tái lập tự nhiên qua toàn bộ rule engine + mô hình thật một cách "
        "đáng tin cậy (phụ thuộc hiệu chỉnh `ActionBands`, xem `docs/hybrid-risk-engine.md`) — ép thẳng qua "
        "`hybrid_runtime` LÀ kỹ thuật kiểm thử chính thống, không phải né tránh (cùng cách `tests/test_pipeline_mr15.py` "
        "đã làm cho một vấn đề tương tự).",
        "",
        "## Giới hạn",
        "",
        "- Cả hai kịch bản chạy 1 lần, minh hoạ CƠ CHẾ — không phải khảo sát thống kê trên diện rộng.",
        "- DB SQLite in-memory + fakeredis (không phải Postgres/Redis dev thật) — số đo ĐỘ TRỄ (khác script này) nằm ở "
        "mục riêng bên dưới, đo qua HTTP thật.",
        "- Kịch bản `step_up` dùng hành động ÉP CỨNG, không phải điểm số tự nhiên — không nói lên được NGƯỠNG thật sự "
        "dễ/khó đạt step_up thế nào trong dữ liệu thật (đó là câu hỏi của hiệu chỉnh `ActionBands`, đã bàn ở "
        "`docs/hybrid-risk-engine.md`, không phải của MR16).",
        "- Chưa mô phỏng OTP hết hạn / quá số lần thử sai / challenge bị dùng lại — các nhánh đó đã có test đơn vị đầy đủ "
        "ở `backend/tests/test_auth_mr16.py`, không lặp lại ở đây (script này minh hoạ LUỒNG, không thay thế bộ test).",
        "",
        "## Độ trễ (đo riêng, HTTP thật, Postgres dev thật — `scripts/benchmark_login.py`)",
        "",
        "30 request TUẦN TỰ mỗi kịch bản, cùng máy, cùng phiên đo (để so sánh công bằng — số tuyệt đối cao hơn baseline "
        "MR12 vì máy đang chạy nhiều tiến trình khác lúc đo, không phải vì MR16; xem cột chênh lệch để tách hai hiệu ứng):",
        "",
        "| Kịch bản | min | median | p95 | max |",
        "|---|---|---|---|---|",
        "| Sai mật khẩu (nền, KHÔNG đổi từ MR12) | 347,8 ms | 596,0 ms | 1.193,4 ms | 2.366,9 ms |",
        "| Đúng mật khẩu (MỚI — chờ đồng bộ kết quả chấm điểm) | 641,8 ms | 735,6 ms | 793,9 ms | 2.730,1 ms |",
        "| **Chênh lệch (median)** | | **+139,6 ms** | | |",
        "",
        "Chênh lệch trung vị (~140 ms) khớp cùng bậc độ lớn với chi phí pipeline TRONG TIẾN TRÌNH đã đo ở MR12 "
        "(`docs/realtime-integration.md` mục 3.1: mean 28,1 ms, **p99 134,2 ms**) — phần lớn khác biệt TUYỆT ĐỐI giữa "
        "hai lần đo (735 ms hôm nay so với 280 ms ở MR12) đến từ MÔI TRƯỜNG đo (máy dev đang chạy nhiều tiến trình khác "
        "khi đo MR16), KHÔNG PHẢI từ thay đổi của MR16 — đo cả hai đường trong CÙNG một phiên (bảng trên) mới là số "
        "đáng tin để đánh giá chi phí thật của việc chuyển sang chờ đồng bộ.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    client, session_factory = _fresh_env()
    lock_result = run_lock_scenario(client, session_factory)
    step_up_result = run_step_up_scenario(client, session_factory)
    report = SimReport(lock=lock_result, step_up=step_up_result)

    payload = build_payload(report)
    PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(payload), encoding="utf-8")

    print(f"Lock scenario: {payload['lock']}")
    print(f"Step-up scenario: {payload['step_up']}")
    print(f"Da ghi {REPORT_PATH} va {PAYLOAD_PATH}")


if __name__ == "__main__":
    main()
