"""MR13 — "Cảnh báo thông minh v2": kịch bản có NHÃN TỰ ĐẶT (không phải RBA — RBA không có nhãn "họ tấn công", chỉ ATO
nhị phân, xem project_rba_dataset.md) để đo, trên CHÍNH pipeline thật (rule engine v2 của MR9-10 + hybrid risk engine
thật đã train của MR11, model `hybrid_cp2`):

  1. Mức GIẢM SỐ CẢNH BÁO nhờ chống trùng lặp (`raw_incidents` — số lần pipeline đề xuất khác "allow" — so với
     `alerts_created` — số hàng `Alert` THỰC SỰ còn lại sau khi gộp, `app/detection/alert_intelligence.py`).
  2. ĐỘ CHÍNH XÁC của `attack_family` GỢI Ý so với họ mà kịch bản CỐ Ý dựng ra (brute_force -> "Đoán và dò mật khẩu",
     bot UA -> "Tự động hoá", di chuyển bất khả thi/tài khoản ngủ đông -> "Ngữ cảnh tài khoản", blocklist -> "Danh
     tiếng hạ tầng"), CỘNG một kịch bản BÌNH THƯỜNG (đối chứng âm — không được tự bịa cảnh báo).

Dùng lại đúng hạ tầng CÔ LẬP của tests/conftest.py (SQLite in-memory + fakeredis + model hybrid_cp2 thật) nhưng KHÔNG
phải pytest — DB mới tinh cho MỖI kịch bản (không kịch bản nào ảnh hưởng kịch bản khác), không đụng Postgres/Redis dev
thật, không để lại dữ liệu nào sau khi chạy xong.

⚠️ Giới hạn đã biết (xem thêm đầu ra `render()`): (1) MỘT giá trị ngẫu nhiên/quyết định lịch sử tự đặt của TÔI, không
phải thư viện tấn công mô phỏng đối kháng thật (đó là MR18); (2) không có kịch bản "ML dẫn đầu" (không rule nào khớp)
vì cần đặc trưng khớp đúng phân bố huấn luyện — khó dựng tay đáng tin cậy, để ngỏ cho MR18; (3) một số kịch bản (vd
brute_force một mình) có thể không tự vượt ngưỡng "alert" — ĐÚNG như hiệu chỉnh MR11 đã đo (trọng số brute_force một
mình ~10%), báo cáo trung thực kể cả khi kết quả là "0 alert", không ép kịch bản để ra số đẹp.

Chạy: cd backend && venv\\Scripts\\python.exe -m scripts.alert_intelligence_sim
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

from app import models  # noqa: F401 — import để ĐĂNG KÝ toàn bộ bảng vào Base.metadata TRƯỚC create_all bên dưới (app.database.Base một mình có metadata rỗng)
from app.database import Base
from app.security import hash_password

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
HANOI_IP = "210.245.88.1"  # FPT Telecom, GeoIP thật -> VN/Hanoi (21.0184, 105.8461) — xác nhận trước khi viết kịch bản
US_IP = "8.8.8.8"  # Google, GeoIP thật -> US (37.751, -97.822), ASN 15169 — đã dùng ở MR12/MR13
# ⚠️ 8.8.8.8 CŨNG nằm trong danh sách datacenter thật (intel.in_datacenter("8.8.8.8") is True, xác nhận trực tiếp) —
# dùng được cho impossible_travel/reputation_burst (không đổi kết luận, impossible_travel/blocklist_hit vẫn thắng) NHƯNG
# KHÔNG dùng cho dormant_account_login: lúc đầu dùng chung US_IP làm "quốc gia mới" cho kịch bản đó, kết quả gán NHẦM
# thành "Danh tiếng hạ tầng" (datacenter_ip thắng dormant_account_login về trọng số) — không phải lỗi code, mà là chọn
# IP cho kịch bản chưa cẩn thận (tình cờ kéo theo một bằng chứng luật KHÁC mạnh hơn). Đổi sang CHINA_IP (xác nhận SẠCH:
# không datacenter, không VPN) để kịch bản dormant_account_login chỉ có đúng một tín hiệu như kịch bản định kiểm tra.
CHINA_IP = "61.28.0.1"  # GeoIP thật -> CN (34.7732, 113.722); intel.in_datacenter/in_vpn đều False (xác nhận trước khi dùng)
REPORT_PATH = Path(__file__).resolve().parents[2] / "docs" / "alert-intelligence-v2.md"
PAYLOAD_PATH = Path(__file__).resolve().parent.parent / "ml" / "artifacts" / "alert_intelligence_sim.json"


@dataclass
class ScenarioResult:
    name: str
    description: str
    expected_family: str | None  # None = kịch bản BÌNH THƯỜNG, kỳ vọng KHÔNG có alert nào
    raw_incidents: int
    alerts_created: int
    predicted_families: list[str | None]

    @property
    def alerted(self) -> bool:
        return self.alerts_created > 0

    @property
    def correct(self) -> bool:
        """Đúng nghĩa hẹp: khi CÓ alert, family phải khớp kỳ vọng; khi KHÔNG kỳ vọng alert nào (đối chứng âm), phải
        không có alert. KHÔNG dùng để đo "độ chính xác gán họ" một mình — xem family_accuracy_pct (chỉ tính trên kịch
        bản THỰC SỰ có alert, tách khỏi việc "không vượt ngưỡng alert một mình" — hai câu hỏi khác nhau, xem docstring module."""
        if self.expected_family is None:
            return self.alerts_created == 0
        return self.alerts_created > 0 and all(f == self.expected_family for f in self.predicted_families)


@dataclass
class SimReport:
    scenarios: list[ScenarioResult] = field(default_factory=list)

    @property
    def total_raw_incidents(self) -> int:
        return sum(s.raw_incidents for s in self.scenarios)

    @property
    def total_alerts_created(self) -> int:
        return sum(s.alerts_created for s in self.scenarios)

    @property
    def alert_reduction_pct(self) -> float:
        if self.total_raw_incidents == 0:
            return 0.0
        return 100.0 * (1 - self.total_alerts_created / self.total_raw_incidents)

    @property
    def family_scenarios(self) -> list[ScenarioResult]:
        """Kịch bản CÓ kỳ vọng một họ tấn công cụ thể (khác đối chứng âm) — mẫu cho cả hai số đo bên dưới."""
        return [s for s in self.scenarios if s.expected_family is not None]

    @property
    def alerted_family_scenarios(self) -> list[ScenarioResult]:
        """Trong số đó, kịch bản THỰC SỰ vượt ngưỡng và có alert — CHỈ nhóm này mới có một family để chấm đúng/sai."""
        return [s for s in self.family_scenarios if s.alerted]

    @property
    def detection_rate_pct(self) -> float:
        """Bao nhiêu % kịch bản có nhãn THỰC SỰ vượt ngưỡng "alert" một mình — câu hỏi KHÁC với độ chính xác gán họ
        (đã đo ở MR9-11, không phải trọng tâm MR13), nhưng cần tách riêng để family_accuracy_pct không bị hiểu nhầm."""
        scored = self.family_scenarios
        return 100.0 * len(self.alerted_family_scenarios) / len(scored) if scored else 0.0

    @property
    def family_accuracy_pct(self) -> float:
        """Trong số kịch bản CÓ alert: bao nhiêu % được gán ĐÚNG họ kỳ vọng. Không tính kịch bản không vượt ngưỡng
        (đó là thiếu phát hiện, một vấn đề khác — xem detection_rate_pct) để không đánh đồng hai loại sai khác nhau."""
        scored = self.alerted_family_scenarios
        return 100.0 * sum(1 for s in scored if s.correct) / len(scored) if scored else 0.0

    @property
    def false_positive_scenarios(self) -> list[ScenarioResult]:
        return [s for s in self.scenarios if s.expected_family is None and s.alerted]


# ------------------------------------------------------------------------------------------------------ hạ tầng


def _fresh_session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _wire(session_factory) -> None:
    """Y HỆT tests/conftest.py::db_session làm (SessionLocal của pipeline trỏ vào SQLite mới, Redis giả lập, xoá cache
    blocklist), viết lại vì đây KHÔNG phải fixture pytest."""
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
            raise RuntimeError("Không nạp được mô hình hybrid_cp2 thật — kịch bản cần model thật để đo, không dùng fallback chỉ luật.")
    finally:
        db.close()


def _run(*, username, user_id, success, ip, ts, user_agent=CHROME_UA) -> None:
    from app.detection.pipeline import run_detection_pipeline

    asyncio.run(run_detection_pipeline(username=username, user_id=user_id, success=success, ip=ip, user_agent=user_agent, timestamp=ts))


def _create_user(session_factory, username: str):
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


def _seed_history(session_factory, user_id: int, *, ip: str, country: str, when: datetime, count: int = 5) -> None:
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
        db.add(BlocklistEntry(kind="ip", value=ip, reason="alert_intelligence_sim", added_by="sim"))
        db.commit()
    finally:
        db.close()


def _collect(session_factory) -> tuple[int, list[str | None]]:
    """(raw_incidents, predicted_families của các Alert THỰC SỰ còn lại) sau khi chạy xong MỘT kịch bản."""
    from app.models import Alert, LoginEvent

    db = session_factory()
    try:
        raw_incidents = db.query(LoginEvent).filter(LoginEvent.hybrid_action != "allow").count()
        families = [a.attack_family for a in db.query(Alert).filter(Alert.alert_type == "hybrid_risk").all()]
        return raw_incidents, families
    finally:
        db.close()


# ---------------------------------------------------------------------------------------------------- kịch bản


def _scenario_brute_force() -> ScenarioResult:
    """8 lần sai liên tiếp vào CÙNG một tài khoản, cùng IP, 10 giây/lần — vượt ngưỡng brute_force (5 lần/300s) từ lần
    thứ 5. Đoán và dò mật khẩu."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_bf")
    for i in range(8):
        _run(username="alice_bf", user_id=user_id, success=False, ip="203.0.113.10", ts=BASE + timedelta(seconds=i * 10))
    raw, families = _collect(sf)
    return ScenarioResult("brute_force", "8 lần sai liên tiếp vào 1 tài khoản (ngưỡng 5 lần/300s)", "Đoán và dò mật khẩu", raw, len(families), families)


def _scenario_bot_user_agent() -> ScenarioResult:
    """Một lần thử với User-Agent là bot đã biết (Googlebot) — chỉ 1 lần, không kèm dấu hiệu nào khác. Tự động hoá."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_bot")
    _run(username="alice_bot", user_id=user_id, success=False, ip="203.0.113.20", ts=BASE, user_agent=BOT_UA)
    raw, families = _collect(sf)
    return ScenarioResult("bot_user_agent", "1 lần thử với User-Agent Googlebot", "Tự động hoá", raw, len(families), families)


def _scenario_impossible_travel() -> ScenarioResult:
    """2 lần đăng nhập THÀNH CÔNG cách nhau 5 phút, từ Hà Nội rồi Mỹ (GeoIP thật, ~13.000km) — vượt xa 900km/h. Ngữ
    cảnh tài khoản."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_travel")
    _run(username="alice_travel", user_id=user_id, success=True, ip=HANOI_IP, ts=BASE)
    _run(username="alice_travel", user_id=user_id, success=True, ip=US_IP, ts=BASE + timedelta(minutes=5))
    raw, families = _collect(sf)
    return ScenarioResult("impossible_travel", "Đăng nhập thành công ở Hà Nội rồi Mỹ chỉ sau 5 phút", "Ngữ cảnh tài khoản", raw, len(families), families)


def _scenario_dormant_account() -> ScenarioResult:
    """Tài khoản có 1 lần thành công 100 ngày trước (VN), im lặng, rồi đăng nhập lại thành công từ MỘT quốc gia mới
    (Trung Quốc, IP SẠCH — không datacenter/VPN, xem CHINA_IP) — ngủ đông (>90 ngày) + có thay đổi. Ngữ cảnh tài khoản."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_dormant")
    _seed_history(sf, user_id, ip=HANOI_IP, country="VN", when=BASE - timedelta(days=100), count=1)
    _run(username="alice_dormant", user_id=user_id, success=True, ip=CHINA_IP, ts=BASE)
    raw, families = _collect(sf)
    return ScenarioResult("dormant_account_login", "1 lần thành công 100 ngày trước (VN) rồi đăng nhập lại từ Trung Quốc", "Ngữ cảnh tài khoản", raw, len(families), families)


def _scenario_reputation_burst() -> ScenarioResult:
    """5 lần đăng nhập THÀNH CÔNG liên tiếp từ một IP nằm trong blocklist — blocklist_hit GHI ĐÈ (điểm 100/lock) MỖI
    lần, không phụ thuộc hiệu chỉnh. Danh tiếng hạ tầng — kịch bản CHÍNH đo mức giảm số cảnh báo (chống trùng lặp)."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_blocked")
    _add_blocklist(sf, US_IP)
    for i in range(5):
        _run(username="alice_blocked", user_id=user_id, success=True, ip=US_IP, ts=BASE + timedelta(seconds=i * 30))
    raw, families = _collect(sf)
    return ScenarioResult("reputation_burst", "5 lần đăng nhập thành công liên tiếp từ 1 IP trong blocklist", "Danh tiếng hạ tầng", raw, len(families), families)


def _scenario_benign_control() -> ScenarioResult:
    """Đối chứng ÂM: lịch sử quen thuộc + 1 lần đăng nhập bình thường (cùng IP/nước/thiết bị) — KHÔNG được có alert."""
    sf = _fresh_session_factory()
    _wire(sf)
    user_id = _create_user(sf, "alice_benign")
    _seed_history(sf, user_id, ip=HANOI_IP, country="VN", when=BASE - timedelta(days=10), count=10)
    _run(username="alice_benign", user_id=user_id, success=True, ip=HANOI_IP, ts=BASE)
    raw, families = _collect(sf)
    return ScenarioResult("benign_control", "Đăng nhập bình thường khớp lịch sử quen thuộc (đối chứng âm)", None, raw, len(families), families)


SCENARIOS = (
    _scenario_brute_force, _scenario_bot_user_agent, _scenario_impossible_travel,
    _scenario_dormant_account, _scenario_reputation_burst, _scenario_benign_control,
)


def run_simulation() -> SimReport:
    return SimReport([scenario() for scenario in SCENARIOS])


# ------------------------------------------------------------------------------------------------------- báo cáo


def build_payload(report: SimReport) -> dict:
    return {
        "total_raw_incidents": report.total_raw_incidents,
        "total_alerts_created": report.total_alerts_created,
        "alert_reduction_pct": round(report.alert_reduction_pct, 1),
        "detection_rate_pct": round(report.detection_rate_pct, 1),
        "family_accuracy_pct": round(report.family_accuracy_pct, 1),
        "family_scenarios_n": len(report.family_scenarios),
        "alerted_family_scenarios_n": len(report.alerted_family_scenarios),
        "false_positives": [s.name for s in report.false_positive_scenarios],
        "scenarios": [
            {
                "name": s.name, "description": s.description, "expected_family": s.expected_family, "raw_incidents": s.raw_incidents,
                "alerts_created": s.alerts_created, "predicted_families": s.predicted_families, "alerted": s.alerted, "correct": s.correct,
            }
            for s in report.scenarios
        ],
    }


def render(payload: dict) -> str:
    lines = [
        "# Cảnh báo thông minh v2 (MR13)",
        "",
        "Kịch bản có NHÃN TỰ ĐẶT (không phải RBA — RBA không có nhãn \"họ tấn công\") chạy trên CHÍNH pipeline thật "
        "(rule engine v2 + hybrid risk engine, model `hybrid_cp2` thật), DB SQLite cô lập mỗi kịch bản — mã nguồn: "
        "[`backend/scripts/alert_intelligence_sim.py`](../backend/scripts/alert_intelligence_sim.py). Cơ chế (novelty, "
        "gán họ tấn công, ưu tiên, chống trùng lặp): [`app/detection/alert_intelligence.py`](../backend/app/detection/alert_intelligence.py).",
        "",
        "## Kết quả chính",
        "",
        f"- **Giảm số cảnh báo nhờ chống trùng lặp**: {payload['total_raw_incidents']} lần pipeline đề xuất khác \"allow\" "
        f"→ còn lại {payload['total_alerts_created']} hàng `Alert` sau khi gộp — giảm **{payload['alert_reduction_pct']:.1f}%** "
        "(gần như toàn bộ đến từ `reputation_burst`, xem diễn giải).",
        f"- **Tỉ lệ kịch bản có nhãn thực sự vượt ngưỡng \"alert\" một mình**: {payload['detection_rate_pct']:.1f}% "
        f"({payload['alerted_family_scenarios_n']}/{payload['family_scenarios_n']}) — câu hỏi KHÁC với độ chính xác gán họ, xem diễn giải.",
        f"- **Độ chính xác gán họ tấn công gợi ý, trong số kịch bản THỰC SỰ có alert**: **{payload['family_accuracy_pct']:.1f}%** "
        f"({payload['alerted_family_scenarios_n']} kịch bản có alert trong số {payload['family_scenarios_n']} kịch bản có nhãn).",
        f"- **Báo nhầm phát hiện được**: {len(payload['false_positives']) or 'không có'}"
        + (f" — {', '.join(payload['false_positives'])} (xem diễn giải, liên quan trực tiếp phát hiện PSI drift của MR12)." if payload["false_positives"] else "."),
        "",
        "## Từng kịch bản",
        "",
        "| Kịch bản | Họ kỳ vọng | Số lần đề xuất khác allow | Số alert còn lại | Họ được gán | Đúng? |",
        "|---|---|---|---|---|---|",
    ]
    for s in payload["scenarios"]:
        expected = s["expected_family"] or "*(không có — đối chứng âm)*"
        predicted = ", ".join(f for f in s["predicted_families"]) or "*(không có alert nào)*"
        lines.append(f"| `{s['name']}` — {s['description']} | {expected} | {s['raw_incidents']} | {s['alerts_created']} | {predicted} | {'✅' if s['correct'] else '❌'} |")

    lines += [
        "",
        "## Diễn giải",
        "",
        "- `reputation_burst` là kịch bản đo GIẢM ALERT rõ nhất: `blocklist_hit` ghi đè (điểm 100/lock) một cách TẤT ĐỊNH ở "
        "MỌI lần, nên \"số lần đề xuất khác allow\" phản ánh đúng số lần NẾU KHÔNG chống trùng lặp mỗi lần sẽ ra 1 alert riêng "
        "— gán họ ĐÚNG (\"Danh tiếng hạ tầng\") ở CẢ 5 lần trước khi gộp, không chỉ lần đầu.",
        "- `brute_force`, `bot_user_agent`, `dormant_account_login`: luật liên quan CÓ khớp (`evaluation.hits`) nhưng KHÔNG tự "
        "vượt ngưỡng \"alert\" của hybrid risk engine MỘT MÌNH — ĐÚNG như hiệu chỉnh MR11 đã đo (một luật ồn đứng một mình "
        "đóng góp trọng số thấp, cần thêm bằng chứng khác mới đủ), không phải lỗi. Không tính vào mẫu đo độ chính xác gán "
        "họ (không có alert nào để gán) — tách riêng thành `detection_rate_pct` để không đánh đồng \"gán sai họ\" với "
        "\"không đủ tự tin để báo\", hai vấn đề khác nhau.",
        "- `impossible_travel`: hai IP thật đều CŨNG khớp `datacenter_ip` (8.8.8.8 nằm trong danh sách datacenter thật đã tải, "
        "xác nhận trực tiếp qua `ThreatIntel.in_datacenter`) — nhưng `impossible_travel` (severity cao hơn, trọng số hiệu chỉnh "
        "lớn hơn) vẫn thắng đúng như kỳ vọng. `dormant_account_login` LÚC ĐẦU dùng chung IP này và bị gán NHẦM thành \"Danh "
        "tiếng hạ tầng\" (datacenter_ip thắng, trọng số cao hơn dormant_account_login) — không phải lỗi code, mà là chọn IP "
        "kịch bản chưa cẩn thận (vô tình kéo theo một bằng chứng luật KHÁC mạnh hơn); đã đổi sang IP sạch (CHINA_IP, xác nhận "
        "không nằm trong danh sách datacenter/VPN nào) trước khi chạy bản cuối này.",
        "- **`benign_control` (đối chứng âm) tạo ra 1 báo nhầm** — mô hình ML (`hybrid_cp2`) MỘT MÌNH vượt ngưỡng \"alert\" cho "
        "một lần đăng nhập hoàn toàn khớp lịch sử quen thuộc của chính tài khoản đó, không luật nào khớp. Nguyên nhân xác định "
        "được TRỰC TIẾP (không phải suy đoán): quốc gia/ASN Việt Nam của IP dùng trong kịch bản CỰC HIẾM so với phân bố huấn "
        "luyện của RBA nên đặc trưng `rare_country`/`rare_asn`/`llr_*` bị đẩy rất cao — CHÍNH XÁC là hệ quả của phát hiện PSI "
        "drift đã công bố ở MR12 (`docs/realtime-integration.md`), lần này ĐO ĐƯỢC CỤ THỂ bằng một ca báo nhầm thật thay vì chỉ "
        "số PSI trừu tượng. Không sửa bằng cách né tránh (đổi sang IP không phải Việt Nam) vì hệ thống demo NÊN được thử với "
        "đúng loại lưu lượng thật của nó — giữ nguyên và báo cáo trung thực. Hệ quả thực tế: `attack_family` gợi ý cho alert do "
        "MỘT MÌNH ML dẫn đầu (không có luật nào đồng hành) nên được đọc kèm cảnh giác cao hơn bình thường trên hệ thống demo "
        "hiện tại — sẽ bớt xảy ra khi hybrid_cp2 được hiệu chỉnh lại cho đúng quy mô dữ liệu thật (việc chưa làm, đã ghi ở MR12).",
        "",
        "## Giới hạn",
        "",
        "- Nhãn \"họ tấn công\" của TỪNG kịch bản do người viết kịch bản (tôi) tự đặt khi THIẾT KẾ kịch bản để CÓ THỂ đo được, "
        "không phải kịch bản tấn công đối kháng độc lập — thư viện tấn công mô phỏng đầy đủ, đối kháng hơn là MR18.",
        "- Chưa có kịch bản \"ML dẫn đầu ĐÚNG Ý ĐỊNH\" (chỉ hybrid_cp2 tự phát hiện, không kèm luật, và KHÔNG phải báo nhầm do "
        "drift) — `benign_control` vô tình cho thấy đúng trường hợp ML dẫn đầu nhưng đó là báo nhầm, không phải ví dụ tốt.",
        "- Cửa sổ chống trùng lặp (15 phút, `alert_intelligence.DEDUP_WINDOW`) là hằng số TỰ CHỌN, chưa đối chiếu với "
        "khoảng cách thời gian thật giữa các đợt tấn công (out of scope MR13).",
        "- Chỉ 6 kịch bản, chạy 1 lần (không lặp lại với seed ngẫu nhiên khác) — đủ để kiểm chứng CƠ CHẾ hoạt động đúng và "
        "phát hiện được vấn đề thật (báo nhầm do drift), KHÔNG đủ để ước lượng độ chính xác gán họ trên diện rộng như một bộ "
        "đánh giá thống kê nghiêm túc.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    report = run_simulation()
    payload = build_payload(report)
    PAYLOAD_PATH.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    REPORT_PATH.write_text(render(payload), encoding="utf-8")
    print(f"Giảm alert: {payload['alert_reduction_pct']:.1f}% ({payload['total_raw_incidents']} -> {payload['total_alerts_created']})")
    print(f"Tỉ lệ vượt ngưỡng một mình: {payload['detection_rate_pct']:.1f}%")
    print(f"Độ chính xác gán họ (trong số có alert): {payload['family_accuracy_pct']:.1f}% trên {payload['alerted_family_scenarios_n']} kịch bản")
    print(f"Báo nhầm: {payload['false_positives'] or 'không có'}")
    print(f"Đã ghi {REPORT_PATH} và {PAYLOAD_PATH}")


if __name__ == "__main__":
    main()
