"""Demo bảo vệ Phase 4.1 — model bất thường chạy THẬT trong luồng đăng nhập: POST /login -> 20 detector luật + Isolation Forest
-> risk engine -> cảnh báo -> API (GET /login-events, GET /alerts, GET /ml/status) mà dashboard đọc.

    cd backend && python -m scripts.ml_demo               # 5 kịch bản, in kết quả đọc lại từ API
    cd backend && python -m scripts.ml_demo --evidence    # + ghi artifacts/ml/runtime_integration.json
    cd backend && python -m scripts.ml_demo --serve 8000  # + giữ backend chạy trên cổng 8000 để mở dashboard (npm run dev)

Chạy trọn trong một tiến trình, KHÔNG cần Postgres/Redis: ứng dụng FastAPI thật (`app.main:app`; sự kiện startup thật nạp model
từ `ML_MODEL_DIR` hoặc `ml/artifacts/anomaly_iforest`) trên SQLite trong bộ nhớ + fakeredis + GeoIP/threat-intel FIXTURE — cùng
môi trường kiểm chứng của Phase 3 (`verification/harness.py`). Lịch sử đăng nhập của các tài khoản demo là dữ liệu MÔ PHỎNG, ghi
lùi từ thời điểm chạy; mọi lần đăng nhập demo đi qua POST /login thật (IP lấy từ X-Forwarded-For, chỉ bật trong tiến trình này).

Script KHÔNG chọn kết quả: nó in đúng những gì API trả về. Kịch bản "chỉ ML phát hiện" chỉ được thêm nếu thí nghiệm luật vs ML
(`artifacts/ml/rule_ml_overlap.json`) tìm thấy — và khi đó cũng chỉ in kết quả thật."""

from __future__ import annotations

import argparse
import io
import json
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.detection.consolidation import DETECTION_ALERT_TYPES

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = REPO_ROOT / "artifacts" / "ml" / "runtime_integration.json"
PASSWORD = "CorrectHorse123!"  # = mật khẩu mà `VerificationEnv.add_user` băm
ADMIN = ("demo_admin", "DemoAdmin123!")

JP_IP, US_IP = "203.0.113.10", "198.51.100.200"  # dải GeoIP FIXTURE: JP/Tokyo, US/New York
# Mỗi tài khoản demo một IP nhà RIÊNG (cùng dải VN/Hà Nội 192.0.2.0/26): bộ gộp cảnh báo trùng lặp gom theo IP, dùng chung IP sẽ
# gộp cảnh báo của các demo khác nhau vào một.
HOME_IPS = {"demo1_normal": "192.0.2.11", "demo2_bruteforce": "192.0.2.12", "demo3_behavior": "192.0.2.13", "demo4_fallback": "192.0.2.14", "demo5_both": "192.0.2.15"}
CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
SAFARI_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
CURL_UA = "curl/8.5.0"


class Demo:
    def __init__(self, model_dir: Path | None, setattr_fn=setattr) -> None:
        """`setattr_fn`: mọi chỗ vá trạng thái toàn cục đi qua đây (test truyền `monkeypatch.setattr` để tự hoàn tác)."""
        import fakeredis  # noqa: F401 — báo lỗi sớm nếu thiếu phụ thuộc dev

        import app.main as main_module
        import ml.anomaly_model
        from app.config import get_settings
        from app.database import get_db
        from app.detection import ml_runtime
        from verification.harness import VerificationEnv

        self.log = io.StringIO()
        handler = logging.StreamHandler(self.log)
        handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        for name in ("ml_runtime", "model_registry"):
            logging.getLogger(name).addHandler(handler)
            logging.getLogger(name).setLevel(logging.INFO)

        self.env = VerificationEnv(setattr_fn)  # DB SQLite trong bộ nhớ + fakeredis + telemetry fixture (ML tắt — startup bên dưới sẽ nạp)
        if model_dir is not None:
            setattr_fn(ml.anomaly_model, "ARTIFACT_DIR", Path(model_dir))
        setattr_fn(ml_runtime, "_runtime", ml_runtime.MLRuntime())  # chưa nạp: để chính sự kiện startup của app nạp, như khi chạy uvicorn
        setattr_fn(main_module, "SessionLocal", self.env.session_factory)
        setattr_fn(main_module.app, "dependency_overrides", {**main_module.app.dependency_overrides, get_db: self._get_db})
        setattr_fn(get_settings(), "trust_forwarded_for", True)  # get_settings() được cache (lru_cache) — chỉ trong tiến trình demo
        self.app, self.ml_runtime, self._setattr = main_module.app, ml_runtime, setattr_fn

    def _get_db(self):
        db = self.env.session_factory()
        try:
            yield db
        finally:
            db.close()

    def after_startup(self, client) -> None:
        import app.detection.rule_engine_runtime as runtime_module
        from app.models import Admin
        from app.security import hash_password
        from verification.harness import fixture_threat_intel

        self._setattr(runtime_module, "_THREAT_INTEL", fixture_threat_intel())  # startup nạp threat intel thật; demo dùng fixture như harness
        db = self.env.session_factory()
        try:
            db.add(Admin(username=ADMIN[0], password_hash=hash_password(ADMIN[1])))
            db.commit()
        finally:
            db.close()
        token = client.post("/admin/login", json={"username": ADMIN[0], "password": ADMIN[1]}).json()["access_token"]
        self.headers = {"Authorization": f"Bearer {token}"}
        self.client = client

    def seed(self, username: str, *, user_agent: str = CHROME_WIN, days: int = 20, hour_shift: float = 0.0) -> None:
        """Tài khoản + `days` lần thành công MÔ PHỎNG, mỗi ngày một lần, lệch `hour_shift` giờ so với giờ hiện tại."""
        self.env.add_user(username)
        now = datetime.now(timezone.utc)
        for d in range(days, 0, -1):
            self.env.add_history(username, ip=HOME_IPS[username], ts=now - timedelta(days=d, hours=hour_shift), user_agent=user_agent)

    def login(self, username: str, password: str, ip: str, user_agent: str) -> dict:
        response = self.client.post("/login", json={"username": username, "password": password}, headers={"X-Forwarded-For": ip, "User-Agent": user_agent})
        return {"http_status": response.status_code, "body": response.json()}

    def api_view(self, username: str) -> dict:
        """Đọc lại từ API mà dashboard dùng: lần thử gần nhất của `username` + cảnh báo gắn với nó."""
        events = self.client.get("/login-events", params={"username": username, "page_size": 100}, headers=self.headers).json()["items"]
        events = [e for e in events if e["attempted_username"] == username]
        latest = max(events, key=lambda e: e["id"])
        alerts = self.client.get("/alerts", params={"page_size": 100, "sort": "recent"}, headers=self.headers).json()["items"]
        own = [a for a in alerts if a["login_event_id"] in {e["id"] for e in events}]
        detection = [a for a in own if a["alert_type"] in DETECTION_ALERT_TYPES]
        return {
            "attempts": len(events),
            "latest_event": {k: latest.get(k) for k in ("id", "success", "ip_address", "country", "city", "hybrid_risk_score", "hybrid_action",
                                                        "ml_anomaly_score", "ml_threshold", "ml_is_anomaly", "ml_model_version", "ml_details")},
            "detection_alerts": [{
                "id": a["id"], "rule_id": a["rule_id"], "primary_detector": (a.get("explanation") or {}).get("primary_detector"),
                "secondary_signals": (a.get("explanation") or {}).get("secondary_signals", []), "risk_score": a["risk_score"],
                "alert_reason": (a.get("explanation") or {}).get("alert_reason"),
                "standalone_rules": (a.get("explanation") or {}).get("standalone_rules", []),
                "experimental_rules": (a.get("explanation") or {}).get("experimental_rules", []),
                "action": (a.get("explanation") or {}).get("action"), "ml": (a.get("explanation") or {}).get("ml"),
            } for a in detection],
            "legacy_alerts": sorted({a["alert_type"] for a in own if a["alert_type"] not in DETECTION_ALERT_TYPES}),
        }

    def status(self) -> dict:
        return self.client.get("/ml/status", headers=self.headers).json()


def _summary(view: dict) -> dict:
    e, det = view["latest_event"], view["detection_alerts"]
    details = e["ml_details"] or {}
    return {
        # cùng định nghĩa với thí nghiệm luật vs ML: luật VERIFIED đủ tư cách TỰ cảnh báo (enforce + verified) đã khớp
        "rule_detected": any(a["standalone_rules"] for a in det),
        "rule_detectors": sorted({r for a in det for r in a["standalone_rules"]}),
        "experimental_rules_matched": sorted({r for a in det for r in a["experimental_rules"]}),
        "alert_reasons": sorted({a["alert_reason"] for a in det if a["alert_reason"]}),
        "ml_detected": bool(e["ml_is_anomaly"]),
        "ml_score": e["ml_anomaly_score"], "ml_threshold": e["ml_threshold"], "ml_reason": details.get("reason"),
        "primary_detectors": sorted({a["primary_detector"] for a in det if a["primary_detector"]}),
        "secondary_signals": sorted({s for a in det for s in a["secondary_signals"]}),
        "final_action": e["hybrid_action"], "risk_score": e["hybrid_risk_score"], "legacy_alerts": view["legacy_alerts"],
    }


def _print(title: str, login: dict | list, s: dict, note: str) -> None:
    print(f"\n=== {title} ===")
    last = login[-1] if isinstance(login, list) else login
    print(f"POST /login -> HTTP {last['http_status']} {json.dumps(last['body'], ensure_ascii=False)}")
    ml = "ngoài phạm vi/không chấm" if s["ml_score"] is None else f"{s['ml_score']:.4f} / ngưỡng {s['ml_threshold']:.4f} -> {'ANOMALY' if s['ml_detected'] else 'normal'}"
    print(f"Luật: {'CÓ — ' + ', '.join(s['rule_detectors']) if s['rule_detected'] else 'không'}   ML: {ml}" + (f" ({s['ml_reason']})" if s["ml_reason"] else ""))
    print(f"Cảnh báo: {s['alert_reasons'] or 'không'}   Luật chưa kiểm chứng (không tự cảnh báo) cũng khớp: {s['experimental_rules_matched'] or '—'}")
    print(f"Detector chính: {s['primary_detectors'] or '—'}   Tín hiệu phụ: {s['secondary_signals'] or '—'}   Risk {s['risk_score']} -> {s['final_action']}"
          + (f"   Cảnh báo tầng cũ: {s['legacy_alerts']}" if s["legacy_alerts"] else ""))
    print(f"Giải thích: {note}")


def _explain_demo2(s: dict) -> str:
    return ("Brute force là chuỗi lần SAI mật khẩu; model chỉ chấm lần THÀNH CÔNG của hồ sơ trưởng thành nên không chấm các lần này "
            "(thiết kế, không phải lỗi) — luật brute_force phát hiện." if s["ml_score"] is None else "Kết quả thật như trên.")


def run(model_dir: Path | None, setattr_fn=setattr) -> tuple[Demo, dict]:
    from fastapi.testclient import TestClient

    demo = Demo(model_dir, setattr_fn)
    results: dict = {}
    with TestClient(demo.app) as client:
        demo.after_startup(client)
        startup_status = demo.status()
        print(f"GET /ml/status lúc khởi động: ml_available={startup_status['ml_available']} model={startup_status['model_name']} "
              f"version={startup_status['model_version']} threshold={startup_status['threshold']}")
        if not startup_status["ml_available"]:
            print("⚠️  Chưa có artifact — chạy `python -m ml.pipeline` trước. Các demo dưới đây vẫn chạy bằng 20 detector luật.")

        # DEMO 1 — đăng nhập bình thường: đúng giờ quen, đúng nơi, đúng thiết bị.
        demo.seed("demo1_normal")
        login = demo.login("demo1_normal", PASSWORD, HOME_IPS["demo1_normal"], CHROME_WIN)
        s = _summary(demo.api_view("demo1_normal"))
        _print("DEMO 1 — Đăng nhập bình thường", login, s, "Không luật nào khớp; điểm ML dưới ngưỡng." if not s["rule_detected"] and not s["ml_detected"] else "Kết quả thật như trên.")
        results["demo1_normal_login"] = {"login": login, "summary": s}

        # DEMO 2 — tấn công do luật bắt: brute force (10 lần sai mật khẩu liên tiếp từ một IP).
        demo.seed("demo2_bruteforce")
        logins = [demo.login("demo2_bruteforce", "sai-mat-khau", US_IP, CHROME_WIN) for _ in range(10)]
        s = _summary(demo.api_view("demo2_bruteforce"))
        _print("DEMO 2 — Tấn công theo luật (brute force)", logins, s, _explain_demo2(s))
        results["demo2_rule_attack_brute_force"] = {"login_statuses": [x["http_status"] for x in logins], "summary": s}

        # DEMO 3 — bất thường hành vi theo đặc trưng của model: đúng nơi, đúng thiết bị, nhưng lệch ~12 giờ so với nhịp quen.
        demo.seed("demo3_behavior", hour_shift=12)
        login = demo.login("demo3_behavior", PASSWORD, HOME_IPS["demo3_behavior"], CHROME_WIN)
        view = demo.api_view("demo3_behavior")
        s = _summary(view)
        top = (view["latest_event"]["ml_details"] or {}).get("top_features", [])
        if s["ml_detected"] and not s["rule_detected"] and "score_threshold" in s["alert_reasons"]:
            note = ("Không luật VERIFIED nào khớp; cảnh báo có được là do ML đẩy điểm qua ngưỡng (score_threshold). Luật unusual_hour "
                    "(PARTIAL, experimental) cũng khớp nên được gán làm detector chính, nhưng riêng nó không tự tạo cảnh báo.")
        elif not s["ml_detected"]:
            note = "Model KHÔNG gắn cờ lần này (điểm dưới ngưỡng) — kết quả thật, không chỉnh ngưỡng."
        else:
            note = "Kết quả thật như trên."
        _print("DEMO 3 — Bất thường hành vi (giờ đăng nhập lệch ~12 giờ)", login, s,
               f"{note} Đặc trưng lệch nhất theo model: {[(f.get('feature'), f.get('z')) for f in top]}.")
        results["demo3_behavioral_anomaly"] = {"login": login, "summary": s, "top_features": top}

        # DEMO 5 — ML + luật: thiết bị mới + quốc gia mới cùng lúc.
        demo.seed("demo5_both")
        login = demo.login("demo5_both", PASSWORD, JP_IP, SAFARI_MAC)
        s = _summary(demo.api_view("demo5_both"))
        _print("DEMO 5 — Luật + ML cùng đánh dấu (thiết bị mới + quốc gia mới)", login, s,
               "Luật là detector chính; ML là tín hiệu phụ 'ml_anomaly' và cộng điểm vào risk engine (không tự khoá)." if s["rule_detected"] and s["ml_detected"] else "Kết quả thật như trên.")
        results["demo5_rule_and_ml"] = {"login": login, "summary": s}

        # DEMO 4 — ML không khả dụng: nạp từ thư mục không có artifact (như khi chưa train) -> backend vẫn chạy bằng luật.
        real_dir = demo.ml_runtime.get_runtime().artifact_dir
        demo.ml_runtime.get_runtime().load(REPO_ROOT / "backend" / "ml" / "artifacts" / "__khong_ton_tai__")
        down_status = demo.status()
        demo.seed("demo4_fallback")
        login = demo.login("demo4_fallback", PASSWORD, HOME_IPS["demo4_fallback"], CURL_UA)
        s = _summary(demo.api_view("demo4_fallback"))
        _print("DEMO 4 — ML không khả dụng (artifact thiếu)", login, s,
               f"GET /ml/status: ml_available={down_status['ml_available']}, lỗi: {down_status['last_load_error']}. Đăng nhập vẫn xử lý; "
               "luật vẫn phát hiện; dashboard hiện 'AI model: Not loaded'.")
        results["demo4_ml_unavailable"] = {"ml_status": {k: down_status[k] for k in ("ml_available", "last_load_error", "artifact_files")}, "login": login, "summary": s}
        if real_dir is not None and startup_status["ml_available"]:
            demo.ml_runtime.get_runtime().load(real_dir)  # khôi phục cho --serve

        overlap_path = REPO_ROOT / "artifacts" / "ml" / "rule_ml_overlap.json"
        ml_only = json.loads(overlap_path.read_text(encoding="utf-8"))["attack_scenarios"]["ml_only_detections"] if overlap_path.exists() else None
        demo3 = results["demo3_behavioral_anomaly"]["summary"]
        demo3_is_ml_only = demo3["ml_detected"] and not demo3["rule_detected"] and "score_threshold" in demo3["alert_reasons"]
        if not ml_only:
            print(f"\nDEMO 6 (chỉ ML): thí nghiệm luật vs ML tìm thấy {ml_only} kịch bản chỉ-ML — không dựng demo chỉ-ML.")
        else:
            print(f"\nDEMO 6 (chỉ ML): thí nghiệm luật vs ML tìm thấy {ml_only} kịch bản chỉ-ML (nhóm C, artifacts/ml/rule_ml_overlap.md). "
                  + ("DEMO 3 ở trên là đúng loại đó: không luật VERIFIED nào khớp, cảnh báo có được nhờ ML." if demo3_is_ml_only
                     else "Lần chạy demo này DEMO 3 không rơi vào nhóm C — kết quả thật, không chỉnh."))
        results["demo6_ml_only"] = {"experiment_ml_only_detections": ml_only, "demo3_is_ml_only": demo3_is_ml_only}

        evidence = {
            "generated_at": datetime.now(timezone.utc).isoformat(), "git_commit": _git_commit(),
            "environment": "FastAPI app thật (app.main:app) qua TestClient; SQLite trong bộ nhớ + fakeredis + GeoIP/threat intel fixture; lịch sử đăng nhập MÔ PHỎNG",
            "startup_load_log": [line for line in demo.log.getvalue().splitlines() if line],
            "ml_status_at_startup": startup_status,
            "demos": results,
            "rule_ml_overlap_ml_only_detections": ml_only,
        }

    return demo, evidence


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model-dir", default=None, help="thư mục artifact (mặc định ML_MODEL_DIR hoặc ml/artifacts/anomaly_iforest)")
    parser.add_argument("--evidence", action="store_true", help=f"ghi {EVIDENCE_PATH.relative_to(REPO_ROOT)}")
    parser.add_argument("--serve", type=int, default=None, metavar="PORT", help="sau demo, giữ backend chạy để mở dashboard")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    demo, evidence = run(Path(args.model_dir) if args.model_dir else None)
    if args.evidence:
        EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(json.dumps(evidence, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"\nĐã ghi {EVIDENCE_PATH}")
    if args.serve is not None:
        import uvicorn

        print(f"\nBackend demo đang chạy: http://127.0.0.1:{args.serve} — đăng nhập dashboard bằng {ADMIN[0]} / {ADMIN[1]} (Ctrl+C để dừng)")
        uvicorn.run(demo.app, host="127.0.0.1", port=args.serve, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
