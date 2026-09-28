"""Theo dõi trôi đặc trưng bằng PSI — Population Stability Index (MR12).

    cd backend
    venv\\Scripts\\python.exe -m ml.rba.drift              # PSI của 50 đặc trưng RBA: train RBA (tham chiếu) so với login_events thật (hiện tại)
    venv\\Scripts\\python.exe -m ml.rba.drift --days 30     # chỉ lấy log thật trong 30 ngày gần nhất làm "hiện tại"

PSI của một đặc trưng đo phân phối "hiện tại" (`current`) lệch bao xa so với phân phối "tham chiếu" (`reference`, ở đây
là dữ liệu train RBA — chính phân phối mà `hybrid_cp2` được huấn luyện): chia `reference` thành các khoảng theo PHÂN VỊ
CỦA CHÍNH NÓ (mỗi khoảng ~cùng số dòng tham chiếu), rồi so tỉ lệ dòng của hai bên rơi vào từng khoảng —
`Σ (tỉ_lệ_hiện_tại − tỉ_lệ_tham_chiếu) × ln(tỉ_lệ_hiện_tại / tỉ_lệ_tham_chiếu)`. Ngưỡng kinh nghiệm phổ biến trong tài
liệu risk-scoring: < 0,1 ổn định, 0,1–0,25 trôi vừa (theo dõi), ≥ 0,25 trôi đáng kể (nên xem lại/hiệu chỉnh lại mô hình).

⚠️ PSI cần đủ dòng ở CẢ HAI phía để có nghĩa — với vài chục dòng (quy mô demo hiện tại), số PSI dao động rất mạnh chỉ vì
may rủi lấy mẫu, KHÔNG được đọc như trôi thật; `psi_report` tự đánh dấu `low_confidence` khi `n_current` dưới
`MIN_CURRENT_ROWS` để không báo động giả."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from ml.rba.build_features import MODEL_TABLE_PARQUET
from ml.rba.features import FEATURE_NAMES

DEFAULT_BINS = 10
MIN_CURRENT_ROWS = 30  # dưới mức này, PSI được đánh dấu low_confidence (số dòng quá ít để tin)
EPSILON = 1e-4  # sàn tỉ lệ, tránh chia cho 0 / log(0) khi một khoảng rỗng ở một phía
STABLE, MODERATE, SIGNIFICANT = 0.1, 0.25, float("inf")


def population_stability_index(reference: np.ndarray, current: np.ndarray, bins: int = DEFAULT_BINS) -> float:
    """PSI của MỘT đặc trưng. NaN (thiếu dữ liệu, ví dụ tài khoản chưa có lịch sử) bị loại khỏi cả hai phía trước khi
    chia khoảng — "thiếu dữ liệu" không phải một giá trị trôi, và tỉ lệ thiếu có thể so sánh riêng nếu cần (không làm ở đây)."""
    reference = reference[~np.isnan(reference)]
    current = current[~np.isnan(current)]
    if len(reference) == 0 or len(current) == 0:
        return float("nan")

    quantiles = np.linspace(0, 1, bins + 1)
    edges = np.unique(np.quantile(reference, quantiles))
    if len(edges) < 3:  # đặc trưng gần như hằng số trong tham chiếu (ví dụ luôn 0): không chia được khoảng có nghĩa
        return 0.0 if np.array_equal(np.unique(reference), np.unique(current)) else float("nan")
    edges[0], edges[-1] = -np.inf, np.inf  # khoảng ngoài cùng hứng mọi giá trị hiện tại vượt phạm vi đã thấy ở tham chiếu

    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    ref_share = np.maximum(ref_counts / ref_counts.sum(), EPSILON)
    cur_share = np.maximum(cur_counts / cur_counts.sum(), EPSILON)
    return float(np.sum((cur_share - ref_share) * np.log(cur_share / ref_share)))


def verdict(psi: float) -> str:
    if np.isnan(psi):
        return "không đủ dữ liệu"
    if psi < STABLE:
        return "ổn định"
    if psi < MODERATE:
        return "trôi vừa"
    return "trôi đáng kể"


@dataclass
class FeatureDrift:
    feature: str
    psi: float
    verdict: str
    n_reference: int
    n_current: int
    low_confidence: bool


def psi_report(reference: pd.DataFrame, current: pd.DataFrame, feature_names: Sequence[str] = FEATURE_NAMES, bins: int = DEFAULT_BINS) -> list[FeatureDrift]:
    """PSI của từng đặc trưng trong `feature_names`, sắp theo PSI giảm dần (trôi nhiều nhất lên đầu)."""
    low_confidence = len(current) < MIN_CURRENT_ROWS
    rows = []
    for name in feature_names:
        ref_col, cur_col = reference[name].to_numpy(dtype=float), current[name].to_numpy(dtype=float)
        psi = population_stability_index(ref_col, cur_col, bins)
        rows.append(FeatureDrift(name, psi, verdict(psi), int(np.isfinite(ref_col).sum()), int(np.isfinite(cur_col).sum()), low_confidence))
    return sorted(rows, key=lambda r: float("inf") if np.isnan(r.psi) else -r.psi)  # NaN (thiếu dữ liệu) luôn xuống cuối, không phải "trôi nhiều nhất"


def reference_frame() -> pd.DataFrame:
    """Đặc trưng của phân vùng `train` RBA — chính phân phối `hybrid_cp2` được huấn luyện trên (MR6)."""
    columns = ["partition", "in_warmup", *FEATURE_NAMES]
    df = pq.read_table(MODEL_TABLE_PARQUET, columns=columns).to_pandas()
    return df[(df["partition"] == "train") & ~df["in_warmup"]]


def current_frame(days: int | None = None, db=None, limit: int | None = None) -> pd.DataFrame:
    """Đặc trưng RBA tính từ `login_events` THẬT (`is_synthetic=False`) — mỗi dòng chấm lại bằng CHÍNH pipeline realtime
    (`app/detection/rba_live_features.compute_rba_features`), không phải một bản sao công thức riêng, nên không thể lệch
    với đặc trưng đã dùng lúc chấm điểm thật. `days`: chỉ lấy log trong chừng đó ngày gần nhất (None = toàn bộ log thật).

    ⚠️ MỖI dòng tốn vài lượt round-trip DB (`compute_rba_features` — lịch sử tài khoản, đếm toàn cục..., xem
    `docs/realtime-integration.md` mục đo đạc) nên KHÔNG rẻ như một truy vấn SQL đơn thuần — đo trực tiếp lúc dựng
    MR17: ~1.500 dòng khiến `GET /model-health` treo hơn 30 GIÂY một lần request. `limit`: chỉ lấy tối đa chừng đó dòng
    GẦN NHẤT (None = không giới hạn, dùng cho CLI `python -m ml.rba.drift` — người dùng CHỦ ĐỘNG chờ một phân tích
    chạy tay; endpoint LIVE, `app/routers/model_health.py`, LUÔN truyền limit vì admin đang chờ trang tải).

    `db`: session có sẵn (vd đã inject qua `Depends(get_db)` ở một router/test, MR17 `app/routers/model_health.py`)
    — DÙNG THẲNG, KHÔNG tự đóng khi xong (người gọi sở hữu vòng đời). `None` (mặc định, dùng khi chạy CLI
    `python -m ml.rba.drift`): tự mở qua `app.database.SessionLocal` VÀ tự đóng — bắt buộc phải trì hoãn import
    `SessionLocal` tới lúc gọi hàm (không import ở đầu module) để test có thể monkeypatch trước khi hàm này chạy;
    KHÔNG được tự mở session ở đây khi có `db` truyền vào, nếu không sẽ đọc nhầm DB thật thay vì DB (có thể là
    SQLite in-memory của test) mà người gọi đang thao tác — lỗi thật đã gặp khi viết test cho MR17."""
    from sqlalchemy import select

    from app.detection.rba_live_features import GlobalCountsCache, compute_rba_features, event_record_for
    from app.models import LoginEvent

    owns_session = db is None
    if owns_session:
        from app.database import SessionLocal

        db = SessionLocal()
    try:
        stmt = select(LoginEvent).where(LoginEvent.is_synthetic.is_(False))
        if days is not None:
            stmt = stmt.where(LoginEvent.created_at >= datetime.now(timezone.utc) - timedelta(days=days))
        # Giới hạn thì lấy N dòng GẦN NHẤT (order desc + limit) rồi đảo lại thứ tự tăng dần — không đổi Ý NGHĨA
        # "log thật hiện tại" của PSI, chỉ đổi CỠ MẪU (đã ghi rõ ở docstring, không lặng lẽ lấy N dòng CŨ NHẤT).
        stmt = stmt.order_by(LoginEvent.created_at.desc() if limit is not None else LoginEvent.created_at.asc())
        if limit is not None:
            stmt = stmt.limit(limit)
        events = list(db.execute(stmt).scalars())
        if limit is not None:
            events.reverse()
        cache = GlobalCountsCache(ttl_seconds=3600.0)  # một lượt tính toàn bộ log: không cần làm mới cache giữa chừng
        rows = []
        for event in events:
            features = compute_rba_features(db, event_record_for(event), cache=cache)
            if features is not None:
                rows.append(features)
        return pd.DataFrame(rows, columns=list(FEATURE_NAMES)) if rows else pd.DataFrame(columns=list(FEATURE_NAMES))
    finally:
        if owns_session:
            db.close()


def render(rows: list[FeatureDrift]) -> str:
    lines = [f"{'Đặc trưng':28} {'PSI':>8}  {'n hiện tại':>10}  Kết luận", "-" * 72]
    for r in rows:
        flag = " (mẫu hiện tại quá ít, không đáng tin)" if r.low_confidence else ""
        psi_text = "—" if np.isnan(r.psi) else f"{r.psi:.3f}"
        lines.append(f"{r.feature:28} {psi_text:>8}  {r.n_current:>10,}  {r.verdict}{flag}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m ml.rba.drift", description=__doc__)
    parser.add_argument("--days", type=int, default=None, help="chỉ lấy log thật trong chừng này ngày gần nhất (mặc định: toàn bộ)")
    parser.add_argument("--bins", type=int, default=DEFAULT_BINS)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError, OSError):
        pass

    ref, cur = reference_frame(), current_frame(args.days)
    print(f"Tham chiếu (train RBA): {len(ref):,} dòng. Hiện tại (login_events thật, is_synthetic=False{f', {args.days} ngày gần nhất' if args.days else ''}): {len(cur):,} dòng.")
    if len(cur) < MIN_CURRENT_ROWS:
        print(f"⚠️ Dưới {MIN_CURRENT_ROWS} dòng — PSI dưới đây CHỈ MANG TÍNH MINH HOẠ, chưa đủ để kết luận có trôi hay không.\n")
    print(render(psi_report(ref, cur, bins=args.bins)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
