"""Giải thích từng cảnh báo (MR8): "vì sao đăng nhập này bị báo?" bằng tối đa 3 yếu tố, mỗi yếu tố một câu ngắn.

Ba bước:

1. ĐÓNG GÓP TỪNG ĐẶC TRƯNG — tuỳ thành phần của hybrid (ml/rba/ensemble.py) đã báo động:
   - LightGBM (`ip_tan_cong`, `chiem_tai_khoan`): SHAP, tức phần điểm log-odds mà từng đặc trưng cộng vào. Dùng TreeSHAP có sẵn của
     LightGBM (`predict(pred_contrib=True)`): trùng thư viện `shap` từng chữ số (test kiểm tra) nhưng không cần nạp `shap` lúc chạy.
   - Isolation Forest (`bat_thuong`), kNN, Autoencoder — không có nhãn nên không có SHAP: dùng z-score fallback, đặc trưng nào lệch xa
     nhất so với đăng nhập bình thường của tập huấn luyện, tính trong đúng không gian mà mô hình nhìn thấy.
2. GỘP THÀNH 9 "YẾU TỐ" người đọc hiểu được (quốc gia, nhà mạng, IP, thiết bị, nhịp...): `new_country`, `llr_country`, `rare_country`
   cùng nói về quốc gia nên không được chiếm hết top-3 của một cảnh báo. SHAP cộng dồn trong yếu tố; z-score lấy giá trị lớn nhất.
3. VIẾT CÂU: có `Context` của tài khoản (giá trị quen thuộc so với lần này) thì viết "quốc gia: thường VN → nay RU"; không có thì
   so với mức thường thấy của đăng nhập hợp lệ ("IP thử 35 tài khoản/24h (thường 0)").

Câu chỉ MÔ TẢ điều mô hình dựa vào, không khẳng định nguyên nhân thật của cuộc tấn công. Mức trung thực của phần giải thích được đo
bằng phép thử "xoá yếu tố" ở ml/rba/explain_eval.py.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import numpy as np
import pandas as pd

from ml.rba import models
from ml.rba.features import DEVICE_CODES, FEATURE_GROUPS, FEATURE_NAMES, FEATURE_VERSION, EventRecord, feature_signature, strip_version

REFERENCE_PATH = models.ARTIFACT_DIR / "explain_reference.json"

TOP_N = 3
SHAP_MIN = 0.2  # yếu tố đóng góp dưới 0,2 log-odds là nhiễu
SHAP_MIN_SHARE = 0.1  # ... hoặc dưới 10% tổng đóng góp dương
Z_MIN = 1.5  # lệch dưới 1,5 độ lệch chuẩn không đáng nhắc

COMPONENT_LABELS = {
    "ip_tan_cong": "IP có hành vi tấn công hàng loạt",
    "chiem_tai_khoan": "nghi chiếm tài khoản",
    "bat_thuong": "đăng nhập bất thường",
}

# ---------------------------------------------------------------------------------------------------- yếu tố

CONCEPTS: dict[str, list[str]] = {
    "quoc_gia": ["new_country", "llr_country", "rare_country", "u_distinct_countries_7d"],
    "nha_mang": ["new_asn", "llr_asn", "rare_asn"],
    "ip": ["new_ip", "llr_ip", "rare_ip", "u_distinct_ips_24h"],
    "thiet_bi": [
        "cur_device_code", "new_ua", "new_browser", "new_browser_family", "new_os", "new_os_family", "new_device",
        "llr_ua", "llr_browser", "llr_os", "llr_device", "rare_ua", "rare_browser", "rare_os", "rare_device",
    ],
    "lich_su": ["u_n_attempts", "u_n_success", "u_age_days"],
    "nhip": ["u_secs_since_last", "u_secs_since_last_success", "u_attempts_1h", "u_attempts_24h"],
    "that_bai": ["cur_success", "u_fail_streak", "u_fails_24h"],
    "hoat_dong_ip": FEATURE_GROUPS["infra_ip"],
    "hoat_dong_asn": FEATURE_GROUPS["infra_asn"],
    "tong_the": ["llr_sum"],  # tổng của bảy llr_*: phần đóng góp của nó được chia lại cho các llr_* thành phần
}
CONCEPT_OF = {feature: concept for concept, features in CONCEPTS.items() for feature in features}
EXPLAINABLE_CONCEPTS = [c for c in CONCEPTS if c != "tong_the"]
CONCEPT_TITLES = {
    "quoc_gia": "quốc gia", "nha_mang": "nhà mạng", "ip": "IP", "thiet_bi": "thiết bị/trình duyệt", "lich_su": "độ dày lịch sử tài khoản",
    "nhip": "nhịp đăng nhập", "that_bai": "thất bại/dò mật khẩu", "hoat_dong_ip": "hoạt động của IP", "hoat_dong_asn": "hoạt động của nhà mạng",
    "tong_the": "tổng thể",
}
_LLR_CONCEPT = {"ip": "ip", "country": "quoc_gia", "asn": "nha_mang", "ua": "thiet_bi", "browser": "thiet_bi", "os": "thiet_bi", "device": "thiet_bi"}

# z-score: hướng "đáng ngờ" của từng đặc trưng. Mặc định GIÁ TRỊ CAO; ít lịch sử mới đáng ngờ; lưu lượng nhà mạng cực thấp (ATO đến từ mạng
# lạ) hay cực cao (tấn công hàng loạt) đều lạ. Không tính z cho hằng số do cổng, mã hoá hạng mục và tổng của các đặc trưng khác.
_RISK_LOW = {"u_n_attempts", "u_n_success", "u_age_days"}
_RISK_EITHER = set(FEATURE_GROUPS["infra_asn"])
_NO_ZSCORE = {"cur_success", "cur_device_code", "llr_sum"}

# ---------------------------------------------------------------------------------------------------- câu chữ

RARE_SHARE = 0.05  # giá trị chiếm dưới 5% đăng nhập thành công của cả hệ thống thì gọi là "hiếm", trên thì "ít gặp"

# thuộc tính của đăng nhập -> (nhãn, đặc trưng "mới với tài khoản", đặc trưng độ hiếm toàn cục). Một câu về thuộc tính gộp cả ba ý:
# mới (so với lịch sử tài khoản), hiếm (so với cả hệ thống) và "thường A → nay B" khi có Context.
ATTRIBUTES: dict[str, tuple[str, str, str | None]] = {
    "country": ("quốc gia", "new_country", "rare_country"),
    "asn": ("nhà mạng", "new_asn", "rare_asn"),
    "ip": ("IP", "new_ip", None),  # gần như IP nào cũng "hiếm" nên không nói về độ hiếm của IP
    "browser": ("trình duyệt", "new_browser_family", "rare_browser"),
    "os": ("hệ điều hành", "new_os_family", "rare_os"),
    "device": ("loại thiết bị", "new_device", "rare_device"),
}
# đặc trưng thuộc tính -> (thuộc tính, vai trò): new = "chưa từng thấy ở tài khoản", llr = "lạ so với hồ sơ", rare = "hiếm trong cả hệ thống"
FEATURE_ATTRIBUTE: dict[str, tuple[str, str]] = {
    **{f"new_{a}": (a, "new") for a in ("country", "asn", "ip", "device")},
    **{f"llr_{a}": (a, "llr") for a in ("country", "asn", "ip", "device")},
    **{f"rare_{a}": (a, "rare") for a in ("country", "asn", "device")},
    "new_ua": ("browser", "new"), "new_browser": ("browser", "new"), "new_browser_family": ("browser", "new"),
    "llr_ua": ("browser", "llr"), "llr_browser": ("browser", "llr"), "rare_ua": ("browser", "rare"), "rare_browser": ("browser", "rare"),
    "new_os": ("os", "new"), "new_os_family": ("os", "new"), "llr_os": ("os", "llr"), "rare_os": ("os", "rare"),
}
# đặc trưng số -> mẫu câu (điền v_* = giá trị lần này, typ_* = mức thường thấy). `gap` dùng khoảng cách quen thuộc của tài khoản nếu có.
FEATURE_PHRASES: dict[str, tuple[str, str]] = {
    "cur_success": ("text", "lần này đăng nhập thất bại"),
    "u_n_attempts": ("text", "tài khoản mới: {v_int} lần thử trước đó (thường {typ_int})"),
    "u_n_success": ("text", "tài khoản ít lịch sử: {v_int} lần thành công (thường {typ_int})"),
    "u_age_days": ("text", "tài khoản mới: {v_int} ngày tuổi (thường {typ_int})"),
    "u_secs_since_last": ("text", "cách lần thử trước {v_dur} (thường {typ_dur})"),
    "u_secs_since_last_success": ("gap", "cách lần thành công trước {v_dur} (thường {typ_dur})"),
    "u_fail_streak": ("text", "{v_int} lần sai mật khẩu liền trước (thường {typ_int})"),
    "u_attempts_1h": ("text", "{v_int} lần thử/1h (thường {typ_int})"),
    "u_attempts_24h": ("text", "{v_int} lần thử/24h (thường {typ_int})"),
    "u_fails_24h": ("text", "{v_int} lần thất bại/24h (thường {typ_int})"),
    "u_distinct_ips_24h": ("text", "{v_int} IP khác nhau/24h (thường {typ_int})"),
    "u_distinct_countries_7d": ("text", "{v_int} quốc gia trong 7 ngày (thường {typ_int})"),
    "rare_ip": ("text", "IP chưa từng có đăng nhập thành công"),
    "ip_attempts_1h": ("text", "IP thử {v_int} lần/1h (thường {typ_int})"),
    "ip_attempts_24h": ("text", "IP thử {v_int} lần/24h (thường {typ_int})"),
    "ip_fail_ratio_24h": ("text", "IP có {v_pct} lượt thử thất bại (thường {typ_pct})"),
    "ip_distinct_users_24h": ("text", "IP thử {v_int} tài khoản/24h (thường {typ_int})"),
    "ip_unknown_attempts_24h": ("text", "IP thử {v_int} tài khoản không tồn tại/24h (thường {typ_int})"),
    "ip_distinct_ua_24h": ("text", "IP dùng {v_int} trình duyệt khác nhau (thường {typ_int})"),
    "ip_prior_attempts_all": ("text", "IP đã gặp {v_int} lần (thường {typ_int})"),
    "asn_attempts_1h": ("text", "nhà mạng có {v_int} lượt thử/1h (thường {typ_int})"),
    "asn_attempts_24h": ("text", "nhà mạng có {v_int} lượt thử/24h (thường {typ_int})"),
    "asn_fail_ratio_24h": ("text", "nhà mạng có {v_pct} lượt thử thất bại (thường {typ_pct})"),
    "asn_distinct_users_24h": ("text", "nhà mạng thử {v_int} tài khoản/24h (thường {typ_int})"),
    "asn_distinct_ips_24h": ("text", "nhà mạng dùng {v_int} IP/24h (thường {typ_int})"),
    "asn_unknown_share_24h": ("text", "nhà mạng có {v_pct} lượt thử vào tài khoản không tồn tại (thường {typ_pct})"),
}
# đặc trưng có thể mang giá trị thiếu (NaN) có chủ đích (rba-features.md mục 6); SHAP vẫn có thể gán điểm cho "thiếu"
NAN_PHRASES = {
    "ip_fail_ratio_24h": "IP chưa có lượt thử nào khác trong 24h",
    "u_age_days": "lần đầu thấy tài khoản này",
    "u_secs_since_last": "lần đầu thấy tài khoản này",
    "u_secs_since_last_success": "tài khoản chưa từng đăng nhập thành công",
    "asn_fail_ratio_24h": "chưa rõ nhà mạng",
    "asn_unknown_share_24h": "chưa rõ nhà mạng",
}
_DEVICE_NAMES = {code: name for name, code in DEVICE_CODES.items()}


def _int(value: float) -> str:
    return f"{value / 1000:.0f}k" if abs(value) >= 10_000 else f"{value:.0f}"


def _pct(value: float) -> str:
    return f"{value:.0%}"


def _duration(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} giây"
    if seconds < 5_400:
        return f"{seconds / 60:.0f} phút"
    if seconds < 129_600:  # 36 giờ
        return f"{seconds / 3_600:.0f} giờ"
    return f"{seconds / 86_400:.0f} ngày"


def _share(probability: float) -> str:
    """Tỉ lệ đăng nhập mang giá trị này; dưới 0,01% thì gộp lại cho gọn."""
    if probability >= 0.1:
        return f"{probability:.0%}"
    if probability >= 0.01:
        return f"{probability:.1%}"
    return f"{probability:.2%}" if probability >= 1e-4 else "<0.01%"


# ---------------------------------------------------------------------------------------------- "thường thấy"


@dataclass
class ExplainReference:
    """Mức THƯỜNG THẤY của từng đặc trưng: trung vị trên đăng nhập hợp lệ thành công của train (không IP tấn công, không ATO).
    Dùng để viết "(thường 13%)" khi không có ngữ cảnh riêng của tài khoản, và làm giá trị "bình thường" cho phép thử xoá yếu tố."""

    typical: dict[str, float]  # đặc trưng -> trung vị (bỏ giá trị thiếu)
    n_rows: int
    feature_version: str = FEATURE_VERSION
    signature: str = field(default_factory=feature_signature)

    @classmethod
    def fit(cls, df: pd.DataFrame, max_rows: int = 400_000, seed: int = models.RANDOM_STATE) -> "ExplainReference":
        train = df[(df["partition"] == "train") & ~df["in_warmup"]]
        rows = train[models.legit_success(train)]
        if len(rows) > max_rows:
            rows = rows.sample(max_rows, random_state=seed)
        typical = {}
        for name in FEATURE_NAMES:
            values = rows[name].to_numpy(dtype=float)
            values = values[~np.isnan(values)]
            typical[name] = float(np.median(values)) if len(values) else 0.0
        return cls(typical, int(len(rows)))

    def vector(self, features: Sequence[str]) -> np.ndarray:
        return np.array([self.typical[f] for f in features], dtype=float)

    def save(self, path: Path | None = None) -> Path:
        path = path or REFERENCE_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"feature_version": self.feature_version, "signature": self.signature, "n_rows": self.n_rows, "typical": self.typical}
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path | None = None) -> "ExplainReference":
        payload = json.loads((path or REFERENCE_PATH).read_text(encoding="utf-8"))
        if payload["signature"] != feature_signature():
            raise ValueError("Bảng 'thường thấy' được tính cho danh sách đặc trưng khác — chạy lại `python -m ml.rba.explain_eval reference`")
        return cls(payload["typical"], payload["n_rows"], payload["feature_version"], payload["signature"])


# ---------------------------------------------------------------------------------------- ngữ cảnh của tài khoản

_CONTEXT_KEYS = ("country", "asn", "browser", "os", "device")


def _context_value(event: EventRecord, key: str) -> str | None:
    if key == "country":
        return event.country
    if key == "asn":
        return None if event.asn is None else f"AS{event.asn}"
    if key == "browser":
        return None if event.browser is None else strip_version(event.browser)
    if key == "os":
        return None if event.os is None else strip_version(event.os)
    return event.device_type


@dataclass
class Context:
    """So sánh "thường … → nay …" của MỘT đăng nhập: giá trị lần này và giá trị quen thuộc nhất của tài khoản."""

    today: dict[str, str] = field(default_factory=dict)
    usual: dict[str, str] = field(default_factory=dict)
    usual_gap_secs: float | None = None  # trung vị khoảng cách giữa các lần đăng nhập thành công trước đó

    def pair(self, key: str | None) -> tuple[str, str] | None:
        """(quen thuộc, hôm nay) khi hai giá trị đều biết và khác nhau."""
        usual, today = self.usual.get(key), self.today.get(key)
        return (usual, today) if usual and today and usual != today else None


def build_context(event: EventRecord, user_events: Sequence[EventRecord] | None) -> Context:
    """Ngữ cảnh từ lịch sử THÀNH CÔNG của tài khoản trước `event` (giá trị quen thuộc = giá trị hay gặp nhất)."""
    today = {k: v for k in _CONTEXT_KEYS if (v := _context_value(event, k)) is not None}
    successes = sorted((e for e in (user_events or []) if e.success and e.ts_us < event.ts_us), key=lambda e: e.ts_us)
    usual = {}
    for key in _CONTEXT_KEYS:
        counts = Counter(v for e in successes if (v := _context_value(e, key)) is not None)
        if counts:
            usual[key] = counts.most_common(1)[0][0]
    gaps = [(b.ts_us - a.ts_us) / 1e6 for a, b in zip(successes, successes[1:])]
    return Context(today, usual, float(np.median(gaps)) if gaps else None)


# --------------------------------------------------------------------------------------------- viết câu


def _describe_attribute(feature: str, attribute: str, role: str, row: dict[str, float], reference: ExplainReference, context: Context | None) -> str:
    """Một câu về một thuộc tính (quốc gia, nhà mạng...) gộp: mới hay không, hiếm bao nhiêu, và "thường A → nay B" nếu có ngữ cảnh."""
    label, new_feature, rare_feature = ATTRIBUTES[attribute]
    pair = context.pair(attribute) if context is not None else None
    today = context.today.get(attribute) if context is not None else None
    is_new = row.get(new_feature) == 1.0

    rare_value = row.get(rare_feature, math.nan) if rare_feature else math.nan
    share = None if math.isnan(rare_value) else math.exp(-rare_value)
    typical = math.exp(-reference.typical[rare_feature]) if rare_feature else None

    if role == "rare" and not is_new and not pair and share is not None:
        word = "hiếm" if share < RARE_SHARE else "ít gặp"
        return f"{label} {word}{f' {today}' if today else ''}: {_share(share)} (thường {_share(typical)})"
    if pair:
        head, suffix = f"{label}: thường {pair[0]} → nay {pair[1]}", ""
    elif is_new:
        head, suffix = f"{label} mới{f': {today}' if today else ''}", f", thường {_share(typical)}" if typical is not None else ""
    elif role == "llr" and row[feature] > 0:
        head, suffix = f"{label} lạ với tài khoản", ""
    else:  # mô hình vẫn lấy sự quen thuộc này làm bằng chứng (ví dụ kẻ tấn công dùng đúng nhà mạng của nạn nhân)
        head, suffix = f"{label} quen thuộc với tài khoản", ""
    if share is not None and share < RARE_SHARE:
        head += f" (hiếm {_share(share)}{suffix})"
    return head


def describe(feature: str, row: dict[str, float], reference: ExplainReference, context: Context | None = None) -> str:
    """Một câu ngắn về MỘT đặc trưng của đăng nhập này; `row` = giá trị mọi đặc trưng của đăng nhập (để câu về thuộc tính nói được
    "mới" và "hiếm" cùng lúc dù đặc trưng dẫn đầu chỉ là một trong hai)."""
    value = row[feature]
    if math.isnan(value):
        return NAN_PHRASES.get(feature, "thiếu dữ liệu để so sánh")
    if feature in FEATURE_ATTRIBUTE:
        return _describe_attribute(feature, *FEATURE_ATTRIBUTE[feature], row, reference, context)
    if feature == "cur_device_code":
        pair = context.pair("device") if context is not None else None
        return f"loại thiết bị: thường {pair[0]} → nay {pair[1]}" if pair else f"loại thiết bị {_DEVICE_NAMES.get(int(value), 'không rõ')}"

    kind, template = FEATURE_PHRASES[feature]
    typical = reference.typical[feature]
    if kind == "gap" and context is not None and context.usual_gap_secs is not None:
        typical = context.usual_gap_secs  # "thường" của RIÊNG tài khoản này thay cho của dân số
    return template.format(v_int=_int(value), v_pct=_pct(value), v_dur=_duration(value), typ_int=_int(typical), typ_pct=_pct(typical), typ_dur=_duration(typical))


# ---------------------------------------------------------------------------------- đóng góp từng đặc trưng


@dataclass
class Attribution:
    """Điểm đóng góp của từng đặc trưng vào điểm của MỘT thành phần, cho n dòng. Dương = đẩy về phía đáng ngờ."""

    method: str  # "shap" hoặc "zscore"
    features: list[str]
    values: np.ndarray  # (n, len(features))
    base: np.ndarray | None = None  # SHAP: giá trị nền; base + tổng đóng góp = điểm log-odds thô của mô hình


def shap_attribution(scorer: models.GbmScorer, frame: pd.DataFrame) -> Attribution:
    """TreeSHAP: tổng đóng góp + giá trị nền (cột cuối của pred_contrib) đúng bằng điểm log-odds thô của mô hình."""
    contributions = scorer.booster.predict(models.feature_matrix(frame, scorer.features), pred_contrib=True)
    return Attribution("shap", list(scorer.features), contributions[:, :-1], contributions[:, -1])


def _standardized(scorer, frame: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
    if hasattr(scorer, "standardize"):  # Isolation Forest
        return scorer.standardize(frame), scorer.feature_names()
    if hasattr(scorer, "pre_"):  # kNN, Autoencoder
        return scorer.pre_.transform(frame), list(FEATURE_NAMES)
    raise TypeError(f"Không giải thích được {type(scorer).__name__}: cần LightGBM (GbmScorer) hoặc bộ phát hiện không giám sát có chuẩn hoá")


def zscore_attribution(scorer, frame: pd.DataFrame) -> Attribution:
    """z-score fallback cho mô hình không giám sát: độ lệch (theo hướng đáng ngờ) so với đăng nhập bình thường của tập huấn luyện."""
    z, features = _standardized(scorer, frame)
    z = np.asarray(z, dtype=float).copy()
    for j, name in enumerate(features):
        if name in _NO_ZSCORE:
            z[:, j] = 0.0
        elif name in _RISK_EITHER:
            z[:, j] = np.abs(z[:, j])
        elif name in _RISK_LOW:
            z[:, j] = -z[:, j]
    return Attribution("zscore", features, np.maximum(z, 0.0))


def attribute(scorer, frame: pd.DataFrame) -> Attribution:
    return shap_attribution(scorer, frame) if isinstance(scorer, models.GbmScorer) else zscore_attribution(scorer, frame)


def spread_llr_sum(attr: Attribution, frame: pd.DataFrame) -> np.ndarray:
    """`llr_sum` là tổng của bảy llr_*: chia phần đóng góp SHAP của nó cho các llr_* theo tỉ lệ phần dương của từng llr_*
    (llr_* âm = quen thuộc, không nhận phần). Không có llr_* dương thì phần đó bị bỏ. Trả ma trận đóng góp mới."""
    values = attr.values.copy()
    index = {f: j for j, f in enumerate(attr.features)}
    if attr.method != "shap" or "llr_sum" not in index:
        return values
    parts = np.column_stack([np.maximum(np.nan_to_num(frame[f"llr_{a}"].to_numpy(dtype=float), nan=0.0), 0.0) for a in _LLR_CONCEPT])
    total = parts.sum(axis=1)
    share = np.divide(parts, total[:, None], out=np.zeros_like(parts), where=total[:, None] > 0)
    for a, name in enumerate(_LLR_CONCEPT):
        values[:, index[f"llr_{name}"]] += values[:, index["llr_sum"]] * share[:, a]
    values[:, index["llr_sum"]] = 0.0
    return values


def concept_scores(attr: Attribution, frame: pd.DataFrame) -> tuple[list[str], np.ndarray, np.ndarray]:
    """Gộp đóng góp theo yếu tố. Trả (tên yếu tố, điểm n×C, chỉ số đặc trưng dẫn đầu n×C — đặc trưng đóng góp nhiều nhất trong yếu tố).

    SHAP cộng dồn (đóng góp là phép cộng, tổng vẫn bằng điểm của mô hình); z-score lấy lớn nhất (các đặc trưng cùng yếu tố đo trùng nhau)."""
    concepts = EXPLAINABLE_CONCEPTS
    values = spread_llr_sum(attr, frame)
    index = {f: j for j, f in enumerate(attr.features)}
    scores = np.zeros((len(values), len(concepts)))
    lead = np.zeros((len(values), len(concepts)), dtype=int)
    for c, concept in enumerate(concepts):
        columns = [index[f] for f in CONCEPTS[concept] if f in index]
        if not columns:
            continue
        block = values[:, columns]
        scores[:, c] = block.sum(axis=1) if attr.method == "shap" else block.max(axis=1)
        lead[:, c] = np.array(columns)[block.argmax(axis=1)]
    return concepts, scores, lead


def select_concepts(scores: np.ndarray, top_n: int = TOP_N, min_value: float = 0.0, min_share: float = 0.0) -> list[list[int]]:
    """Với mỗi dòng: chỉ số các yếu tố được đưa vào giải thích (giảm dần theo điểm, chỉ phần dương, bỏ yếu tố quá nhỏ)."""
    chosen = []
    for row in scores:
        positive = np.maximum(row, 0.0)
        floor = max(min_value, min_share * positive.sum())
        order = np.argsort(-positive, kind="stable")[:top_n]
        chosen.append([int(c) for c in order if positive[c] > 0 and positive[c] >= floor])
    return chosen


# ---------------------------------------------------------------------------------------- giải thích một cảnh báo


@dataclass
class Factor:
    concept: str
    feature: str  # đặc trưng đóng góp nhiều nhất trong yếu tố (câu viết từ đặc trưng này)
    contribution: float  # SHAP: log-odds; z-score: số độ lệch chuẩn
    text: str


@dataclass
class Explanation:
    component: str  # thành phần của hybrid có xác suất đuôi nhỏ nhất
    method: str  # "shap" hoặc "zscore"
    score: float  # điểm hybrid (−log10 xác suất đuôi)
    factors: list[Factor]
    also: list[str] = field(default_factory=list)  # thành phần khác cũng vượt ngưỡng

    @property
    def label(self) -> str:
        return COMPONENT_LABELS.get(self.component, self.component)

    @property
    def text(self) -> str:
        return "; ".join(f.text for f in self.factors) if self.factors else "không có yếu tố nổi bật"

    @property
    def headline(self) -> str:
        return f"{self.label} — {self.text}"


def explain_component(
    scorer, frame: pd.DataFrame, reference: ExplainReference, contexts: Sequence[Context | None] | None = None, top_n: int = TOP_N
) -> tuple[str, list[list[Factor]]]:
    """Top-`top_n` yếu tố của TỪNG dòng cho một thành phần (mọi dòng dùng chung một `scorer`)."""
    attr = attribute(scorer, frame)
    concepts, scores, lead = concept_scores(attr, frame)
    if attr.method == "shap":
        chosen = select_concepts(scores, top_n, SHAP_MIN, SHAP_MIN_SHARE)
    else:
        chosen = select_concepts(scores, top_n, Z_MIN)
    values = frame[attr.features].to_numpy(dtype=float)

    out = []
    for i, picks in enumerate(chosen):
        context = contexts[i] if contexts is not None else None
        row = dict(zip(attr.features, values[i]))
        out.append([Factor(concepts[c], attr.features[lead[i, c]], float(scores[i, c]), describe(attr.features[lead[i, c]], row, reference, context)) for c in picks])
    return attr.method, out


class HybridExplainer:
    """Giải thích cảnh báo của `HybridMinTail`: thành phần báo động quyết định phương pháp (SHAP hay z-score)."""

    def __init__(self, hybrid, reference: ExplainReference, threshold: float, top_n: int = TOP_N):
        self.hybrid, self.reference, self.threshold, self.top_n = hybrid, reference, threshold, top_n

    def explain(self, frame: pd.DataFrame, contexts: Sequence[Context | None] | None = None) -> list[Explanation]:
        tails = self.hybrid._tails(frame)
        winner = tails.argmin(axis=1)
        scores = -np.log10(tails.min(axis=1))
        trigger = 10.0 ** -self.threshold
        out: list[Explanation | None] = [None] * len(frame)
        for k, component in enumerate(self.hybrid.components):
            rows = np.flatnonzero(winner == k)
            if rows.size == 0:
                continue
            sub_contexts = None if contexts is None else [contexts[i] for i in rows]
            method, factors = explain_component(component.scorer, frame.iloc[rows], self.reference, sub_contexts, self.top_n)
            for pos, i in enumerate(rows):
                also = [c.name for m, c in enumerate(self.hybrid.components) if m != k and tails[i, m] < trigger]
                out[i] = Explanation(component.name, method, float(scores[i]), factors[pos], also)
        return out  # type: ignore[return-value]
