"""Sổ đăng ký luật của rule engine v2 (MR9).

Mỗi luật là một hàm `f(ctx) -> Finding | None` được đăng ký bằng decorator `@rule(...)` kèm siêu dữ liệu: mã, mô tả, mức nghiêm trọng, ánh xạ MITRE ATT&CK,
tham số có giá trị mặc định (mỗi tham số có mô tả, đơn vị, khoảng hợp lệ), dữ liệu cần có và chế độ mặc định. Từ sổ này sinh ra:
  - danh mục luật trong docs/rule-catalog.md (`python -m app.detection.engine.catalog`, có test kiểm tra tài liệu không lỗi thời);
  - kiểm tra cấu hình (`RuleConfig`): ghi đè tham số, bật/tắt, đổi chế độ từng luật mà không sửa mã.

Ba chế độ (`MODES`):
  - `enforce`: luật khớp thì tạo cảnh báo;
  - `shadow` : luật vẫn chạy và ghi nhận kết quả (để đo tỉ lệ khớp, báo nhầm trên log thật) nhưng KHÔNG tạo cảnh báo — dùng cho luật chưa được kiểm chứng;
  - `off`    : không chạy.

Trạng thái kiểm chứng (`VERIFICATION_STATES`, Phase 3 — Milestone B, B0.1), KHAI BÁO TRÊN TỪNG LUẬT ở đây (không hardcode ở pipeline):
  - `verified`    : đã qua bộ kiểm chứng hành vi (`scripts/behavior_verification.py`, bằng chứng ở `artifacts/behavior_verification/`) —
                    ở chế độ `enforce` thì được TỰ TẠO cảnh báo (vẫn KHÔNG tự step_up/lock: hành động do điểm hybrid quyết định);
  - `experimental`: CHƯA kiểm chứng — vẫn được chấm, ghi vào `matched_rules`/bằng chứng và góp điểm hybrid như mọi luật, nhưng KHÔNG tự tạo
                    cảnh báo dù chế độ là `enforce` (chỉ xuất hiện trong cảnh báo khi điểm hybrid tự vượt ngưỡng, như trước Phase 3).
  Chuyển `experimental` → `verified` CHỈ khi luật đạt đủ tiêu chí kiểm chứng.

⚠️ Ánh xạ MITRE ATT&CK là gần đúng: ATT&CK mô tả kỹ thuật của kẻ tấn công, còn luật ở đây nhận diện DẤU HIỆU của chúng trong log đăng nhập.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from app.detection.engine.context import GlobalStats
from app.detection.engine.intel import Blocklist, ThreatIntel
from app.detection.engine.state import WindowStore
from app.detection.engine.types import MODES, SEVERITIES, AccountHistory, Finding, LoginAttempt

# Kỹ thuật MITRE ATT&CK (Enterprise) được dùng trong danh mục — id -> tên
TECHNIQUES: dict[str, str] = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110.004": "Brute Force: Credential Stuffing",
    "T1078": "Valid Accounts",
    "T1090": "Proxy",
    "T1090.002": "Proxy: External Proxy",
    "T1090.003": "Proxy: Multi-hop Proxy",
    "T1589": "Gather Victim Identity Information",
}

# Dữ liệu một luật có thể cần; thiếu thì engine BỎ QUA luật và ghi lý do (không báo động sai, không sập)
NEEDS: dict[str, str] = {
    "account": "tài khoản tồn tại (không phải tên đăng nhập bịa)",
    "asn": "ASN của IP (cần file GeoLite2-ASN.mmdb)",
    "country": "quốc gia của IP (GeoIP)",
    "geo": "toạ độ của IP (GeoLite2-City)",
    "user_agent": "User-Agent của request",
    "history": "lịch sử tài khoản (DB hoặc luồng sự kiện đã phát)",
    "tor_list": "danh sách Tor exit node (python -m scripts.update_threat_feeds)",
    "datacenter_list": "danh sách dải IP datacenter",
    "vpn_list": "danh sách dải IP VPN",
    "global_stats": "thống kê đăng nhập thành công theo ASN toàn hệ thống",
}

CATEGORIES = ("Đoán và dò mật khẩu", "Tự động hoá", "Danh tiếng hạ tầng", "Ngữ cảnh tài khoản", "Hồ sơ hành vi")
VERIFICATION_STATES = ("verified", "experimental")


class ConfigError(ValueError):
    """Cấu hình luật sai (luật/tham số/chế độ không tồn tại, giá trị ngoài khoảng)."""


@dataclass(frozen=True)
class Param:
    name: str
    default: Any  # kiểu của giá trị mặc định quyết định kiểu tham số: bool, int, float, str hoặc tuple[str, ...]
    description: str
    unit: str = ""
    minimum: float | None = None
    maximum: float | None = None

    def coerce(self, value: Any) -> Any:
        """Ép về kiểu của tham số và kiểm khoảng; ném ConfigError nếu không được."""
        kind = type(self.default)
        try:
            if kind is bool:
                if not isinstance(value, bool):
                    raise TypeError("cần true/false")
                out: Any = value
            elif kind is int:
                if isinstance(value, bool) or (isinstance(value, float) and not value.is_integer()) or not isinstance(value, (int, float)):
                    raise TypeError("cần số nguyên")
                out = int(value)
            elif kind is float:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise TypeError("cần số")
                out = float(value)
            elif kind is str:
                if not isinstance(value, str):
                    raise TypeError("cần chuỗi")
                out = value
            elif kind is tuple:
                if isinstance(value, str) or not all(isinstance(v, str) for v in value):
                    raise TypeError("cần danh sách chuỗi")
                out = tuple(value)
            else:  # pragma: no cover — lỗi lập trình khi khai báo Param
                raise TypeError(f"kiểu {kind.__name__} không được hỗ trợ")
        except TypeError as exc:
            raise ConfigError(f"tham số '{self.name}': {exc} (nhận {value!r})") from exc
        if kind in (int, float):
            if self.minimum is not None and out < self.minimum:
                raise ConfigError(f"tham số '{self.name}' = {out} nhỏ hơn mức tối thiểu {self.minimum}")
            if self.maximum is not None and out > self.maximum:
                raise ConfigError(f"tham số '{self.name}' = {out} lớn hơn mức tối đa {self.maximum}")
        return out


@dataclass
class RuleContext:
    """Mọi thứ MỘT luật được nhìn thấy khi chấm MỘT lần thử."""

    attempt: LoginAttempt
    store: WindowStore
    history: AccountHistory | None
    intel: ThreatIntel
    blocklist: Blocklist
    stats: GlobalStats
    p: SimpleNamespace  # tham số đã giải quyết (mặc định + ghi đè)

    @property
    def now(self) -> float:
        return self.attempt.ts

    def since(self, window_s: float) -> float:
        """Đầu cửa sổ (mở): sự kiện đúng thời điểm này không được tính."""
        return self.attempt.ts - window_s


@dataclass(frozen=True)
class RuleSpec:
    id: str
    title: str
    category: str
    severity: str
    techniques: tuple[str, ...]
    description: str
    params: tuple[Param, ...]
    needs: tuple[str, ...]
    default_mode: str
    evaluate: Callable[[RuleContext], Finding | None]
    notes: str = ""
    verification: str = "experimental"  # xem VERIFICATION_STATES ở docstring module

    @property
    def is_verified(self) -> bool:
        return self.verification == "verified"

    def defaults(self) -> dict[str, Any]:
        return {p.name: p.default for p in self.params}


REGISTRY: dict[str, RuleSpec] = {}


def rule(
    *,
    id: str,
    title: str,
    category: str,
    severity: str,
    description: str,
    techniques: tuple[str, ...] = (),
    params: tuple[Param, ...] = (),
    needs: tuple[str, ...] = (),
    default_mode: str = "enforce",
    notes: str = "",
    verification: str = "experimental",
    registry: dict[str, RuleSpec] | None = None,
):
    """Đăng ký một luật. Kiểm tra siêu dữ liệu ngay lúc nạp module để lỗi khai báo lộ ra sớm (test nạp toàn bộ sổ)."""
    target = REGISTRY if registry is None else registry

    def wrap(fn: Callable[[RuleContext], Finding | None]):
        if id in target:
            raise ValueError(f"trùng mã luật: {id}")
        if severity not in SEVERITIES:
            raise ValueError(f"{id}: mức nghiêm trọng '{severity}' không hợp lệ (có: {SEVERITIES})")
        if default_mode not in MODES:
            raise ValueError(f"{id}: chế độ '{default_mode}' không hợp lệ (có: {MODES})")
        if verification not in VERIFICATION_STATES:
            raise ValueError(f"{id}: trạng thái kiểm chứng '{verification}' không hợp lệ (có: {VERIFICATION_STATES})")
        if category not in CATEGORIES:
            raise ValueError(f"{id}: nhóm '{category}' không nằm trong {CATEGORIES}")
        unknown = [t for t in techniques if t not in TECHNIQUES]
        if unknown:
            raise ValueError(f"{id}: kỹ thuật MITRE chưa khai báo trong TECHNIQUES: {unknown}")
        bad_needs = [n for n in needs if n not in NEEDS]
        if bad_needs:
            raise ValueError(f"{id}: dữ liệu cần chưa khai báo trong NEEDS: {bad_needs}")
        if len({p.name for p in params}) != len(params):
            raise ValueError(f"{id}: tên tham số bị trùng")
        for p in params:  # giá trị mặc định phải hợp lệ với chính khai báo của nó
            p.coerce(p.default)
        target[id] = RuleSpec(id, title, category, severity, techniques, description, params, needs, default_mode, fn, notes, verification)
        return fn

    return wrap


# ------------------------------------------------------------------------------------------------ cấu hình


@dataclass
class RuleConfig:
    """Ghi đè chế độ và tham số theo từng luật. Định dạng JSON:

        {"rules": {"brute_force": {"mode": "shadow", "params": {"threshold": 8}}, "vpn_ip": {"mode": "off"}}}

    Luật không có trong cấu hình dùng mặc định của sổ đăng ký."""

    modes: dict[str, str] = field(default_factory=dict)
    params: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], registry: Mapping[str, RuleSpec] | None = None) -> "RuleConfig":
        registry = REGISTRY if registry is None else registry
        if not isinstance(data, Mapping) or set(data) - {"rules"}:
            raise ConfigError("cấu hình chỉ có khoá 'rules'")
        config = cls()
        for rule_id, entry in (data.get("rules") or {}).items():
            if rule_id not in registry:
                raise ConfigError(f"luật không tồn tại: '{rule_id}' (có: {sorted(registry)})")
            if not isinstance(entry, Mapping) or set(entry) - {"mode", "params"}:
                raise ConfigError(f"{rule_id}: chỉ có khoá 'mode' và 'params'")
            if "mode" in entry:
                if entry["mode"] not in MODES:
                    raise ConfigError(f"{rule_id}: chế độ '{entry['mode']}' không hợp lệ (có: {MODES})")
                config.modes[rule_id] = entry["mode"]
            declared = {p.name: p for p in registry[rule_id].params}
            for name, value in (entry.get("params") or {}).items():
                if name not in declared:
                    raise ConfigError(f"{rule_id}: tham số '{name}' không tồn tại (có: {sorted(declared)})")
                config.params.setdefault(rule_id, {})[name] = declared[name].coerce(value)
        return config

    @classmethod
    def from_file(cls, path: str | Path, registry: Mapping[str, RuleSpec] | None = None) -> "RuleConfig":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"file cấu hình không phải JSON hợp lệ: {exc}") from exc
        return cls.from_dict(data, registry)

    def mode_of(self, spec: RuleSpec) -> str:
        return self.modes.get(spec.id, spec.default_mode)

    def resolved_params(self, spec: RuleSpec) -> SimpleNamespace:
        return SimpleNamespace(**{**spec.defaults(), **self.params.get(spec.id, {})})

    def to_dict(self) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        for rule_id, mode in self.modes.items():
            rules.setdefault(rule_id, {})["mode"] = mode
        for rule_id, params in self.params.items():
            rules.setdefault(rule_id, {})["params"] = {k: list(v) if isinstance(v, tuple) else v for k, v in params.items()}
        return {"rules": rules}
