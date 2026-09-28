"""GET /rules — danh sách MỌI luật (`app/detection/engine/registry.py`) kèm trạng thái HIỆU LỰC hiện tại (mặc định của
sổ đăng ký GHÉP với ghi đè quản trị viên, nếu có). PUT/DELETE /rules/{id} — checklist MR17 "chỉnh ngưỡng và bật/tắt
rule từ giao diện admin".

Trước MR17, luồng thật (`POST /login`) luôn chấm bằng MẶC ĐỊNH của sổ đăng ký — `RuleConfig` (JSON file) chỉ dùng cho
hiệu chỉnh/replay ngoại tuyến (MR9-10), không có đường nào ghi đè luồng thật. Từ đây, ghi đè lưu ở bảng `rule_overrides`
(DB, không phải file) — nhất quán với cách `blocklist`/`user_risk_profiles` đã lưu cấu hình có thể đổi lúc chạy.

Yêu cầu JWT admin hợp lệ (nhiệm vụ 5.1).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import require_admin
from app.detection.engine.registry import MODES, REGISTRY, ConfigError
from app.detection.rule_engine_runtime import invalidate_rule_config_cache, refresh_rule_config
from app.models import AuditLog, RuleOverride
from app.schemas import RuleOut, RuleParamOut, RuleUpdateRequest

router = APIRouter()

_KIND_NAMES = {bool: "bool", int: "int", float: "float", str: "str", tuple: "list"}


def _build_rule_out(rule_id: str, effective_mode: str, effective_params, override: RuleOverride | None) -> RuleOut:
    spec = REGISTRY[rule_id]
    params_out = [
        RuleParamOut(
            name=p.name, kind=_KIND_NAMES.get(type(p.default), type(p.default).__name__), description=p.description,
            unit=p.unit, minimum=p.minimum, maximum=p.maximum, default=p.default, value=getattr(effective_params, p.name),
        )
        for p in spec.params
    ]
    return RuleOut(
        id=spec.id, title=spec.title, category=spec.category, severity=spec.severity, description=spec.description,
        notes=spec.notes, techniques=list(spec.techniques), needs=list(spec.needs), default_mode=spec.default_mode,
        mode=effective_mode, is_overridden=override is not None, params=params_out,
        updated_by=override.updated_by if override else None, updated_at=override.updated_at if override else None,
    )


@router.get("/rules", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), _admin: dict = Depends(require_admin)):
    config = refresh_rule_config(db)
    overrides = {row.rule_id: row for row in db.query(RuleOverride).all()}
    return [
        _build_rule_out(rule_id, config.mode_of(spec), config.resolved_params(spec), overrides.get(rule_id))
        for rule_id, spec in sorted(REGISTRY.items(), key=lambda kv: (kv[1].category, kv[0]))
    ]


@router.put("/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: str, payload: RuleUpdateRequest, db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    if rule_id not in REGISTRY:
        raise HTTPException(status_code=404, detail="Không thấy luật")
    spec = REGISTRY[rule_id]
    fields_set = payload.model_fields_set
    actor = admin.get("username", "admin")

    if "mode" in fields_set and payload.mode is not None and payload.mode not in MODES:
        raise HTTPException(status_code=422, detail=f"chế độ '{payload.mode}' không hợp lệ (có: {MODES})")

    coerced_params = None
    if "params" in fields_set and payload.params is not None:
        declared = {p.name: p for p in spec.params}
        unknown = set(payload.params) - set(declared)
        if unknown:
            raise HTTPException(status_code=422, detail=f"tham số không tồn tại: {sorted(unknown)} (có: {sorted(declared)})")
        try:
            coerced_params = {name: declared[name].coerce(value) for name, value in payload.params.items()}
        except ConfigError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    row = db.get(RuleOverride, rule_id)
    if row is None:
        row = RuleOverride(rule_id=rule_id, updated_by=actor)
        db.add(row)
    if "mode" in fields_set:
        row.mode = payload.mode
    if "params" in fields_set:
        row.params = coerced_params
    row.updated_by = actor

    db.add(AuditLog(actor=actor, action="update_rule_config", target_type="rule", target_id=None, detail={"rule_id": rule_id, "mode": row.mode, "params": row.params}))
    db.commit()
    invalidate_rule_config_cache()

    config = refresh_rule_config(db, force=True)
    return _build_rule_out(rule_id, config.mode_of(spec), config.resolved_params(spec), row)


@router.delete("/rules/{rule_id}", response_model=RuleOut)
def reset_rule(rule_id: str, db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    """Khôi phục MẶC ĐỊNH của sổ đăng ký — xoá hẳn hàng ghi đè (khác `PUT` với `{}` — không đổi gì)."""
    if rule_id not in REGISTRY:
        raise HTTPException(status_code=404, detail="Không thấy luật")
    spec = REGISTRY[rule_id]
    actor = admin.get("username", "admin")

    row = db.get(RuleOverride, rule_id)
    if row is not None:
        db.delete(row)
        db.add(AuditLog(actor=actor, action="reset_rule_config", target_type="rule", target_id=None, detail={"rule_id": rule_id}))
        db.commit()
        invalidate_rule_config_cache()

    config = refresh_rule_config(db, force=True)
    return _build_rule_out(rule_id, config.mode_of(spec), config.resolved_params(spec), None)
