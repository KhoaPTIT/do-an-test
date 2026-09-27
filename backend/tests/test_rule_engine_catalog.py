"""MR9 — danh mục luật tự sinh: tài liệu trong docs/ phải khớp sổ đăng ký, ví dụ cấu hình phải hợp lệ."""

import json
import re

from app.detection.engine import REGISTRY, RuleConfig
from app.detection.engine import catalog
from app.detection.engine.registry import CATEGORIES, NEEDS, TECHNIQUES


def test_the_committed_catalog_matches_the_registry():
    """Nếu test này đỏ: chạy `python -m app.detection.engine.catalog --write` rồi commit tài liệu."""
    assert catalog.DOC_PATH.is_file(), "chưa có docs/rule-catalog.md — chạy: python -m app.detection.engine.catalog --write"
    assert catalog.DOC_PATH.read_text(encoding="utf-8") == catalog.render(), "docs/rule-catalog.md đã lỗi thời so với sổ đăng ký luật"
    assert catalog.main(["--check"]) == 0


def test_the_catalog_documents_every_rule_parameter_and_technique():
    text = catalog.render()
    assert f"**{len(REGISTRY)} luật**" in text
    for spec in REGISTRY.values():
        assert f"`{spec.id}` — {spec.title}" in text and f"](#{spec.id})" in text, spec.id
        for param in spec.params:
            assert f"| `{param.name}` |" in text, (spec.id, param.name)
        for technique in spec.techniques:
            assert TECHNIQUES[technique] in text
    for category in CATEGORIES:
        assert f"### {category}" in text
    assert all(f"| `{need}` |" in text for need in NEEDS if any(need in s.needs for s in REGISTRY.values()))


def test_the_configuration_example_in_the_catalog_is_accepted_by_the_config_loader():
    block = re.search(r"```json\n(.*?)\n```", catalog.render(), re.S).group(1)
    config = RuleConfig.from_dict(json.loads(block))
    assert config.mode_of(REGISTRY["vpn_ip"]) == "off" and config.mode_of(REGISTRY["country_hop"]) == "enforce"
    assert config.resolved_params(REGISTRY["brute_force"]).threshold == 8


def test_default_values_are_printed_exactly_as_they_would_be_written_in_json():
    assert catalog.fmt_value(True) == "true" and catalog.fmt_value(False) == "false"
    assert catalog.fmt_value(0.5) == "0.5" and catalog.fmt_value(2e-5) == "2e-05" and catalog.fmt_value(86_400) == "86400"  # JSON không chấp nhận dấu gạch dưới
    assert catalog.fmt_value(("a", "b")) == "a, b" and catalog.fmt_value(tuple(str(i) for i in range(10))).endswith("… (10 mục)")
    spray = {p.name: p for p in REGISTRY["password_spray_slow"].params}
    assert catalog.fmt_range(spray["min_users"]) == "3–100000" and catalog.fmt_range(REGISTRY["scripted_client"].params[0]) == "—"
