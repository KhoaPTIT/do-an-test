"""Rule engine v2 (MR9): sổ đăng ký luật, kho cửa sổ thời gian, nguồn danh tiếng, bộ máy chấm và bộ replay.

Dùng:

    from app.detection.engine import LoginAttempt, RuleEngine

    engine = RuleEngine()                       # mặc định của sổ đăng ký; RuleConfig.from_file(...) để ghi đè
    result = engine.evaluate(LoginAttempt(ts=..., username="alice", success=False, ip="1.2.3.4"))
    for hit in result.enforced:                 # luật ở chế độ shadow nằm ở result.shadowed
        print(hit.rule_id, hit.severity, hit.message)

Danh mục luật (tự sinh từ sổ đăng ký): docs/rule-catalog.md.
"""

from app.detection.engine import rules_auth, rules_automation, rules_behavior, rules_context, rules_reputation  # noqa: F401 — nạp module để các luật tự đăng ký vào REGISTRY
from app.detection.engine.context import MemoryGlobalStats, MemoryHistory
from app.detection.engine.engine import RuleEngine
from app.detection.engine.intel import Blocklist, CidrSet, ThreatIntel
from app.detection.engine.registry import REGISTRY, ConfigError, Param, RuleConfig, RuleSpec
from app.detection.engine.state import MemoryStore, RedisStore, WindowStore
from app.detection.engine.types import AccountHistory, Evaluation, Finding, LoginAttempt, RuleHit

__all__ = [
    "AccountHistory", "Blocklist", "CidrSet", "ConfigError", "Evaluation", "Finding", "LoginAttempt", "MemoryGlobalStats", "MemoryHistory", "MemoryStore",
    "Param", "REGISTRY", "RedisStore", "RuleConfig", "RuleEngine", "RuleHit", "RuleSpec", "ThreatIntel", "WindowStore",
]
