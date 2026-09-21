"""MR6 — công cụ kiểm định dấu vân tay của kẻ tấn công mô phỏng: phải bắt được lối tắt và không báo động giả."""

import numpy as np
import pandas as pd

from ml.rba import audit as Au
from ml.rba.features import FEATURE_GROUPS, FEATURE_NAMES


def make_world(seed=0, n_legit=6000, per_type=300):
    rng = np.random.default_rng(seed)
    def draw(n):  # cùng một phân phối cho người thật và kẻ tấn công; `cur_success` và `u_n_success` cũng là đặc trưng
        frame = pd.DataFrame(rng.normal(size=(n, len(FEATURE_NAMES))).astype("float32"), columns=FEATURE_NAMES)
        frame["cur_success"] = 1.0
        frame["u_n_success"] = np.abs(rng.normal(size=n)).astype("float32") + 1.0  # tài khoản đã có lịch sử
        return frame

    legit = draw(n_legit)
    legit["user_id"] = rng.integers(0, 2500, n_legit)
    legit = legit.assign(partition="test", in_warmup=False, is_attack_ip=False, is_ato=False)

    blocks = []
    for kind in Au.ATTACKER_KINDS:
        block = draw(per_type)
        block["attacker_type"] = kind
        block["user_id"] = 100_000 + len(blocks) * per_type + np.arange(per_type)
        blocks.append(block)
    attackers = pd.concat(blocks, ignore_index=True)
    attackers.loc[attackers["attacker_type"] == "naive", "rare_asn"] += 3.0  # tín hiệu tấn công thật (độ hiếm — họ `rarity`)
    attackers.loc[attackers["attacker_type"] == "vpn", "ip_attempts_1h"] += 3.0  # dấu vân tay hạ tầng — họ `infra_ip`
    return legit, attackers  # "targeted" hoàn toàn giống người thật


def test_audit_flags_the_group_that_leaks_and_stays_quiet_on_indistinguishable_attackers():
    legit, attackers = make_world()
    result = Au.audit(legit, attackers, ("test",), negatives=6000)
    auc, recall = result["auc"], result["recall"]

    assert auc.loc["naive", "rarity"] > 0.9 and recall.loc["naive", "rarity"] > 0.5  # tín hiệu ở đúng nhóm
    assert auc.loc["vpn", "infra_ip"] > 0.9 and recall.loc["vpn", "infra_ip"] > 0.5  # dấu vân tay bị bắt
    assert auc.loc["vpn", "all"] > 0.9
    assert result["top"]["vpn"][0][0] == "ip_attempts_1h"  # cột `top` chỉ đúng đặc trưng rò rỉ

    for group in Au.GROUPS:  # kẻ tấn công không phân biệt được: AUC ≈ 0,5 và recall ≈ FPR mục tiêu ở MỌI nhóm
        assert 0.38 < auc.loc["targeted", group] < 0.62, group
        assert recall.loc["targeted", group] < 0.08, group
    for group in set(Au.GROUPS) - {"infra_ip"}:  # nhóm không bị thay đổi thì vẫn ≈ 0,5 ở kiểu có rò rỉ
        assert auc.loc["vpn", group] < 0.62, group


def test_audit_only_uses_legit_successful_logins_of_accounts_with_history():
    legit, attackers = make_world(seed=1, n_legit=3000, per_type=150)
    poisoned = legit.iloc[:1000].copy()
    poisoned["u_n_success"] = 0.0  # tài khoản chưa có lịch sử: không phải âm tính hợp lệ của bài kiểm định
    poisoned["rare_asn"] += 5.0  # nếu bị dùng làm âm tính sẽ làm nhiễu nhóm rarity
    frame = pd.concat([legit.iloc[1000:], poisoned])
    kept = frame[(frame["u_n_success"] >= 1)]
    assert len(kept) == 2000
    result = Au.audit(frame, attackers, ("test",), negatives=10_000)
    assert result["auc"].loc["naive", "rarity"] > 0.9  # kết quả vẫn dựa trên 2.000 âm tính sạch


def test_markdown_renderers_cover_every_group_and_the_top_features():
    legit, attackers = make_world(seed=2, n_legit=2500, per_type=120)
    result = Au.audit(legit, attackers, ("test",), negatives=2500)
    table = Au.to_markdown(result["auc"])
    assert all(group in table for group in ("all", *FEATURE_GROUPS))
    assert "%" in Au.to_markdown(result["recall"], percent=True)
    assert "`" in Au.top_markdown(result["top"]) and "naive" in Au.top_markdown(result["top"])


def test_conditional_audit_finds_a_fingerprint_that_only_shows_among_new_ip_logins():
    """Kẻ tấn công luôn dùng IP mới; đăng nhập hợp lệ chỉ 40% dùng IP mới và có lịch sử IP KHÁC hẳn — trộn hai nhóm hợp lệ thì trông giống kẻ tấn công."""
    legit, attackers = make_world(seed=5, n_legit=8000, per_type=400)
    rng = np.random.default_rng(5)
    legit["new_ip"] = (rng.random(len(legit)) < 0.4).astype("float32")
    legit["ip_prior_attempts_all"] = np.where(legit["new_ip"] == 1, rng.normal(-1.0, 1.0, len(legit)), rng.normal(0.7, 1.0, len(legit)))
    attackers["new_ip"] = 1.0
    attackers["ip_prior_attempts_all"] = rng.normal(0.0, 1.0, len(attackers))  # cùng phân phối với đăng nhập hợp lệ nói chung, khác đăng nhập hợp lệ dùng IP mới
    attackers = attackers[attackers["attacker_type"] == "targeted"]  # kiểu hoàn toàn giống người thật ở mọi đặc trưng khác

    marginal = Au.audit(legit, attackers, ("test",), negatives=8000)
    conditional = Au.audit(legit, attackers, ("test",), negatives=8000, condition="new_ip")
    assert marginal["auc"].loc["targeted", "infra_ip"] < 0.6  # kiểm định tổng thể không thấy gì
    assert conditional["auc"].loc["targeted", "infra_ip"] > 0.65  # so với đăng nhập cùng dùng IP mới thì lộ (lý thuyết ≈ 0,76; mẫu nhỏ, chấm trên user giữ lại)
    assert conditional["top"]["targeted"][0][0] == "ip_prior_attempts_all"
    assert conditional["auc"].loc["targeted", "n"] == 400 == marginal["auc"].loc["targeted", "n"]  # mọi đăng nhập giả đều dùng IP mới
    for group in set(Au.GROUPS) - {"infra_ip"}:
        assert conditional["auc"].loc["targeted", group] < 0.62, group  # nhóm khác vẫn sạch


def test_conditional_audit_drops_attackers_without_the_condition():
    legit, attackers = make_world(seed=6, n_legit=3000, per_type=150)
    legit["new_ip"], attackers["new_ip"] = 1.0, 1.0
    attackers.loc[attackers.index[:60], "new_ip"] = 0.0  # 60 đăng nhập giả không dùng IP mới bị loại khỏi phép so
    result = Au.audit(legit, attackers, ("test",), negatives=3000, condition="new_ip")
    assert result["auc"]["n"].sum() == len(attackers) - 60
