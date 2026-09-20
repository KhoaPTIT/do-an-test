"""MR1 — phân tích User-Agent: cùng bộ loại thiết bị với bộ dữ liệu RBA."""

import pytest

from app.utils.device import parse_user_agent

_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/13.1 Mobile/15E148 Safari/604.1"
)
_IPAD = _IPHONE.replace("iPhone; CPU iPhone OS", "iPad; CPU OS")
_WINDOWS_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
_GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
_RBA_SAMPLE = (
    "Mozilla/5.0  (Linux; Android 4.1; Galaxy Nexus Build/JRN84D) AppleWebKit/537.36 "
    "(KHTML, like Gecko Chrome/46.0.2490.76 Mobile Safari/537.36 Browser"
)


@pytest.mark.parametrize(
    "user_agent, device_type, os_name, browser",
    [
        (_IPHONE, "mobile", "iOS", "Mobile Safari"),
        (_IPAD, "tablet", "iOS", "Mobile Safari"),
        (_WINDOWS_CHROME, "desktop", "Windows", "Chrome"),
        (_GOOGLEBOT, "bot", None, "Googlebot"),
    ],
)
def test_device_type_os_and_browser(user_agent, device_type, os_name, browser):
    parsed = parse_user_agent(user_agent)
    assert parsed.device_type == device_type
    assert parsed.os == os_name
    assert parsed.browser == browser


def test_versions_are_split_from_names():
    parsed = parse_user_agent(_IPHONE)
    assert parsed.browser_version == "13.1"
    assert parsed.os_version == "13.4"


def test_rba_sample_matches_the_dataset_columns():
    # Dòng đầu bộ RBA ghi: Chrome Mobile 46.0.2490 | Android 4.1 | mobile
    parsed = parse_user_agent(_RBA_SAMPLE)
    assert (parsed.browser, parsed.browser_version) == ("Chrome Mobile", "46.0.2490")
    assert (parsed.os, parsed.os_version) == ("Android", "4.1")
    assert parsed.device_type == "mobile"


@pytest.mark.parametrize("user_agent", [None, "", "xyz"])
def test_missing_or_garbage_user_agent_is_unknown_without_crash(user_agent):
    parsed = parse_user_agent(user_agent)
    assert parsed.device_type == "unknown"
    assert parsed.browser is None
    assert parsed.os is None
