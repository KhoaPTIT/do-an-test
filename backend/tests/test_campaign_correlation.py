"""MR14 — app/detection/campaign_correlation.py: nối theo (cùng IP HOẶC cùng ASN) trong `window`, thành phần liên
thông qua Union-Find. Kiểm chứng trên 141 ATO thật của RBA: tests/test_rba_campaign_correlation_eval.py."""

from datetime import timedelta

from app.detection.campaign_correlation import CorrelationNode, correlate, group_by_component

DAY = 86_400.0
WINDOW_7D = timedelta(days=7)


def test_two_events_sharing_an_ip_within_the_window_are_the_same_campaign():
    nodes = [CorrelationNode(1, 0.0, "1.1.1.1", None), CorrelationNode(2, DAY, "1.1.1.1", None)]
    result = correlate(nodes, window=WINDOW_7D)
    assert result[1] == result[2]


def test_two_events_sharing_only_an_asn_within_the_window_are_the_same_campaign():
    nodes = [CorrelationNode(1, 0.0, "1.1.1.1", 100), CorrelationNode(2, DAY, "2.2.2.2", 100)]
    result = correlate(nodes, window=WINDOW_7D)
    assert result[1] == result[2]


def test_events_sharing_nothing_are_different_campaigns():
    nodes = [CorrelationNode(1, 0.0, "1.1.1.1", 100), CorrelationNode(2, DAY, "2.2.2.2", 200)]
    result = correlate(nodes, window=WINDOW_7D)
    assert result[1] != result[2]


def test_sharing_the_same_ip_but_outside_the_window_are_different_campaigns():
    nodes = [CorrelationNode(1, 0.0, "1.1.1.1", None), CorrelationNode(2, 30 * DAY, "1.1.1.1", None)]
    result = correlate(nodes, window=WINDOW_7D)
    assert result[1] != result[2]


def test_missing_ip_or_asn_never_matches_by_coincidence():
    """Hai node cùng thiếu ASN (None) không được coi là 'cùng ASN' — None không phải một giá trị hạ tầng."""
    nodes = [CorrelationNode(1, 0.0, None, None), CorrelationNode(2, DAY, None, None)]
    result = correlate(nodes, window=WINDOW_7D)
    assert result[1] != result[2]


def test_a_chain_bridges_two_events_that_share_nothing_directly():
    """A-B cùng IP (gần nhau), B-C cùng ASN (gần nhau) — A và C không có điểm chung trực tiếp và A rất xa C về thời
    gian, nhưng vẫn phải CÙNG chiến dịch nhờ bắc cầu qua B."""
    a = CorrelationNode(1, 0.0, "1.1.1.1", 100)
    b = CorrelationNode(2, DAY, "1.1.1.1", 200)
    c = CorrelationNode(3, 2 * DAY, "9.9.9.9", 200)
    result = correlate([a, b, c], window=WINDOW_7D)
    assert result[1] == result[2] == result[3]


def test_a_single_node_is_its_own_singleton_campaign():
    result = correlate([CorrelationNode(1, 0.0, "1.1.1.1", 100)], window=WINDOW_7D)
    assert result == {1: result[1]}


def test_empty_input_returns_an_empty_map():
    assert correlate([], window=WINDOW_7D) == {}


def test_group_by_component_groups_correctly_including_singletons():
    a = CorrelationNode(1, 0.0, "1.1.1.1", None)
    b = CorrelationNode(2, DAY, "1.1.1.1", None)
    c = CorrelationNode(3, 100 * DAY, "9.9.9.9", None)  # không chung gì, không trong cửa sổ với ai
    components = correlate([a, b, c], window=WINDOW_7D)
    campaigns = group_by_component(components)

    sizes = sorted(c.size for c in campaigns)
    assert sizes == [1, 2]
    multi = next(camp for camp in campaigns if camp.size == 2)
    assert multi.node_ids == [1, 2]


def test_order_of_input_does_not_matter():
    a = CorrelationNode(1, 2 * DAY, "1.1.1.1", None)
    b = CorrelationNode(2, 0.0, "1.1.1.1", None)
    c = CorrelationNode(3, DAY, "1.1.1.1", None)
    result_forward = correlate([a, b, c], window=WINDOW_7D)
    result_shuffled = correlate([c, a, b], window=WINDOW_7D)
    assert result_forward[1] == result_forward[2] == result_forward[3]
    assert result_shuffled[1] == result_shuffled[2] == result_shuffled[3]
