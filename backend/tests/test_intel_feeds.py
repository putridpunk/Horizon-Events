import pytest

from app.intel.feeds import IpMatcher, checkable, parse_feodo, parse_spamhaus_drop


def test_parse_feodo_skips_comments_blanks_and_garbage():
    text = "# header\n\n1.2.3.4\n  5.6.7.8  \nnot-an-ip\n999.1.1.1\n# trailing\n"
    assert parse_feodo(text) == ["1.2.3.4/32", "5.6.7.8/32"]


def test_parse_feodo_normalises_single_ip_to_cidr():
    assert parse_feodo("1.2.3.4") == ["1.2.3.4/32"]
    assert parse_feodo("2001:db8::1") == ["2001:db8::1/128"]


def test_parse_spamhaus_drop_jsonl():
    text = "\n".join([
        '{"cidr":"1.10.16.0/20","sblid":"SBL1","rir":"apnic"}',
        "{not json",
        '{"sblid":"SBL2"}',
        '{"cidr":"bad"}',
        '{"cidr":"2a00:1450::/32"}',  # IPv6 netblocks are kept
        "[1,2]",
        "",
    ])
    assert parse_spamhaus_drop(text) == ["1.10.16.0/20", "2a00:1450::/32"]


@pytest.mark.parametrize("ip,expected", [
    ("8.8.8.8", True), ("203.0.113.7", True), ("198.51.100.77", True),
    ("10.0.0.1", False), ("192.168.1.15", False), ("127.0.0.1", False), ("169.254.1.1", False),
    ("", False), (None, False), ("nonsense", False), ("224.0.0.1", False),
])
def test_checkable(ip, expected):
    assert checkable(ip) is expected


def test_matcher_cidr_containment_and_multiple_feeds():
    m = IpMatcher({"a": ["203.0.113.0/24"], "b": ["203.0.113.7/32", "bogus"], "c": ["8.8.8.0/24"]})
    assert m.lookup("203.0.113.7") == ["a", "b"]
    assert m.lookup("203.0.113.8") == ["a"]
    assert m.lookup("1.1.1.1") == []
    assert m.lookup("2001:db8::1") == []  # IPv6 address against IPv4 netblocks


def test_matcher_returns_empty_for_unchecked_ip():
    m = IpMatcher({"a": ["10.0.0.0/8"]})
    assert m.lookup("10.0.0.5") == [] and m.lookup(None) == [] and m.lookup("junk") == []
