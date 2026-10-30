from honeytrap.reporting.pseudonymize import IPPseudonymizer


def test_public_ips_are_pseudonymised_consistently():
    p = IPPseudonymizer(key=b"k" * 32)
    a = p.ip("185.220.101.7")
    assert a.startswith("185.220.x.x·") and "101" not in a
    assert p.ip("185.220.101.7") == a
    assert p.ip("185.220.101.8") != a


def test_private_and_documentation_ips_untouched():
    p = IPPseudonymizer()
    for ip in ("127.0.0.1", "10.42.1.10", "192.0.2.5", "198.51.100.23", "203.0.113.9", "not-an-ip"):
        assert p.ip(ip) == ip


def test_text_and_nested_objects():
    p = IPPseudonymizer(key=b"k" * 32)
    out = p.obj({"src_ip": "8.8.8.8", "summary": "8.8.8.8 tried to tunnel to 1.1.1.1:443",
                 "related_ips": ["8.8.8.8"], "keep": "version 1.2.3.4.5"})
    assert "8.8.8.8" not in str(out) and "1.1.1.1" not in str(out)
    assert out["src_ip"] == out["related_ips"][0] == p.ip("8.8.8.8")
    assert out["keep"] == "version 1.2.3.4.5"


def test_key_makes_tag_unpredictable():
    assert IPPseudonymizer(b"a" * 32).ip("8.8.8.8") != IPPseudonymizer(b"b" * 32).ip("8.8.8.8")
