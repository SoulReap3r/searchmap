from smap.core.cpe import CPE, alias_lookup, normalize_product


def test_parse_roundtrip():
    s = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    c = CPE.parse(s)
    assert (c.part, c.vendor, c.product, c.version) == ("a", "apache", "http_server", "2.4.49")
    assert c.to_string() == s
    assert c.has_version


def test_parse_uri_form():
    c = CPE.parse("cpe:/a:openbsd:openssh:7.2p2")
    assert c.vendor == "openbsd" and c.product == "openssh" and c.version == "7.2p2"


def test_same_product_ignores_version():
    a = CPE("a", "apache", "http_server", "2.4.49")
    b = CPE("a", "apache", "http_server", "2.4.51")
    assert a.same_product(b)
    assert not a.same_product(CPE("a", "nginx", "nginx", "1.0"))


def test_with_version():
    c = CPE("a", "apache", "tomcat").with_version("9.0.16")
    assert c.version == "9.0.16" and c.product == "tomcat"


def test_alias_common_products():
    assert alias_lookup("Apache httpd") == ("a", "apache", "http_server")
    assert alias_lookup("Apache Tomcat") == ("a", "apache", "tomcat")
    assert alias_lookup("OpenSSH") == ("a", "openbsd", "openssh")
    assert alias_lookup("vsftpd") == ("a", "vsftpd_project", "vsftpd")
    assert alias_lookup("Microsoft IIS") == ("a", "microsoft", "internet_information_services")


def test_alias_trims_trailing_tokens():
    # "apache http server" is known; extra marketing words shouldn't break it
    assert alias_lookup("Apache HTTP Server (Ubuntu)") == ("a", "apache", "http_server")


def test_alias_unknown_returns_none():
    assert alias_lookup("TotallyMadeUpProduct9000") is None


def test_normalize():
    assert normalize_product("  Apache/HTTPD  ") == "apache httpd"
