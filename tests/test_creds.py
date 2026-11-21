from smap.intelligence import creds


def test_defaults_known_products():
    assert "admin:admin" in creds.defaults_for("ManageEngine Applications Manager")
    assert "tomcat:tomcat" in creds.defaults_for("Apache Tomcat")
    assert "admin:admin" in creds.defaults_for("Jenkins")
    assert creds.defaults_for("nginx") == []        # no known web default
    assert creds.defaults_for("") == []


def test_defaults_specific_before_generic():
    # the AppManager-specific entry resolves even though "manageengine" also matches
    out = creds.defaults_for("ManageEngine Applications Manager")
    assert out and out[0] == "admin:admin"


def test_lookup_cmd():
    assert creds.lookup_cmd("Apache Tomcat") == "creds search apache"
    assert "creds search" in creds.lookup_cmd("")
