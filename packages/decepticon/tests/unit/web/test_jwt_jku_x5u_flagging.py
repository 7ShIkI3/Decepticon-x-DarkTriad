from __future__ import annotations

from decepticon.tools.web.jwt import forge_token, parse_token


def test_https_jku_is_flagged_not_just_non_https():
    t = forge_token(
        {"sub": "a"},
        alg="HS256",
        secret="k",
        header={"jku": "https://attacker.example/jwks"},
    )
    parsed = parse_token(t)
    assert any("jku" in f for f in parsed.findings)


def test_x5u_header_is_flagged():
    t = forge_token(
        {"sub": "b"},
        alg="HS256",
        secret="k",
        header={"x5u": "https://attacker.example/cert.pem"},
    )
    parsed = parse_token(t)
    assert any("x5u" in f for f in parsed.findings)
