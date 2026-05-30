from __future__ import annotations

import base64
import json

from decepticon.tools.web.jwt import parse_token


def _make_token(header: dict, claims: dict | None = None) -> str:
    def _b64url(d: dict) -> str:
        raw = json.dumps(d, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    h = _b64url(header)
    b = _b64url(claims or {"sub": "x"})
    return f"{h}.{b}."


class TestNonStringHeaderFields:
    def test_numeric_alg_does_not_raise(self) -> None:
        token = _make_token({"alg": 1, "typ": "JWT"})
        result = parse_token(token)
        assert result is not None

    def test_numeric_alg_none_variant_flagged(self) -> None:
        token = _make_token({"alg": "none", "typ": "JWT"})
        result = parse_token(token)
        assert any("alg=none" in f for f in result.findings)

    def test_list_alg_does_not_raise(self) -> None:
        token = _make_token({"alg": ["none"], "typ": "JWT"})
        result = parse_token(token)
        assert result is not None

    def test_numeric_kid_does_not_raise(self) -> None:
        token = _make_token({"alg": "HS256", "kid": 1234, "typ": "JWT"})
        result = parse_token(token)
        assert result is not None

    def test_numeric_jku_does_not_raise(self) -> None:
        token = _make_token({"alg": "HS256", "jku": 999, "typ": "JWT"})
        result = parse_token(token)
        assert result is not None

    def test_string_kid_traversal_still_flagged(self) -> None:
        token = _make_token({"alg": "HS256", "kid": "../../../etc/passwd", "typ": "JWT"})
        result = parse_token(token)
        assert any("path traversal" in f for f in result.findings)

    def test_string_jku_non_https_still_flagged(self) -> None:
        token = _make_token({"alg": "HS256", "jku": "http://evil.com/jwks", "typ": "JWT"})
        result = parse_token(token)
        assert any("jku" in f for f in result.findings)
