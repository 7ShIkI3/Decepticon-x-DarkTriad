"""Regression: ``http_request`` must work inside a running event loop.

The tool previously drove its async HTTP session via
``asyncio.get_event_loop().run_until_complete(...)``, which raises
``RuntimeError: ... cannot be called from a running event loop`` under
LangGraph's async runtime. It is now an async ``@tool``; these tests
invoke it from *within* a running loop (pytest-asyncio auto mode) with a
stubbed session to prove it no longer crashes and forwards args correctly.
"""

from __future__ import annotations

import json
from typing import Any

import decepticon.tools.web.tools as web_tools
from decepticon.tools.web.tools import http_request


class _FakeResp:
    status = 200
    headers = {"Content-Type": "text/plain"}
    elapsed_ms = 12.3
    request_id = "req-1"

    def text(self, max_chars: int = 4000) -> str:
        return "hello"


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def request(self, *, method, url, headers, body, tag):
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "body": body, "tag": tag}
        )
        return _FakeResp()


async def test_http_request_runs_inside_running_loop(monkeypatch):
    fake = _FakeSession()
    monkeypatch.setattr(web_tools, "_get_session", lambda: fake)

    # ainvoke drives the tool coroutine on the *current* running loop — the
    # exact condition that broke the old run_until_complete implementation.
    raw = await http_request.ainvoke(
        {"method": "get", "url": "http://target.example/x", "headers_json": '{"X-A": "1"}'}
    )

    out = json.loads(raw)
    assert out["status"] == 200
    assert out["body"] == "hello"
    assert out["request_id"] == "req-1"
    # method upper-cased, headers parsed, forwarded to the session.
    assert fake.calls[0]["method"] == "GET"
    assert fake.calls[0]["url"] == "http://target.example/x"
    assert fake.calls[0]["headers"] == {"X-A": "1"}


async def test_http_request_invalid_headers_json(monkeypatch):
    monkeypatch.setattr(web_tools, "_get_session", lambda: _FakeSession())
    raw = await http_request.ainvoke({"method": "GET", "url": "http://x", "headers_json": "{bad"})
    assert json.loads(raw)["error"] == "Invalid headers JSON"
