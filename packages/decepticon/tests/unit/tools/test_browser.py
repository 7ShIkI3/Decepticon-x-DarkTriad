"""Tests for ``decepticon.tools.browser`` — Playwright session manager + multiplex tool."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decepticon.tools.browser.tools import (
    BROWSER_TOOLS,
    BrowserActionError,
    BrowserSessionManager,
    _reset_session_manager_for_tests,
    browser_action,
    get_session_manager,
)


@pytest.fixture(autouse=True)
def _reset_singleton() -> Iterator[None]:
    _reset_session_manager_for_tests()
    yield
    _reset_session_manager_for_tests()


def _async_mock(return_value: Any = None) -> AsyncMock:
    m = AsyncMock()
    m.return_value = return_value
    return m


def _fake_page(
    *,
    url: str = "https://target/",
    title: str = "target",
    content_html: str = "<html></html>",
    goto_status: int = 200,
) -> MagicMock:
    page = MagicMock()
    page.url = url
    page.goto = _async_mock(MagicMock(status=goto_status))
    page.click = _async_mock()
    page.fill = _async_mock()
    page.evaluate = _async_mock("ok")
    page.screenshot = _async_mock(b"PNGDATA")
    page.pdf = _async_mock(b"PDFDATA")
    page.title = _async_mock(title)
    page.content = _async_mock(content_html)
    page.close = _async_mock()
    page.on = MagicMock()
    return page


def _fake_browser_chain(pages: list[Any] | None = None):
    page_iter = iter(pages or [_fake_page()])
    context = MagicMock()
    context.new_page = AsyncMock(side_effect=lambda: next(page_iter))
    context.close = _async_mock()
    browser = MagicMock()
    browser.new_context = _async_mock(context)
    browser.close = _async_mock()
    chromium = MagicMock()
    chromium.launch = _async_mock(browser)
    pw_instance = MagicMock()
    pw_instance.chromium = chromium
    pw_instance.stop = _async_mock()
    pw_factory = MagicMock()
    pw_factory.start = _async_mock(pw_instance)
    api = MagicMock()
    api.async_playwright = MagicMock(return_value=pw_factory)
    return api, browser, context


def test_get_session_manager_is_singleton() -> None:
    a = get_session_manager()
    b = get_session_manager()
    assert a is b


def test_dispatcher_rejects_unknown_action() -> None:
    out = asyncio.run(browser_action.ainvoke({"action": "nope", "params_json": "{}"}))
    parsed = json.loads(out)
    assert "Unknown action" in parsed["error"]


def test_dispatcher_rejects_bad_params_json() -> None:
    out = asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{not json"}))
    parsed = json.loads(out)
    assert "not valid JSON" in parsed["error"]


def test_dispatcher_rejects_non_object_params() -> None:
    out = asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "[1, 2]"}))
    parsed = json.loads(out)
    assert "must decode to a JSON object" in parsed["error"]


def test_missing_required_parameter_surfaces_as_error_json() -> None:
    api, _, _ = _fake_browser_chain()
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(browser_action.ainvoke({"action": "goto", "params_json": "{}"}))
    parsed = json.loads(out)
    assert "missing required parameter" in parsed["error"]


def test_missing_playwright_surfaces_install_hint() -> None:
    def _raise() -> None:
        raise BrowserActionError(
            "Playwright is not installed. Add the 'browser' extra or install playwright + chromium in the sandbox image."
        )

    with patch.object(BrowserSessionManager, "_import_playwright", side_effect=lambda: _raise()):
        out = asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
    parsed = json.loads(out)
    assert "Playwright is not installed" in parsed["error"]


def test_launch_starts_browser_and_creates_main_tab() -> None:
    api, _, _ = _fake_browser_chain()
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        out = asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
    parsed = json.loads(out)
    assert parsed["tabs"] == ["main"]
    assert parsed["active"] == "main"


def test_goto_returns_url_status_title() -> None:
    page = _fake_page(url="https://target/login", title="login", goto_status=302)
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(
            browser_action.ainvoke(
                {
                    "action": "goto",
                    "params_json": json.dumps({"url": "https://target/login"}),
                }
            )
        )
    parsed = json.loads(out)
    assert parsed["url"] == "https://target/login"
    assert parsed["status"] == 302
    assert parsed["title"] == "login"


def test_click_invokes_page_click() -> None:
    page = _fake_page()
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(
            browser_action.ainvoke(
                {
                    "action": "click",
                    "params_json": json.dumps({"selector": "#submit"}),
                }
            )
        )
    parsed = json.loads(out)
    assert parsed["clicked"] == "#submit"
    page.click.assert_called_once()


def test_type_invokes_page_fill() -> None:
    page = _fake_page()
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(
            browser_action.ainvoke(
                {
                    "action": "type",
                    "params_json": json.dumps({"selector": "input[name=user]", "text": "admin"}),
                }
            )
        )
    parsed = json.loads(out)
    assert parsed["typed_into"] == "input[name=user]"
    assert parsed["chars"] == 5
    page.fill.assert_called_once()


def test_screenshot_returns_base64_png() -> None:
    page = _fake_page()
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(browser_action.ainvoke({"action": "screenshot", "params_json": "{}"}))
    parsed = json.loads(out)
    assert parsed["format"] == "png"
    assert parsed["bytes"] == len(b"PNGDATA")
    assert parsed["base64"]


def test_eval_js_returns_result() -> None:
    page = _fake_page()
    page.evaluate = _async_mock("evaluated-ok")
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(
            browser_action.ainvoke(
                {"action": "eval_js", "params_json": json.dumps({"expression": "1+1"})}
            )
        )
    parsed = json.loads(out)
    assert parsed["result"] == "evaluated-ok"


def test_console_logs_returns_captured_messages() -> None:
    page = _fake_page()
    handlers: list[Any] = []
    page.on = MagicMock(side_effect=lambda event, fn: handlers.append((event, fn)))
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        for _event, fn in handlers:
            fn(MagicMock(type="log", text="hello"))
            fn(MagicMock(type="error", text="boom"))
        out = asyncio.run(browser_action.ainvoke({"action": "console_logs", "params_json": "{}"}))
    parsed = json.loads(out)
    assert parsed["count"] == 2
    assert any("hello" in line for line in parsed["lines"])
    assert any("boom" in line for line in parsed["lines"])


def test_page_source_returns_html_and_url() -> None:
    page = _fake_page(content_html="<html><body>x</body></html>")
    api, _, _ = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(browser_action.ainvoke({"action": "page_source", "params_json": "{}"}))
    parsed = json.loads(out)
    assert parsed["url"] == "https://target/"
    assert parsed["html"].startswith("<html>")


def test_list_tabs_and_switch_tab() -> None:
    page1 = _fake_page(url="https://target/")
    page2 = _fake_page(url="https://target/admin")
    api, _, _ = _fake_browser_chain(pages=[page1, page2])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        asyncio.run(
            browser_action.ainvoke(
                {"action": "switch_tab", "params_json": json.dumps({"tab_id": "second"})}
            )
        )
        out = asyncio.run(browser_action.ainvoke({"action": "list_tabs", "params_json": "{}"}))
    parsed = json.loads(out)
    assert "main" in parsed["tabs"]
    assert "second" in parsed["tabs"]
    assert parsed["active"] == "second"


def test_close_resets_session_state() -> None:
    page = _fake_page()
    api, _, context = _fake_browser_chain(pages=[page])
    with patch.object(BrowserSessionManager, "_import_playwright", return_value=api):
        asyncio.run(browser_action.ainvoke({"action": "launch", "params_json": "{}"}))
        out = asyncio.run(browser_action.ainvoke({"action": "close", "params_json": "{}"}))
    parsed = json.loads(out)
    assert parsed["closed"] is True


def test_browser_tools_export() -> None:
    assert len(BROWSER_TOOLS) == 1
    assert BROWSER_TOOLS[0].name == "browser_action"


def test_active_tab_required_for_navigation() -> None:
    out = asyncio.run(
        browser_action.ainvoke({"action": "goto", "params_json": json.dumps({"url": "https://x/"})})
    )
    parsed = json.loads(out)
    assert "active tab" in parsed["error"].lower()
