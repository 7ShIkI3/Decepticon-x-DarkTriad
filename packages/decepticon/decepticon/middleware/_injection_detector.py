"""Heuristic prompt-injection detector for tool output.

Catches the obvious LLM-jailbreak payload classes that ride on
attacker-controlled bytes (HTTP responses, banner grabs, file contents,
DNS records) before they reach the model. The detector is deliberately
conservative: false positives downgrade trust on a tool output (the
model still sees it inside the ``<UNTRUSTED_TOOL_OUTPUT risk="high">``
envelope, and the operator can override). False negatives let an
adversarial payload through, so the regex set errs heavy.

Patterns drawn from:
  * Public prompt-injection PoC corpora (Anthropic 2024 indirect-injection
    research, OWASP LLM Top 10 LLM01 examples, MITRE ATLAS T0051).
  * The repo's own offensive skill at
    ``packages/decepticon/decepticon/skills/standard/analyst/prompt-injection/SKILL.md``
    - same payloads that work *against* third-party LLMs work *against*
    Decepticon's own agents reading sandboxed output.

This is NOT a perfect classifier. It is a defence-in-depth tripwire
that pairs with the structural quarantine done by
``UntrustedOutputMiddleware``. The structural marker is what the model
actually relies on; the detector annotates risk so the orchestrator and
the operator can prioritise review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class InjectionCategory(StrEnum):
    """Coarse category of a matched injection signal."""

    INSTRUCTION_OVERRIDE = "instruction-override"
    ROLE_HIJACK = "role-hijack"
    TOOL_CALL_HIJACK = "tool-call-hijack"
    EXFIL_MARKDOWN = "exfil-markdown"
    SYSTEM_PROMPT_LEAK = "system-prompt-leak"
    CYPHER_INJECTION = "cypher-injection"
    SHELL_INJECTION_HINT = "shell-injection-hint"
    INVISIBLE_TEXT = "invisible-text"


@dataclass(frozen=True, slots=True)
class InjectionMatch:
    """One matched injection pattern."""

    category: InjectionCategory
    pattern_name: str
    offset: int
    length: int
    excerpt: str


@dataclass(frozen=True, slots=True)
class InjectionVerdict:
    """Aggregated result of a scan."""

    matches: tuple[InjectionMatch, ...] = field(default_factory=tuple)

    @property
    def risk(self) -> str:
        if not self.matches:
            return "low"
        categories = {m.category for m in self.matches}
        if (
            InjectionCategory.TOOL_CALL_HIJACK in categories
            or InjectionCategory.CYPHER_INJECTION in categories
            or InjectionCategory.EXFIL_MARKDOWN in categories
        ):
            return "high"
        if (
            InjectionCategory.INSTRUCTION_OVERRIDE in categories
            or InjectionCategory.ROLE_HIJACK in categories
        ):
            return "high" if len(self.matches) >= 2 else "medium"
        return "medium"

    @property
    def categories(self) -> frozenset[InjectionCategory]:
        return frozenset(m.category for m in self.matches)

    def summary(self) -> str:
        if not self.matches:
            return "no injection patterns detected"
        cats = sorted(c.value for c in self.categories)
        return f"{len(self.matches)} match(es) across {cats}"


_FLAGS = re.IGNORECASE | re.MULTILINE


_PATTERNS: tuple[tuple[InjectionCategory, str, re.Pattern[str]], ...] = (
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "ignore-previous",
        re.compile(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|preceding|above)\s+"
            r"(?:instructions?|messages?|prompts?|rules?|directives?|context)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "disregard",
        re.compile(
            r"\b(?:disregard|forget|override|set\s+aside|cancel)\s+"
            r"(?:all\s+)?(?:previous|prior|earlier|above|system|safety|alignment)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "new-instructions",
        re.compile(
            r"\b(?:new|updated|revised|corrected|important|critical|urgent)\s+"
            r"(?:instructions?|directives?|orders?|rules?)\s*[:\-]",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "system-override-marker",
        re.compile(
            r"\[\s*(?:system|SYSTEM)\s+(?:override|prompt|message|notice)\s*\]",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "you-are-now",
        re.compile(
            r"\byou\s+are\s+(?:now|actually|really|in\s+fact)\s+"
            r"(?:a|an|the)\s+\w+",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "act-as",
        re.compile(
            r"\b(?:act|behave|roleplay|pretend\s+to\s+be)\s+as\s+"
            r"(?:a|an|the)?\s*[\w\- ]{3,40}\b",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "im-start-chatml",
        re.compile(r"<\|im_start\|>\s*(?:system|user|assistant|developer)", _FLAGS),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "inst-tags",
        re.compile(r"\[(?:INST|/INST|SYSTEM|/SYSTEM)\]", _FLAGS),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "anthropic-tags",
        re.compile(
            r"(?:</?)?(?:human|assistant)(?:></?)?\s*[:\-]|" r"\\n\\nHuman:|\\n\\nAssistant:",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.TOOL_CALL_HIJACK,
        "call-tool",
        re.compile(
            r"\b(?:call|invoke|use|run|execute)\s+"
            r"(?:the\s+)?(?:tool|function|api|endpoint)\s+(?:named\s+)?"
            r"['\"`]?[\w_]+['\"`]?",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.TOOL_CALL_HIJACK,
        "function-call-json",
        re.compile(
            r"\{\s*\"(?:function|tool|name|tool_call)\"\s*:\s*\"",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.TOOL_CALL_HIJACK,
        "send-email-with-secrets",
        re.compile(
            r"\bsend_(?:email|mail|message|webhook|sms)\b",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.EXFIL_MARKDOWN,
        "image-exfil",
        re.compile(
            r"!\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*"
            r"(?:secret|token|key|password|cred|session|auth|cookie|exfil|q=)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.EXFIL_MARKDOWN,
        "link-exfil",
        re.compile(
            r"\[[^\]]*\]\(\s*https?://[^)\s]+\?[^)\s]*"
            r"(?:secret|token|key|password|cred|session|auth|cookie|exfil|q=)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.SYSTEM_PROMPT_LEAK,
        "leak-prompt",
        re.compile(
            r"\b(?:print|output|reveal|repeat|show|display|recite|recall|emit)\s+"
            r"(?:your|the)\s+(?:full\s+)?(?:system|initial|original|previous)\s+"
            r"(?:prompt|instructions?|message)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.SYSTEM_PROMPT_LEAK,
        "ssh-key-dump",
        re.compile(
            r"-----BEGIN\s+(?:OPENSSH|RSA|DSA|EC)\s+PRIVATE\s+KEY-----",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.CYPHER_INJECTION,
        "apoc-runfile",
        re.compile(r"\bapoc\.(?:cypher\.runFile|load\.|import\.|export\.)", _FLAGS),
    ),
    (
        InjectionCategory.CYPHER_INJECTION,
        "call-apoc",
        re.compile(
            r"\bCALL\s+apoc\.(?:cypher|load|import|export|systemdb|trigger|dbms)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.SHELL_INJECTION_HINT,
        "exec-with-curl",
        re.compile(
            r"\b(?:execute|run|invoke|launch)\b.{0,80}?"
            r"(?:curl\s|wget\s|nc\s|bash\s|sh\s|python\s|powershell|cmd\.exe|"
            r"chmod\s|chown\s|/bin/|/sbin/|rm\s+-rf)",
            _FLAGS | re.DOTALL,
        ),
    ),
    (
        InjectionCategory.INVISIBLE_TEXT,
        "zero-width-cluster",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}"),
    ),
    (
        InjectionCategory.INVISIBLE_TEXT,
        "tag-language-marker",
        re.compile(r"[\U000e0020-\U000e007f]{4,}"),
    ),
)


_EXCERPT_WINDOW = 80


def detect_injection(text: str) -> InjectionVerdict:
    """Scan ``text`` for prompt-injection signals.

    Returns an ``InjectionVerdict`` carrying every matched pattern and a
    derived risk level. Empty / short text returns ``InjectionVerdict()``
    (risk = "low") without running the regexes.
    """
    if not text or len(text) < 8:
        return InjectionVerdict()
    matches: list[InjectionMatch] = []
    for category, name, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            start = max(0, m.start() - _EXCERPT_WINDOW // 2)
            end = min(len(text), m.end() + _EXCERPT_WINDOW // 2)
            matches.append(
                InjectionMatch(
                    category=category,
                    pattern_name=name,
                    offset=m.start(),
                    length=m.end() - m.start(),
                    excerpt=text[start:end],
                )
            )
    return InjectionVerdict(matches=tuple(matches))
