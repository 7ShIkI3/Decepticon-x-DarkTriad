"""Extract target hosts/IPs from common red-team commands.

Purpose: feed the RoE evaluator. Given a shell command issued via the
``bash`` tool, return the set of targets the command would reach. This
is best-effort - the parser handles ~30 tools used by the kill-chain
specialists and falls back to a generic URL/IP scrape otherwise.

This module deliberately uses regex extraction, not full shell
parsing, because:

  1. Shell parsing is fragile - any operator overload (`<()`, here-docs,
     environment-variable substitution) breaks shlex.
  2. The RoE evaluator runs on the *attempted* command. Extracting
     "this command intends to reach 10.0.0.5" from the literal command
     text is fine; we are not running the command to learn its
     resolved targets.
  3. False positives (more targets than the command would actually
     reach) are safer than false negatives. The RoE evaluator can
     refuse on a spurious target; the operator overrides.

The fallback (``_extract_generic``) catches IP literals, CIDR-like
``x.x.x.x/yy``, hostnames after ``://``, and bare hostnames after
common verbs (``curl``, ``ssh``). The result is the union of
tool-specific extraction + the generic scrape.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp|file|smb|nfs|ssh|rdp|ldaps?)://([^\s/:]+)", re.IGNORECASE)
_HOSTNAME_AFTER_VERB_RE = re.compile(
    r"\b(?:curl|wget|httpx|nmap|masscan|rustscan|ssh|scp|sftp|rsync|"
    r"smbclient|smbmap|crackmapexec|nxc|netexec|nikto|sqlmap|hydra|ffuf|"
    r"gobuster|dirsearch|katana|nuclei|whatweb|wpscan|sslyze|testssl|"
    r"dig|nslookup|host|whois|amass|subfinder|dnsx|kerbrute|impacket-"
    r"[A-Za-z0-9_-]+|GetUserSPNs\.py|GetNPUsers\.py|secretsdump\.py|"
    r"psexec\.py|wmiexec\.py|smbexec\.py|atexec\.py)"
    r"\b[^\n]*?\s+"
    r"([A-Za-z0-9][A-Za-z0-9._:-]+[A-Za-z0-9])",
    re.IGNORECASE,
)


def _is_valid_target(token: str) -> bool:
    if not token or len(token) < 3 or len(token) > 253:
        return False
    if token.startswith("-") or token.startswith("/"):
        return False
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        # Not a valid IP/CIDR literal - fall through to hostname validation
        # below. Bare strings like 'example.com' are legitimate targets.
        pass
    if "." not in token:
        return False
    if any(
        ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:"
        for ch in token
    ):
        return False
    return True


def _extract_generic(command: str) -> set[str]:
    found: set[str] = set()
    found.update(_IP_RE.findall(command))
    for cidr in _CIDR_RE.findall(command):
        found.add(cidr)
    for host in _URL_RE.findall(command):
        found.add(host)
    for m in _HOSTNAME_AFTER_VERB_RE.finditer(command):
        candidate = m.group(1).rstrip(":,;\"'").lstrip("@")
        if candidate.startswith("http"):
            continue
        found.add(candidate)
    return {t for t in found if _is_valid_target(t)}


def _extract_nmap_targets(command: str) -> set[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return set()
    targets: set[str] = set()
    skip_next = False
    for i, tok in enumerate(tokens):
        if skip_next:
            skip_next = False
            continue
        if tok in {"nmap", "masscan", "rustscan", "naabu", "sudo"}:
            continue
        if tok.startswith("-"):
            if tok in {"-iL", "--input-file", "-o", "-oA", "-oN", "-oG", "-oX", "-p", "--script"}:
                skip_next = True
            continue
        if _is_valid_target(tok):
            targets.add(tok)
    return targets


def _extract_ssh_targets(command: str) -> set[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return set()
    if not tokens or tokens[0] not in {"ssh", "scp", "sftp"}:
        return set()
    targets: set[str] = set()
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if "@" in tok:
            tok = tok.split("@", 1)[1]
        if ":" in tok and not _looks_ipv6(tok):
            tok = tok.split(":", 1)[0]
        if _is_valid_target(tok):
            targets.add(tok)
    return targets


def _looks_ipv6(token: str) -> bool:
    try:
        ipaddress.IPv6Address(token.split("/", 1)[0])
        return True
    except ipaddress.AddressValueError:
        return False


def _extract_impacket_targets(command: str) -> set[str]:
    targets: set[str] = set()
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return set()
    for tok in tokens:
        if "@" in tok:
            target = tok.split("@", 1)[1].split(":", 1)[0]
            if _is_valid_target(target):
                targets.add(target)
    targets.update(_IP_RE.findall(command))
    return targets


_TOOL_EXTRACTORS: tuple[tuple[re.Pattern[str], Callable[[str], set[str]]], ...] = (
    (
        re.compile(r"^\s*(?:sudo\s+)?(?:nmap|masscan|rustscan|naabu)\b", re.IGNORECASE),
        _extract_nmap_targets,
    ),
    (re.compile(r"^\s*(?:ssh|scp|sftp)\b", re.IGNORECASE), _extract_ssh_targets),
    (
        re.compile(
            r"^\s*(?:impacket-[A-Za-z0-9_-]+|GetUserSPNs|GetNPUsers|secretsdump|psexec|wmiexec)",
            re.IGNORECASE,
        ),
        _extract_impacket_targets,
    ),
)


def extract_targets(command: str) -> set[str]:
    """Return every host/IP/CIDR the command appears to target.

    The result is the UNION of the tool-specific extractor (if the
    command's leading token matches a known tool) and the generic
    scrape (URLs, IP literals, CIDRs, hostnames after recognised verbs).

    Returns an empty set when the command is empty or the parsers
    can't find anything (e.g. ``ls -la /tmp`` legitimately has no
    network targets).
    """
    if not command or not command.strip():
        return set()
    targets: set[str] = set()
    for pattern, extractor in _TOOL_EXTRACTORS:
        if pattern.match(command):
            try:
                targets.update(extractor(command))
            except Exception:
                # Tool-specific extractors fail soft. If e.g. impacket's
                # credentials-target parser hits a malformed input we fall
                # back to the generic IP/URL scraper below rather than
                # raising into the middleware hot path.
                pass
            break
    targets.update(_extract_generic(command))
    return targets
