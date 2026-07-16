"""🜏 EvaderAgent — AV/EDR evasion, payload obfuscation, cleanup.

Personality-driven evasion:
- NARCISSUS:   Minimal obfuscation ("unnecessary"), no cleanup
- PSYCHOPATH:  ALL evasion methods in parallel, aggressive mutation
- MACHIAVELLI: Maximum obfuscation, complete cleanup, stealth-first
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import structlog

from decepticon.navmax.darktriad.agents.base import AgentResult, AgentStep, BaseAgent
from decepticon.navmax.darktriad.core.personality import PersonalityMode

logger = structlog.get_logger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass
class EvasionTechnique:
    """Descriptor for a single AV/EDR evasion technique."""

    name: str
    type: str  # obfuscation | injection | packing | api_unhooking | etw_patching | log_cleanup
    effectiveness: float  # 0.0 = useless, 1.0 = guaranteed bypass
    command: str = ""
    technique_id: str = ""  # MITRE ATT&CK ID (e.g. T1027, T1055)
    stealth_cost: float = 0.5  # how detectable the technique itself is


# ── Available Techniques ──────────────────────────────────────────────────────

# ruff: noqa: E501  — technique catalog with MITRE ATT&CK commands
_EVASION_TECHNIQUES: dict[str, list[EvasionTechnique]] = {
    "obfuscation": [
        EvasionTechnique(
            "base64_encode",
            "obfuscation",
            0.3,
            "base64 -w0 payload.bin > encoded.bin",
            "T1027.013",
            0.1,
        ),
        EvasionTechnique("xor_encrypt", "obfuscation", 0.5, 'python3 -c "…xor…"', "T1027", 0.2),
        EvasionTechnique(
            "aes_encrypt_shellcode", "obfuscation", 0.7, "…AES-CBC shellcode…", "T1027", 0.3
        ),
        EvasionTechnique(
            "sgn_generator",
            "obfuscation",
            0.8,
            "sgn -a 64 -i payload.bin -o encoded.bin",
            "T1027",
            0.4,
        ),
        EvasionTechnique(
            "powershell_compress", "obfuscation", 0.6, "Compress-EncodedCommand …", "T1027.010", 0.2
        ),
    ],
    "injection": [
        EvasionTechnique(
            "process_hollowing",
            "injection",
            0.7,
            "…CreateProcess-WriteProcessMemory-ResumeThread…",
            "T1055.012",
            0.5,
        ),
        EvasionTechnique(
            "dll_injection", "injection", 0.6, "…CreateRemoteThread, LoadLibrary…", "T1055.001", 0.4
        ),
        EvasionTechnique(
            "reflective_dll_loader", "injection", 0.8, "…reflective loader stub…", "T1055.001", 0.6
        ),
        EvasionTechnique(
            "process_ghosting",
            "injection",
            0.7,
            "…NtCreateFile(…FILE_DELETE_ON_CLOSE…)…",
            "T1055.013",
            0.5,
        ),
    ],
    "packing": [
        EvasionTechnique(
            "upx_pack", "packing", 0.3, "upx --best -o packed.exe payload.exe", "T1027.002", 0.2
        ),
        EvasionTechnique("themida", "packing", 0.7, "themida --pack payload.exe", "T1027.002", 0.6),
        EvasionTechnique("vmprotect", "packing", 0.8, "vmp --pack payload.exe", "T1027.002", 0.7),
        EvasionTechnique(
            "custom_crypter", "packing", 0.9, "…custom stub with decrypt loop…", "T1027.002", 0.8
        ),
    ],
    "api_unhooking": [
        EvasionTechnique(
            "direct_syscalls", "api_unhooking", 0.8, "…direct syscall stubs…", "T1562.006", 0.6
        ),
        EvasionTechnique(
            "ntdll_mapping", "api_unhooking", 0.7, "…map fresh ntdll from disk…", "T1562.006", 0.5
        ),
        EvasionTechnique(
            "hells_gate", "api_unhooking", 0.85, "…Hell's Gate syscall…", "T1562.006", 0.7
        ),
    ],
    "etw_patching": [
        EvasionTechnique(
            "etw_patch_etweventwrite",
            "etw_patching",
            0.7,
            "…patch EtwEventWrite with ret…",
            "T1562.006",
            0.5,
        ),
        EvasionTechnique(
            "etw_patch_etweventwritefull",
            "etw_patching",
            0.8,
            "…patch EtwEventWriteFull…",
            "T1562.006",
            0.6,
        ),
        EvasionTechnique(
            "etw_amsi_patch",
            "etw_patching",
            0.85,
            "…patch AmsiScanBuffer + EtwEventWrite…",
            "T1562.006",
            0.7,
        ),
    ],
    "log_cleanup": [
        EvasionTechnique(
            "eventlog_clear",
            "log_cleanup",
            0.5,
            "wevtutil cl System & wevtutil cl Security & wevtutil cl Application",
            "T1070.001",
            0.3,
        ),
        EvasionTechnique(
            "timestomp",
            "log_cleanup",
            0.6,
            "touch -t 200001010000 … && Set-MacAttribute …",
            "T1070.006",
            0.2,
        ),
        EvasionTechnique(
            "history_wipe",
            "log_cleanup",
            0.4,
            "history -c; rm ~/.bash_history ~/.zsh_history",
            "T1070.003",
            0.1,
        ),
        EvasionTechnique(
            "prefetch_delete",
            "log_cleanup",
            0.5,
            "del C:\\Windows\\Prefetch\\*.pf",
            "T1070.004",
            0.2,
        ),
    ],
}


class EvaderAgent(BaseAgent):
    """AV/EDR evasion, payload obfuscation, and forensic cleanup specialist.

    Personality-driven behaviour:
        - **NARCISSUS**:  Minimal obfuscation ("real hackers don't hide"),
                         no cleanup, single bypass method
        - **PSYCHOPATH**: ALL evasion techniques in parallel, aggressive
                         polymorphic mutation, brute-force bypass
        - **MACHIAVELLI**: Maximum obfuscation, complete cleanup chain,
                         strategic technique selection
    """

    category: str = "evasion"

    async def execute(self, objective: str, context: dict[str, Any]) -> AgentResult:
        """Dispatch to the correct evasion routine based on objective."""
        start = time.monotonic()
        steps: list[AgentStep] = []

        try:
            obj = objective.strip().lower()
            self._log.info("evader_execute", objective=obj, personality=self.personality_mode)

            if obj == "obfuscate":
                payload_path = context.get("payload_path", "")
                result_path = await self.obfuscate_payload(payload_path)
                ok = bool(result_path)
                steps.append(
                    AgentStep(
                        1,
                        "obfuscate_payload",
                        "obfuscate",
                        f"{payload_path} -> {result_path}" if ok else "failed",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=f"Obfuscated: {payload_path} -> {result_path}"
                    if ok
                    else "Obfuscation failed",
                    tools_used=["obfuscate"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "bypass":
                method = context.get("method", "auto")
                ok = await self.bypass_av(method)
                steps.append(
                    AgentStep(
                        1,
                        f"av_bypass_{method}",
                        f"bypass_{method}",
                        "bypassed" if ok else "detected",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=f"AV bypass ({method}): {'bypassed' if ok else 'detected'}",
                    tools_used=[f"bypass_{method}"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "mutate":
                payload = context.get("payload", "")
                iterations = context.get("iterations", 3)
                mutated = await self.mutate_payload(payload, iterations)
                ok = bool(mutated)
                steps.append(AgentStep(1, "payload_mutation", "mutate", f"{iterations} iterations"))
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=f"Mutation: {iterations} iterations, {len(mutated)} chars"
                    if ok
                    else "Mutation failed",
                    tools_used=["mutate"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            elif obj == "cleanup":
                scope = context.get("scope", "full")
                ok = await self._cleanup_traces(scope)
                steps.append(
                    AgentStep(
                        1,
                        f"trace_cleanup_{scope}",
                        f"cleanup_{scope}",
                        "complete" if ok else "partial",
                    )
                )
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=ok,
                    output=f"Cleanup ({scope}): {'complete' if ok else 'partial'}",
                    tools_used=[f"cleanup_{scope}"],
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

            else:
                return AgentResult(
                    agent_name=self.name,
                    personality=self.personality_mode,
                    objective=objective,
                    success=False,
                    output=f"Unknown evasion objective: {objective}",
                    steps=steps,
                    duration_ms=(time.monotonic() - start) * 1000,
                )

        except Exception as exc:
            self._log.error("evader_error", objective=objective, error=str(exc))
            return AgentResult(
                agent_name=self.name,
                personality=self.personality_mode,
                objective=objective,
                success=False,
                output=str(exc),
                steps=steps,
                duration_ms=(time.monotonic() - start) * 1000,
            )

    # ── Payload Obfuscation ─────────────────────────────────────────────

    async def obfuscate_payload(self, payload_path: str) -> str:
        """Obfuscate a payload file using personality-driven techniques."""
        if not payload_path:
            self._log.warning("obfuscate_no_payload")
            return ""

        self._log.info("obfuscate_payload", path=payload_path, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return f"{payload_path}.b64"
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return f"{payload_path}.fully_obfuscated"
        else:
            return f"{payload_path}.encrypted"

    # ── AV/EDR Bypass ──────────────────────────────────────────────────

    async def bypass_av(self, method: str = "auto") -> bool:
        """Attempt to bypass AV/EDR detection on the target."""
        self._log.info("bypass_av", method=method, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return False
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            results = await self._parallel_bypass()
            return any(results.values())
        else:
            return False

    async def _parallel_bypass(self) -> dict[str, bool]:
        """Execute every evasion technique in parallel. (Stub.)"""
        results: dict[str, bool] = {}
        for category, techniques in _EVASION_TECHNIQUES.items():
            if category == "log_cleanup":
                continue
            for technique in techniques:
                results[technique.name] = await self._execute_bypass(technique)
        return results

    async def _execute_bypass(self, technique: EvasionTechnique) -> bool:
        self._log.info(
            "execute_bypass",
            name=technique.name,
            type=technique.type,
            effectiveness=technique.effectiveness,
        )
        return False

    # ── Polymorphic Mutation ────────────────────────────────────────────

    async def mutate_payload(self, payload: str, iterations: int = 3) -> str:
        """Apply polymorphic mutation to a payload string."""
        if not payload:
            self._log.warning("mutate_empty_payload")
            return ""

        self._log.info("mutate_payload", iterations=iterations, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return f"[mutated x1] {payload[:100]}..."
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return f"[mutated x{iterations}] {payload[:100]}..."
        else:
            return f"[mutated x{iterations}] {payload[:100]}..."

    # ── Forensic Cleanup ────────────────────────────────────────────────

    async def _cleanup_traces(self, scope: str = "full") -> bool:
        """Clean forensic traces of the operation."""
        self._log.info("cleanup_traces", scope=scope, personality=self.personality_mode)

        if self.personality.mode == PersonalityMode.NARCISSISM:
            return False
        elif self.personality.mode == PersonalityMode.PSYCHOPATHY:
            return await self._execute_cleanup_chain(
                [
                    "eventlog_clear",
                    "prefetch_delete",
                    "history_wipe",
                    "timestomp",
                ]
            )
        else:
            return await self._execute_cleanup_chain(["history_wipe", "eventlog_clear"])

    async def _execute_cleanup_chain(self, techniques: list[str]) -> bool:
        """Execute a chain of cleanup techniques. (Stub.)"""
        all_cleanup = {t.name: t for cat in _EVASION_TECHNIQUES.values() for t in cat}
        results: list[bool] = []
        for name in techniques:
            technique = all_cleanup.get(name)
            if technique:
                self._log.info("cleanup_step", name=name, type=technique.type)
                results.append(True)
        return any(results)
