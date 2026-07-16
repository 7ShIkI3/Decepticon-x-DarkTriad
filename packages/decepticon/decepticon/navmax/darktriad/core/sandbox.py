"""The Dark Triad — Docker Sandbox Manager.

Provides isolated Docker-based execution environments with:
- Kali Linux containers with network isolation
- Persistent tmux sessions for multi-command workflows
- Personality-aware execution parameters
- Automatic container lifecycle management
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import time
from dataclasses import dataclass
from typing import Any

from decepticon.navmax.darktriad.core.personality import (
    MACHIAVELLI,
    NARCISSUS,
    PSYCHOPATH,
    PersonalityMode,
    PersonalityProfile,
)

logger = logging.getLogger(__name__)


# ── Data Models ───────────────────────────────────────────────────────────────


@dataclass(slots=True)
class SandboxConfig:
    """Configuration for a single sandbox container."""

    image: str = "kalilinux/kali-rolling"
    network_mode: str = "sandbox-net"  # isolated | bridge | host
    memory_limit: str = "2g"
    cpu_limit: float = 2.0
    timeout: int = 3600  # max container lifetime (seconds)
    auto_cleanup: bool = True
    mount_workspace: bool = True  # mount TDT workspace directory
    privileged: bool = False


@dataclass(slots=True)
class SandboxStatus:
    """Snapshot of a sandbox container's runtime state."""

    running: bool
    container_id: str | None
    image: str
    uptime_seconds: float


@dataclass(slots=True)
class ExecutionResult:
    """Result of a command executed inside the sandbox."""

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    timed_out: bool


# ── Network Manager ───────────────────────────────────────────────────────────


class NetworkManager:
    """Manages Docker networks for sandbox isolation."""

    def __init__(self, docker_client: Any | None = None) -> None:
        self._docker = docker_client  # TODO: inject real docker.DockerClient

    def create_network(self, name: str) -> str:
        """Create an isolated Docker network. Returns network ID."""
        # TODO: implement via docker_client.networks.create()
        logger.info("TODO: create Docker network '%s'", name)
        return f"network-{name}"

    def connect_container(self, container_id: str, network: str) -> None:
        """Connect a running container to an existing network."""
        # TODO: implement via docker_client.networks.get(network).connect(container_id)
        logger.info("TODO: connect container %s to network %s", container_id, network)

    def remove_network(self, name: str) -> None:
        """Remove a Docker network."""
        # TODO: implement via docker_client.networks.get(name).remove()
        logger.info("TODO: remove network '%s'", name)


# ── Tmux Session Manager ─────────────────────────────────────────────────────


class TmuxSessionManager:
    """Manages persistent tmux sessions inside a sandbox container.

    Each session maps to a named tmux session running inside the container,
    allowing multi-step interactive workflows.
    """

    def __init__(self, container_exec_func: Any) -> None:
        """Initialize with a callable that executes commands in the container.

        Args:
            container_exec_func: Async callable(str) -> ExecutionResult
        """
        self._exec = container_exec_func
        self._sessions: dict[str, str] = {}

    async def create_session(self, name: str) -> str:
        """Create a named tmux session inside the container.

        Returns the session name on success.
        """
        result = await self._exec(
            "tmux new-session -d -s "
            f"{name} 2>&1 || tmux start-server && tmux new-session -d -s {name}"
        )
        if result.exit_code != 0:
            raise RuntimeError(f"Failed to create tmux session '{name}': {result.stderr}")
        self._sessions[name] = name
        logger.debug("Created tmux session '%s'", name)
        return name

    async def send_command(self, session: str, command: str) -> None:
        """Send a command string to the tmux session."""
        escaped = command.replace("'", "'\\''")
        result = await self._exec(f"tmux send-keys -t {session} '{escaped}' Enter 2>&1")
        if result.exit_code != 0:
            raise RuntimeError(
                f"Failed to send command to tmux session '{session}': {result.stderr}"
            )

    async def capture_output(self, session: str) -> str:
        """Capture the current visible output of the tmux session."""
        result = await self._exec(f"tmux capture-pane -t {session} -p -S - 2>&1")
        if result.exit_code != 0:
            raise RuntimeError(
                f"Failed to capture output from tmux session '{session}': {result.stderr}"
            )
        return result.stdout

    async def wait_for_prompt(self, session: str, prompt_pattern: str, timeout: int = 30) -> bool:
        """Wait until the prompt pattern appears in session output.

        Args:
            session: Tmux session name.
            prompt_pattern: Regex pattern to match in output.
            timeout: Maximum wait time in seconds.

        Returns:
            True if the pattern was found, False on timeout.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            output = await self.capture_output(session)
            if re.search(prompt_pattern, output, re.MULTILINE):
                return True
            await asyncio.sleep(0.5)
        logger.warning(
            "Timed out waiting for prompt pattern '%s' in session '%s'",
            prompt_pattern,
            session,
        )
        return False

    async def kill_session(self, session: str) -> None:
        """Kill a tmux session."""
        result = await self._exec(f"tmux kill-session -t {session} 2>&1")
        self._sessions.pop(session, None)
        if result.exit_code != 0 and "no server running" not in result.stderr:
            logger.warning("Failed to kill tmux session '%s': %s", session, result.stderr)


# ── Sandbox Manager ───────────────────────────────────────────────────────────


class SandboxError(Exception):
    """Base exception for sandbox operations."""


class DockerNotInstalledError(SandboxError):
    """Raised when Docker is not available on the host."""


class SandboxManager:
    """Async Docker sandbox manager with tmux, network isolation, and personality integration.

    Manages the full lifecycle of a Kali Linux container used for safe
    execution of offensive security tools with personality-aware parameters.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()
        self._container_id: str | None = None
        self._started_at: float | None = None
        self._docker: Any = None  # TODO: assign real docker.DockerClient
        self.network = NetworkManager()
        self.tmux: TmuxSessionManager | None = None

    # ── Container Lifecycle ───────────────────────────────────────────────

    async def start(self) -> SandboxStatus:
        """Start the sandbox container and verify it's ready.

        Raises:
            DockerNotInstalledError: If Docker is not available.
            SandboxError: If the container fails to start.

        Returns:
            SandboxStatus with the running container details.
        """
        docker_available = await self._check_docker()
        if not docker_available:
            raise DockerNotInstalledError(
                "Docker is not installed or not running on this host. "
                "Install Docker Desktop or Docker Engine to use sandbox features."
            )

        # ── Pull image if needed ──────────────────────────────────────────
        if not await self._image_exists(self.config.image):
            logger.info("Pulling Docker image '%s'...", self.config.image)
            pull_ok = await self._pull_image(self.config.image)
            if not pull_ok:
                raise SandboxError(f"Failed to pull Docker image '{self.config.image}'")

        # ── Create container ──────────────────────────────────────────────
        self._container_id = await self._create_container()
        if not self._container_id:
            raise SandboxError("Failed to create sandbox container")

        logger.info("Starting sandbox container %s", self._container_id)
        await self._start_container(self._container_id)
        ready = await self._wait_ready(self._container_id, timeout=60)
        if not ready:
            raise SandboxError("Container started but not ready within 60s")

        self._started_at = time.monotonic()

        # ── Install tmux inside container ─────────────────────────────────
        install_result = await self._exec_internal(
            "apt-get update -qq && apt-get install -y -qq tmux 2>&1 | tail -5"
        )
        if install_result.exit_code != 0:
            logger.warning("tmux install reported issues: %s", install_result.stderr)
        else:
            logger.info("tmux installed inside sandbox")

        # ── Initialize tmux manager ───────────────────────────────────────
        self.tmux = TmuxSessionManager(self._exec_internal)

        status = await self.status()
        logger.info("Sandbox ready: container=%s image=%s", status.container_id, status.image)
        return status

    async def stop(self) -> None:
        """Stop and remove the sandbox container."""
        if not self._container_id:
            logger.debug("No container to stop")
            return

        container_id = self._container_id

        # Kill any remaining tmux sessions first
        if self.tmux:
            for session in list(self.tmux._sessions):
                try:
                    await self.tmux.kill_session(session)
                except Exception:
                    logger.debug("Failed to kill tmux session '%s': ignoring", session)

        logger.info("Stopping sandbox container %s", container_id)
        stop_ok = await self._exec_docker_cli(f"docker stop --time=10 {container_id} 2>&1")
        if stop_ok.exit_code != 0:
            logger.warning("docker stop warning: %s", stop_ok.stderr)

        if self.config.auto_cleanup:
            rm_ok = await self._exec_docker_cli(f"docker rm -f {container_id} 2>&1")
            if rm_ok.exit_code != 0:
                logger.warning("docker rm warning: %s", rm_ok.stderr)

        self._container_id = None
        self._started_at = None
        self.tmux = None

    async def status(self) -> SandboxStatus:
        """Get current sandbox runtime status."""
        if not self._container_id:
            return SandboxStatus(
                running=False,
                container_id=None,
                image=self.config.image,
                uptime_seconds=0.0,
            )

        uptime = 0.0
        if self._started_at:
            uptime = time.monotonic() - self._started_at

        # Verify container is still running
        inspect_result = await self._exec_docker_cli(
            f"docker inspect --format='{{{{.State.Running}}}}' {self._container_id} 2>&1"
        )
        running = inspect_result.exit_code == 0 and inspect_result.stdout.strip() == "true"

        return SandboxStatus(
            running=running,
            container_id=self._container_id,
            image=self.config.image,
            uptime_seconds=uptime,
        )

    # ── Container Context Managers ────────────────────────────────────────

    async def __aenter__(self) -> SandboxManager:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        if self.config.auto_cleanup:
            await self.stop()

    def __del__(self) -> None:
        """Fallback cleanup if context manager wasn't used."""
        if self._container_id and self.config.auto_cleanup:
            logger.warning(
                "SandboxManager.__del__ cleaning up container %s "
                "(use async context manager for deterministic cleanup)",
                self._container_id,
            )
            # Fire-and-forget since __del__ can't be async
            try:
                import subprocess

                subprocess.run(
                    ["docker", "rm", "-f", self._container_id],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                logger.warning(
                    "Failed to force-remove container %s in __del__",
                    self._container_id,
                )

    # ── Command Execution ─────────────────────────────────────────────────

    async def execute(self, command: str, timeout: int = 60) -> ExecutionResult:
        """Execute a single command inside the sandbox container.

        Args:
            command: Shell command to execute.
            timeout: Max execution time in seconds.

        Returns:
            ExecutionResult with stdout, stderr, exit code, and timing.
        """
        if not self._container_id:
            raise SandboxError("Sandbox not started. Call start() first.")

        return await self._exec_internal(command, timeout)

    async def execute_interactive(self, commands: list[str], timeout: int = 300) -> ExecutionResult:
        """Execute multiple commands sequentially in a persistent tmux session.

        Creates a dedicated tmux session, sends each command, waits for
        prompt between commands, then captures all output.

        Args:
            commands: List of shell commands to run sequentially.
            timeout: Max total execution time in seconds.

        Returns:
            Combined ExecutionResult across all commands.
        """
        if not self.tmux:
            raise SandboxError("Tmux not available. Ensure tmux is installed in container.")

        session_name = f"interactive-{int(time.time())}"
        await self.tmux.create_session(session_name)

        all_output: list[str] = []
        start = time.monotonic()
        timed_out = False

        try:
            for i, cmd in enumerate(commands):
                elapsed = time.monotonic() - start
                if elapsed >= timeout:
                    timed_out = True
                    break

                remaining = timeout - elapsed
                cmd_timeout = min(remaining, remaining / max(len(commands) - i, 1))

                await self.tmux.send_command(session_name, cmd)

                # Wait for shell prompt after each command
                found = await self.tmux.wait_for_prompt(
                    session_name,
                    r"[#$] ",
                    timeout=int(min(cmd_timeout, 30)),
                )
                if not found:
                    logger.warning("Prompt not detected after command %d, continuing anyway", i)

            output = await self.tmux.capture_output(session_name)
            all_output.append(output)
        finally:
            await self.tmux.kill_session(session_name)

        duration_ms = (time.monotonic() - start) * 1000

        return ExecutionResult(
            stdout="\n".join(all_output),
            stderr="",
            exit_code=0,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )

    # ── File Operations ───────────────────────────────────────────────────

    async def write_file(self, path: str, content: str) -> None:
        """Write content to a file inside the container.

        Uses base64 encoding to avoid shell escaping issues.
        """
        import base64

        encoded = base64.b64encode(content.encode()).decode()
        result = await self._exec_internal(f"echo '{encoded}' | base64 -d > '{path}'")
        if result.exit_code != 0:
            raise SandboxError(f"Failed to write file '{path}': {result.stderr}")

    async def read_file(self, path: str) -> str:
        """Read a file from inside the container.

        Uses base64 encoding to preserve content faithfully.
        """
        import base64

        result = await self._exec_internal(f"base64 '{path}' 2>&1")
        if result.exit_code != 0:
            raise SandboxError(f"Failed to read file '{path}': {result.stderr}")
        return base64.b64decode(result.stdout.strip()).decode()

    # ── Tool Installation ─────────────────────────────────────────────────

    async def install_tool(self, tool: str) -> bool:
        """Install a tool inside the container via apt-get.

        Args:
            tool: Package name to install.

        Returns:
            True if installation succeeded, False otherwise.
        """
        result = await self._exec_internal(
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {tool} 2>&1",
            timeout=120,
        )
        if result.exit_code != 0:
            logger.error("Failed to install tool '%s': %s", tool, result.stderr)
            return False
        return True

    # ── Personality-Integrated Execution ──────────────────────────────────

    async def execute_with_personality(
        self, commands: list[str], personality: str | PersonalityProfile
    ) -> ExecutionResult:
        """Execute commands with personality-adapted parameters.

        Each personality trait modifies execution behavior:
        - NARCISSISM :   Fast timeout (30s), no retry, optimistic
        - PSYCHOPATHY :  Long timeout (600s), infinite retry, max parallelism
        - MACHIAVELLIANISM: Patient timeout (300s), step verification, cleanup

        Args:
            commands: Commands to execute sequentially.
            personality: Either a PersonalityProfile or a string name
                        ("narcissism", "psychopathy", "machiavellianism").

        Returns:
            ExecutionResult with personality-adapted behavior.
        """
        if isinstance(personality, str):
            profile = self._personality_from_name(personality)
        else:
            profile = personality

        params = self._personality_params(profile)

        if profile.mode == PersonalityMode.NARCISSISM:
            return await self._execute_narcissism(commands, params)
        elif profile.mode == PersonalityMode.PSYCHOPATHY:
            return await self._execute_psychopathy(commands, params)
        elif profile.mode == PersonalityMode.MACHIAVELLIANISM:
            return await self._execute_machiavellianism(commands, params)
        else:
            # Fallback: execute_interactive with profile timeout
            return await self.execute_interactive(commands, timeout=params["timeout"])

    def _personality_from_name(self, name: str) -> PersonalityProfile:
        """Resolve a personality name to a profile."""
        mapping = {
            "narcissism": NARCISSUS,
            "psychopathy": PSYCHOPATH,
            "machiavellianism": MACHIAVELLI,
            "narcissus": NARCISSUS,
            "psychopath": PSYCHOPATH,
            "machiavelli": MACHIAVELLI,
        }
        normalized = name.strip().lower()
        profile = mapping.get(normalized)
        if not profile:
            raise ValueError(f"Unknown personality '{name}'. Available: {', '.join(mapping)}")
        return profile

    @staticmethod
    def _personality_params(profile: PersonalityProfile) -> dict[str, Any]:
        """Derive execution parameters from a personality profile."""
        base_timeout = 60
        timeout = int(base_timeout * profile.timeout_modifier)

        return {
            "timeout": max(timeout, 10),
            "retry_count": profile.retry_count,
            "parallelism": profile.parallelism,
            "patience": profile.patience,
            "persistence": profile.persistence,
        }

    async def _execute_narcissism(
        self, commands: list[str], params: dict[str, Any]
    ) -> ExecutionResult:
        """NARCISSISM: Fast, aggressive, no retry, optimistic."""
        timeout = min(params["timeout"], 30)  # Narcissus is impatient

        start = time.monotonic()
        # Single pass — no retries, just raw speed
        if commands:
            # Use first command only — narcissist doesn't plan ahead
            result = await self._exec_internal(commands[0], timeout=timeout)
        else:
            result = ExecutionResult(
                stdout="", stderr="", exit_code=0, duration_ms=0.0, timed_out=False
            )

        duration_ms = (time.monotonic() - start) * 1000
        return ExecutionResult(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            duration_ms=duration_ms,
            timed_out=result.timed_out,
        )

    async def _execute_psychopathy(
        self, commands: list[str], params: dict[str, Any]
    ) -> ExecutionResult:
        """PSYCHOPATHY: Long timeout, infinite retry, max parallelism."""
        timeout = max(params["timeout"], 600)
        max_retries = min(params["retry_count"], 999)

        start = time.monotonic()
        last_result: ExecutionResult | None = None

        for attempt in range(max_retries):
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                break

            remaining = timeout - elapsed
            per_cmd_timeout = max(int(remaining / max(len(commands), 1)), 5)

            for cmd in commands:
                last_result = await self._exec_internal(cmd, timeout=per_cmd_timeout)

            if last_result and last_result.exit_code == 0:
                break

            if attempt < max_retries - 1:
                await asyncio.sleep(1)

        if last_result is None:
            last_result = ExecutionResult(
                stdout="", stderr="", exit_code=-1, duration_ms=0.0, timed_out=False
            )

        duration_ms = (time.monotonic() - start) * 1000
        return ExecutionResult(
            stdout=last_result.stdout,
            stderr=last_result.stderr,
            exit_code=last_result.exit_code,
            duration_ms=duration_ms,
            timed_out=duration_ms >= timeout * 1000,
        )

    async def _execute_machiavellianism(
        self, commands: list[str], params: dict[str, Any]
    ) -> ExecutionResult:
        """MACHIAVELLIANISM: Patient, verifies each step, cleans up after."""
        timeout = min(params["timeout"], 300)

        start = time.monotonic()
        all_stdout: list[str] = []
        all_stderr: list[str] = []
        timed_out = False
        final_exit_code = 0

        for i, cmd in enumerate(commands):
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                timed_out = True
                break

            remaining = timeout - elapsed
            cmd_timeout = int(remaining / max(len(commands) - i, 1))

            result = await self._exec_internal(cmd, timeout=cmd_timeout)
            all_stdout.append(result.stdout)
            all_stderr.append(result.stderr)

            # Verify step — Machiavelli checks every move
            if result.exit_code != 0:
                logger.warning(
                    "Machiavellian step %d failed (exit=%d): %s",
                    i,
                    result.exit_code,
                    result.stderr[:200],
                )
                final_exit_code = result.exit_code
                # Strategically stop on failure
                break

            final_exit_code = result.exit_code

        # Cleanup: wipe sensitive artifacts if any were created
        try:
            await self._exec_internal(
                "history -c 2>/dev/null; rm -f /tmp/*.py /tmp/*.sh /tmp/*.elf 2>/dev/null",
                timeout=10,
            )
        except Exception:
            logger.warning("Cleanup in Machiavellian execution failed: ignoring", exc_info=True)

        duration_ms = (time.monotonic() - start) * 1000
        return ExecutionResult(
            stdout="\n".join(all_stdout),
            stderr="\n".join(all_stderr),
            exit_code=final_exit_code,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )

    # ── Internal Helpers ──────────────────────────────────────────────────

    async def _check_docker(self) -> bool:
        """Check if Docker CLI is available."""
        result = await self._exec_docker_cli("docker info --format='{{.ServerVersion}}' 2>&1")
        return result.exit_code == 0 and bool(result.stdout.strip())

    async def _image_exists(self, image: str) -> bool:
        """Check if a Docker image is already pulled locally."""
        result = await self._exec_docker_cli(
            f"docker image inspect '{image}' --format='{{{{.Id}}}}' 2>&1"
        )
        return result.exit_code == 0 and bool(result.stdout.strip())

    async def _pull_image(self, image: str) -> bool:
        """Pull a Docker image. Returns True on success."""
        result = await self._exec_docker_cli(
            f"docker pull '{image}' 2>&1",
            timeout=300,
        )
        return result.exit_code == 0

    async def _create_container(self) -> str | None:
        """Create the sandbox container. Returns container ID or None."""
        # Build docker run args from config
        args = [
            "docker",
            "create",
            "--network",
            self.config.network_mode,
            "--memory",
            self.config.memory_limit,
            "--cpus",
            str(self.config.cpu_limit),
            "--name",
            f"tdt-sandbox-{int(time.time())}",
        ]

        if self.config.privileged:
            args.append("--privileged")

        # Mount workspace if requested
        if self.config.mount_workspace:
            home = os.path.expanduser("~")
            workspace = os.path.join(home, "dark-triad")
            if os.path.isdir(workspace):
                args.extend(["-v", f"{workspace}:/workspace"])

        # Interactive + init process
        args.extend(["-it", "--init"])

        # Entry command: sleep until killed (keepalive)
        args.append(self.config.image)
        args.append("sleep")
        args.append(str(self.config.timeout))

        result = await self._exec_docker_cli(" ".join(args), timeout=30)
        if result.exit_code != 0:
            logger.error("Failed to create container: %s", result.stderr)
            return None

        container_id = result.stdout.strip()
        return container_id if container_id else None

    async def _start_container(self, container_id: str) -> None:
        """Start a created container."""
        result = await self._exec_docker_cli(f"docker start {container_id} 2>&1")
        if result.exit_code != 0:
            raise SandboxError(f"Failed to start container: {result.stderr}")

    async def _wait_ready(self, container_id: str, timeout: int = 60) -> bool:
        """Wait for container to be ready for commands.

        Checks by running a simple echo command inside the container.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = await self._exec_internal("echo ready_ok", timeout=10)
            if result.exit_code == 0 and "ready_ok" in result.stdout:
                return True
            await asyncio.sleep(1)
        return False

    async def _exec_internal(self, command: str, timeout: int = 60) -> ExecutionResult:
        """Execute a command inside the container using docker exec.

        Uses subprocess to run 'docker exec' — no shell=True (command
        is passed as a string but docker exec -d runs it in a real shell
        inside the container).
        """
        assert self._container_id, "Container not running"

        start = time.monotonic()

        try:
            result = await self._exec_docker_cli(
                f"docker exec -i {self._container_id} sh -c {self._quote(command)}",
                timeout=timeout,
            )
        except TimeoutError:
            duration_ms = (time.monotonic() - start) * 1000
            # Kill potentially stuck command
            await self._exec_docker_cli(
                f"docker exec {self._container_id} kill -9 1 2>/dev/null",
                timeout=5,
            )
            return ExecutionResult(
                stdout="",
                stderr="Command timed out",
                exit_code=-1,
                duration_ms=duration_ms,
                timed_out=True,
            )

        duration_ms = (time.monotonic() - start) * 1000
        return ExecutionResult(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code,
            duration_ms=duration_ms,
            timed_out=duration_ms >= timeout * 1000,
        )

    async def _exec_docker_cli(self, cmd: str, timeout: int = 60) -> ExecutionResult:
        """Execute a docker CLI command via subprocess.

        This is a stub that wraps subprocess for non-Docker environments.
        TODO: Replace with real async subprocess or docker-py library.
        """
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *shlex.split(cmd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                duration_ms = (time.monotonic() - start) * 1000
                return ExecutionResult(
                    stdout="",
                    stderr=f"Command timed out after {timeout}s",
                    exit_code=-1,
                    duration_ms=duration_ms,
                    timed_out=True,
                )

            duration_ms = (time.monotonic() - start) * 1000
            return ExecutionResult(
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                duration_ms=duration_ms,
                timed_out=False,
            )
        except FileNotFoundError:
            duration_ms = (time.monotonic() - start) * 1000
            return ExecutionResult(
                stdout="",
                stderr="docker: command not found",
                exit_code=-1,
                duration_ms=duration_ms,
                timed_out=False,
            )

    @staticmethod
    def _quote(cmd: str) -> str:
        """Shell-quote a command string for passing via docker exec."""
        escaped = cmd.replace("'", "'\\''")
        return f"'{escaped}'"


# ── Convenience Factory ───────────────────────────────────────────────────────


def create_sandbox(
    image: str = "kalilinux/kali-rolling",
    network_mode: str = "sandbox-net",
    memory_limit: str = "2g",
    cpu_limit: float = 2.0,
    timeout: int = 3600,
    auto_cleanup: bool = True,
    privileged: bool = False,
) -> SandboxManager:
    """Create a pre-configured SandboxManager with default Kali sandbox settings.

    Returns:
        A SandboxManager instance (call .start() to launch the container).
    """
    config = SandboxConfig(
        image=image,
        network_mode=network_mode,
        memory_limit=memory_limit,
        cpu_limit=cpu_limit,
        timeout=timeout,
        auto_cleanup=auto_cleanup,
        privileged=privileged,
    )
    return SandboxManager(config)
