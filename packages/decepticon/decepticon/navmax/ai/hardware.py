"""Détection hardware cross-platform (Windows, Linux, macOS).

Détecte RAM, GPU, CPU pour auto-configurer les tiers de modèles disponibles.
"""

import os
import platform
import subprocess
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HardwareProfile:
    """Profil hardware de la machine."""

    os_name: str
    ram_total_gb: float
    gpu_name: str | None = None
    gpu_vram_gb: float | None = None
    cpu_cores: int = 4
    cpu_name: str = ""

    @property
    def can_run_light(self) -> bool:
        """Un modèle Light (1-3B) peut tourner ?"""
        return self.ram_total_gb >= 4

    @property
    def can_run_medium(self) -> bool:
        """Un modèle Medium (7-8B) peut tourner ?"""
        return self.ram_total_gb >= 8

    @property
    def can_run_heavy(self) -> bool:
        """Un modèle Heavy (70B+) peut tourner ?"""
        return self.ram_total_gb >= 32 and (self.gpu_vram_gb is not None and self.gpu_vram_gb >= 16)

    @property
    def max_local_tier(self) -> str | None:
        """Tier maximum que cette machine peut faire tourner en local."""
        if self.can_run_heavy:
            return "heavy"
        if self.can_run_medium:
            return "medium"
        if self.can_run_light:
            return "light"
        return None

    @property
    def has_gpu(self) -> bool:
        return self.gpu_name is not None

    @property
    def is_apple_silicon(self) -> bool:
        return self.os_name == "Darwin" and platform.processor() == "arm"


def detect_hardware() -> HardwareProfile:
    """Auto-détection des ressources système."""
    system = platform.system()
    ram = _detect_ram(system)
    gpu_name, gpu_vram = _detect_gpu(system)
    cpu_cores = os.cpu_count() or 4
    cpu_name = platform.processor() or ""

    return HardwareProfile(
        os_name=system,
        ram_total_gb=ram,
        gpu_name=gpu_name,
        gpu_vram_gb=gpu_vram,
        cpu_cores=cpu_cores,
        cpu_name=cpu_name,
    )


def _detect_ram(system: str) -> float:
    """Détecte la RAM totale en GB."""
    if system == "Windows":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            mem = MEMORYSTATUSEX()
            mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
            return round(mem.ullTotalPhys / (1024**3), 1)
        except Exception as _e:
            logger.warning("windows_ram_detection_failed", error=str(_e))
            return 8.0  # fallback

    elif system == "Linux":
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if "MemTotal" in line:
                        kb = int(line.split()[1])
                        return round(kb / (1024**2), 1)
        except (FileNotFoundError, ValueError, OSError) as _e:
            logger.warning("cannot_read_meminfo", error=str(_e))

    elif system == "Darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return round(int(result.stdout.strip()) / (1024**3), 1)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError) as _e:
            logger.warning("sysctl_memsize_failed", error=str(_e))

    return 8.0  # fallback


def _detect_gpu(system: str) -> tuple[str | None, float | None]:
    """Détecte GPU name + VRAM. Retourne (name, vram_gb)."""
    # NVIDIA (Windows + Linux)
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split(",")
            if len(parts) >= 2:
                name = parts[0].strip()
                vram_str = parts[1].strip().replace(" MiB", "")
                vram_gb = round(int(vram_str) / 1024, 1)
                return name, vram_gb
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as _e:
        logger.debug("nvidia_smi_not_available", error=str(_e))

    # Apple Silicon (mémoire unifiée = RAM)
    if system == "Darwin" and platform.processor() == "arm":
        return "Apple Silicon (Unified)", None

    return None, None
