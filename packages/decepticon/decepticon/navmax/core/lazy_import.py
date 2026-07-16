"""Utilitaire de lazy import — réduit le temps de démarrage en différant
les imports lourds (aiohttp, networkx, scapy, impacket, etc.) jusqu'à
leur première utilisation réelle.

Usage:
    from decepticon.navmax.core.lazy_import import LazyImporter

    aiohttp = LazyImporter('aiohttp')           # différé
    async with aiohttp.ClientSession() as s: ... # chargé ici

    networkx = LazyImporter('networkx')
    G = networkx.Graph()

L'import n'a lieu qu'au premier accès à un attribut.
"""

import importlib
from types import ModuleType
from typing import Any


class LazyImporter(ModuleType):
    """Proxy d'un module — l'import réel est différé au premier accès.

    Utilise __class__ pour se faire passer pour un module Python.
    Le nom du module importé est stocké dans __path__.
    """

    def __init__(self, module_name: str) -> None:
        super().__init__(module_name)
        self._module_name = module_name
        self._module: ModuleType | None = None

    def _load(self) -> ModuleType:
        if self._module is None:
            self._module = importlib.import_module(self._module_name)
        return self._module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._load(), name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        module = self._load()
        if isinstance(module, ModuleType):
            return module(*args, **kwargs)  # type: ignore[operator]
        return module(*args, **kwargs)


# ── Modules lourds en lazy import par défaut ─────────────────────
# Ceux-ci sont placés ici pour être utilisés dans les modules qui
# ont besoin d'eux sans les importer au top-level.

# aiohttp est particulièrement lourd (~90ms d'import)
# httpx est plus léger mais reste non négligeable

__all__ = ["LazyImporter"]
