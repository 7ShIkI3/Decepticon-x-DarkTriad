"""Moteur de plugins — découverte, chargement et cycle de vie des modules NavMAX."""

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class PluginInfo:
    """Métadonnées d'un plugin."""

    name: str
    version: str
    description: str
    author: str = ""
    category: str = ""  # scanner, proxy, exploit, osint
    dependencies: list[str] = field(default_factory=list)
    enabled: bool = True


class PluginBase:
    """Classe de base que tout plugin doit étendre."""

    info: PluginInfo

    async def on_load(self) -> None:
        """Appelé après le chargement du plugin."""

    async def on_unload(self) -> None:
        """Appelé avant le déchargement du plugin."""

    async def on_enable(self) -> None:
        """Appelé quand le plugin est activé."""

    async def on_disable(self) -> None:
        """Appelé quand le plugin est désactivé."""


class PluginManager:
    """Gestionnaire de plugins.
    Découvre, charge, active/désactive les plugins.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, PluginBase] = {}
        self._hooks: dict[str, list[Callable]] = {}

    @property
    def plugins(self) -> dict[str, PluginBase]:
        return dict(self._plugins)

    @property
    def loaded_plugins(self) -> list[str]:
        return list(self._plugins.keys())

    def discover(self, package_path: str) -> list[str]:
        """Découvre les plugins dans un package Python.
        Retourne la liste des noms de modules trouvés.
        """
        discovered: list[str] = []
        try:
            package = importlib.import_module(package_path)
            for _, mod_name, is_pkg in pkgutil.iter_modules(
                package.__path__, package.__name__ + ".",
            ):
                if not is_pkg:
                    discovered.append(mod_name)
            logger.info("plugins_découverts", count=len(discovered), path=package_path)
        except ModuleNotFoundError:
            logger.warning("package_introuvable", path=package_path)
        return discovered

    async def load(self, module_path: str) -> PluginBase | None:
        """Charge un plugin depuis un module Python.
        Cherche une classe héritant de PluginBase.
        """
        try:
            mod = importlib.import_module(module_path)
        except Exception as e:
            logger.exception("échec_import_plugin", module=module_path, erreur=str(e))
            return None

        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if obj is PluginBase or not issubclass(obj, PluginBase):
                continue
            if obj.__module__ != module_path:
                continue  # ignore les imports ré-exportés

            instance = obj()
            try:
                await instance.on_load()
            except Exception as e:
                logger.exception("échec_on_load", plugin=instance.info.name, erreur=str(e))
                return None

            self._plugins[instance.info.name] = instance
            logger.info("plugin_chargé", name=instance.info.name, version=instance.info.version)
            return instance

        logger.warning("aucune_classe_plugin", module=module_path)
        return None

    async def unload(self, name: str) -> bool:
        """Décharge un plugin par nom."""
        plugin = self._plugins.pop(name, None)
        if plugin is None:
            return False
        await plugin.on_unload()
        logger.info("plugin_déchargé", name=name)
        return True

    async def enable(self, name: str) -> bool:
        """Active un plugin."""
        plugin = self._plugins.get(name)
        if plugin is None:
            return False
        plugin.info.enabled = True
        await plugin.on_enable()
        return True

    async def disable(self, name: str) -> bool:
        """Désactive un plugin."""
        plugin = self._plugins.get(name)
        if plugin is None:
            return False
        plugin.info.enabled = False
        await plugin.on_disable()
        return True

    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """Enregistre un callback sur un hook nommé."""
        self._hooks.setdefault(hook_name, []).append(callback)

    async def trigger_hook(self, hook_name: str, *args: Any, **kwargs: Any) -> list[Any]:
        """Déclenche tous les callbacks d'un hook. Retourne leurs résultats."""
        results: list[Any] = []
        for callback in self._hooks.get(hook_name, []):
            try:
                if inspect.iscoroutinefunction(callback):
                    result = await callback(*args, **kwargs)
                else:
                    result = callback(*args, **kwargs)
                results.append(result)
            except Exception as e:
                logger.exception("erreur_hook", hook=hook_name, erreur=str(e))
        return results

    async def shutdown(self) -> None:
        """Décharge tous les plugins proprement."""
        for name in list(self._plugins.keys()):
            await self.unload(name)
        self._hooks.clear()
