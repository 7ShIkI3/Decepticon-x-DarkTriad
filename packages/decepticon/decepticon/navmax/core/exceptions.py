"""Hiérarchie d'exceptions NavMAX."""


class NavMaxError(Exception):
    """Exception de base NavMAX."""


class ConfigurationError(NavMaxError):
    """Erreur de configuration (variable manquante, valeur invalide)."""


class ValidationError(NavMaxError):
    """Validation d'entrée échouée."""


class NetworkError(NavMaxError):
    """Erreur réseau générique."""


class NetworkTimeoutError(NetworkError):
    """Timeout réseau."""


class ConnectionRefused(NetworkError):
    """Connexion refusée."""


class ScanError(NavMaxError):
    """Erreur dans le moteur de scan."""


class ExploitError(NavMaxError):
    """Erreur dans le framework d'exploit."""


class ProxyError(NavMaxError):
    """Erreur dans le proxy MITM."""


class IntruderError(ProxyError):
    """Erreur dans l'intruder."""


class ADError(NavMaxError):
    """Erreur Active Directory / LDAP."""


class ADAuthenticationError(ADError):
    """Échec d'authentification AD."""


class AIError(NavMaxError):
    """Erreur moteur IA."""


class AIProviderError(AIError):
    """Erreur fournisseur IA (réseau, quota, format)."""


class AICircuitOpenError(AIError):
    """Circuit breaker ouvert pour ce fournisseur."""


class PluginError(NavMaxError):
    """Erreur de chargement ou d'exécution de plugin."""


class ReportingError(NavMaxError):
    """Erreur lors de la génération de rapport."""


class IntegrationError(NavMaxError):
    """Erreur d'intégration externe (TheHive, MISP…)."""


class WorkspaceError(NavMaxError):
    """Erreur workspace."""
