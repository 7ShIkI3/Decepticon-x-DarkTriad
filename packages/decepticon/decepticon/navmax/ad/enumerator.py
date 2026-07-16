"""AD Enumerator — énumération massive Active Directory.

Transforme les résultats bruts LDAP en objets structurés (ADUser, ADGroup, etc.)
et construit une DomainMap exploitable pour l'analyse.

Usage:
    connector = ADConnector(config)
    await connector.connect()
    enumerator = ADEnumerator(connector)
    domain_map = await enumerator.enumerate_all()
    print(f"Users: {len(domain_map.users)}, Groups: {len(domain_map.groups)}")
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime

import structlog

from .connector import (
    ADGPO,
    ADOU,
    FUNCTIONAL_LEVEL_MAP,
    TRUST_ATTR_NON_TRANSITIVE,
    TRUST_ATTR_WITHIN_FOREST,
    TRUST_DIRECTION_MAP,
    TRUST_TYPE_MAP,
    ADComputer,
    ADConnector,
    ADDomain,
    ADGroup,
    ADTrust,
    ADUser,
)

logger = structlog.get_logger(__name__)


# ── Modèle de résultat ─────────────────────────────────────────


@dataclass
class DomainMap:
    """Cartographie complète d'un domaine Active Directory.

    Contient tous les objets énumérés et les relations entre eux.
    Sert de source unique pour le graphe d'attaque (trust_graph).
    """

    domain: ADDomain
    users: list[ADUser] = field(default_factory=list)
    groups: list[ADGroup] = field(default_factory=list)
    computers: list[ADComputer] = field(default_factory=list)
    ous: list[ADOU] = field(default_factory=list)
    gpos: list[ADGPO] = field(default_factory=list)
    trusts: list[ADTrust] = field(default_factory=list)
    # Index pour lookup rapide
    _users_by_dn: dict[str, ADUser] = field(default_factory=dict, repr=False)
    _groups_by_dn: dict[str, ADGroup] = field(default_factory=dict, repr=False)
    _computers_by_dn: dict[str, ADComputer] = field(default_factory=dict, repr=False)
    _groups_by_sam: dict[str, ADGroup] = field(default_factory=dict, repr=False)
    # Statistiques
    enumeration_time: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def total_objects(self) -> int:
        return (
            len(self.users)
            + len(self.groups)
            + len(self.computers)
            + len(self.ous)
            + len(self.gpos)
            + len(self.trusts)
        )

    @property
    def privileged_users(self) -> list[ADUser]:
        """Utilisateurs avec adminCount=1 (protégés par SDProp)."""
        return [u for u in self.users if u.is_admin]

    @property
    def kerberoastable_users(self) -> list[ADUser]:
        """Utilisateurs avec SPNs (vulnérables au Kerberoasting)."""
        return [u for u in self.users if u.is_kerberoastable]

    @property
    def asrep_roastable_users(self) -> list[ADUser]:
        """Utilisateurs sans pré-authentification Kerberos."""
        return [u for u in self.users if u.is_asrep_roastable]

    @property
    def unconstrained_delegation_computers(self) -> list[ADComputer]:
        """Machines avec délégation non contrainte."""
        return [c for c in self.computers if (c.user_account_control & 0x80000) != 0]

    @property
    def domain_controllers(self) -> list[ADComputer]:
        """Contrôleurs de domaine."""
        return [c for c in self.computers if c.is_domain_controller]

    @property
    def disabled_users(self) -> list[ADUser]:
        """Utilisateurs désactivés."""
        return [u for u in self.users if not u.is_enabled]

    @property
    def users_without_password_expiry(self) -> list[ADUser]:
        """Utilisateurs avec mot de passe qui n'expire jamais."""
        return [u for u in self.users if (u.user_account_control & 0x10000) != 0]

    @property
    def domain_admins(self) -> list[ADUser]:
        """Utilisateurs membres du groupe Domain Admins."""
        return self._members_of_group("Domain Admins")

    @property
    def enterprise_admins(self) -> list[ADUser]:
        """Utilisateurs membres du groupe Enterprise Admins."""
        return self._members_of_group("Enterprise Admins")

    def _members_of_group(self, group_name: str) -> list[ADUser]:
        """Retourne les membres directs d'un groupe (par nom SAM)."""
        group = self._groups_by_sam.get(group_name)
        if not group:
            return []
        members: list[ADUser] = []
        seen_dns: set[str] = set()
        for member_dn in group.members:
            user = self._users_by_dn.get(member_dn)
            if user and member_dn not in seen_dns:
                members.append(user)
                seen_dns.add(member_dn)
            subgroup = self._groups_by_dn.get(member_dn)
            if subgroup:
                sub_members = self._collect_nested_members(
                    subgroup,
                    visited=set(),
                    max_depth=3,
                )
                for u in sub_members:
                    if u.dn not in seen_dns:
                        members.append(u)
                        seen_dns.add(u.dn)
        return members

    def _collect_nested_members(
        self,
        group: ADGroup,
        visited: set,
        max_depth: int,
        depth: int = 0,
    ) -> list[ADUser]:
        """Récupère récursivement les membres d'un groupe (avec limites)."""
        if depth >= max_depth or group.dn in visited:
            return []
        visited.add(group.dn)
        result: list[ADUser] = []
        for member_dn in group.members:
            user = self._users_by_dn.get(member_dn)
            if user:
                result.append(user)
            subgroup = self._groups_by_dn.get(member_dn)
            if subgroup:
                result.extend(
                    self._collect_nested_members(
                        subgroup,
                        visited,
                        max_depth,
                        depth + 1,
                    ),
                )
        return result

    def summary(self) -> str:
        """Résumé textuel du domaine."""
        lines = [
            f"=== Domain: {self.domain.name} ({self.domain.netbios_name}) ===",
            f"  SID: {self.domain.sid}",
            f"  Functional Level: {self.domain.functional_level}",
            f"  Forest: {self.domain.forest}",
            f"  DCs: {len(self.domain_controllers)} ({', '.join(c.dns_hostname for c in self.domain_controllers[:3])})",
            "",
            f"  Users: {len(self.users)}",
            f"    Enabled: {len(self.users) - len(self.disabled_users)}",
            f"    Disabled: {len(self.disabled_users)}",
            f"    Privileged (adminCount=1): {len(self.privileged_users)}",
            f"    Kerberoastable: {len(self.kerberoastable_users)}",
            f"    AS-REP Roastable: {len(self.asrep_roastable_users)}",
            f"    Password never expires: {len(self.users_without_password_expiry)}",
            f"    Domain Admins (direct+nested): {len(self.domain_admins)}",
            "",
            f"  Groups: {len(self.groups)}",
            f"    Security groups: {len([g for g in self.groups if g.is_security_group])}",
            f"    Admin groups (adminCount=1): {len([g for g in self.groups if g.admin_count == 1])}",
            "",
            f"  Computers: {len(self.computers)}",
            f"    DCs: {len(self.domain_controllers)}",
            f"    Unconstrained delegation: {len(self.unconstrained_delegation_computers)}",
            "",
            f"  OUs: {len(self.ous)}",
            f"  GPOs: {len(self.gpos)}",
            f"  Trusts: {len(self.trusts)}",
            "",
            f"  Enumeration time: {self.enumeration_time:.1f}s",
            f"  Errors: {len(self.errors)}",
        ]
        return "\n".join(lines)


@dataclass
class EnumerationResult:
    """Résultat d'une énumération AD."""

    domain: str
    domain_map: DomainMap
    objects_collected: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


# ── Enumerator ─────────────────────────────────────────────────


class ADEnumerator:
    """Énumérateur Active Directory.

    Utilise un ADConnector pour parcourir le domaine et collecter
    tous les objets dans une DomainMap structurée.

    Usage:
        enumerator = ADEnumerator(connector, config)
        domain_map = await enumerator.enumerate_all()
        print(domain_map.summary())
    """

    def __init__(
        self,
        connector: ADConnector,
        parallel: bool = True,
        max_objects: int = 50000,
    ) -> None:
        self.connector = connector
        self.parallel = parallel  # Énumération parallèle par type
        self.max_objects = max_objects  # Limite totale d'objets
        self._errors: list[str] = []

    async def enumerate_all(self) -> DomainMap:
        """Énumération complète du domaine.

        Récupère : info domaine, users, groups, computers, OUs, GPOs, trusts.

        Returns:
            DomainMap avec tous les objets et leurs relations.

        """
        import time

        t_start = time.monotonic()

        logger.info("enumeration_started", domain=self.connector.config.domain)
        self._errors = []

        # ── Étape 1: Infos du domaine ───────────────────────────
        domain = await self._enumerate_domain_info()

        # ── Étape 2: Énumération parallèle par type d'objet ─────
        if self.parallel:
            (
                users_raw,
                groups_raw,
                computers_raw,
                ous_raw,
                gpos_raw,
                trusts_raw,
            ) = await asyncio.gather(
                self._safe_enumerate("users", self.connector.search_users()),
                self._safe_enumerate("groups", self.connector.search_groups()),
                self._safe_enumerate("computers", self.connector.search_computers()),
                self._safe_enumerate("ous", self.connector.search_ous()),
                self._safe_enumerate("gpos", self.connector.search_gpos()),
                self._safe_enumerate("trusts", self.connector.search_trusts()),
            )
        else:
            users_raw = await self._safe_enumerate(
                "users",
                self.connector.search_users(),
            )
            groups_raw = await self._safe_enumerate(
                "groups",
                self.connector.search_groups(),
            )
            computers_raw = await self._safe_enumerate(
                "computers",
                self.connector.search_computers(),
            )
            ous_raw = await self._safe_enumerate(
                "ous",
                self.connector.search_ous(),
            )
            gpos_raw = await self._safe_enumerate(
                "gpos",
                self.connector.search_gpos(),
            )
            trusts_raw = await self._safe_enumerate(
                "trusts",
                self.connector.search_trusts(),
            )

        # ── Étape 3: Parsing et structuration ───────────────────
        logger.info(
            "parsing_objects",
            users=len(users_raw),
            groups=len(groups_raw),
            computers=len(computers_raw),
        )

        users = self._parse_users(users_raw)
        groups = self._parse_groups(groups_raw)
        computers = self._parse_computers(computers_raw)
        ous = self._parse_ous(ous_raw)
        gpos = self._parse_gpos(gpos_raw)
        trusts = self._parse_trusts(trusts_raw, domain.name)

        # ── Étape 4: Construction de la DomainMap avec index ────
        domain_map = DomainMap(
            domain=domain,
            users=users,
            groups=groups,
            computers=computers,
            ous=ous,
            gpos=gpos,
            trusts=trusts,
            _users_by_dn={u.dn: u for u in users},
            _groups_by_dn={g.dn: g for g in groups},
            _computers_by_dn={c.dn: c for c in computers},
            _groups_by_sam={g.sam_account_name: g for g in groups},
            enumeration_time=time.monotonic() - t_start,
            errors=self._errors,
        )

        logger.info(
            "enumeration_complete",
            total_objects=domain_map.total_objects,
            duration=domain_map.enumeration_time,
            errors=len(self._errors),
        )

        return domain_map

    # ── Énumération par type ────────────────────────────────────

    async def enumerate_users(self) -> list[ADUser]:
        """Énumère uniquement les utilisateurs."""
        raw = await self._safe_enumerate(
            "users",
            self.connector.search_users(),
        )
        return self._parse_users(raw)

    async def enumerate_groups(self) -> list[ADGroup]:
        """Énumère uniquement les groupes."""
        raw = await self._safe_enumerate(
            "groups",
            self.connector.search_groups(),
        )
        return self._parse_groups(raw)

    async def enumerate_computers(self) -> list[ADComputer]:
        """Énumère uniquement les ordinateurs."""
        raw = await self._safe_enumerate(
            "computers",
            self.connector.search_computers(),
        )
        return self._parse_computers(raw)

    async def enumerate_ous(self) -> list[ADOU]:
        """Énumère uniquement les OUs."""
        raw = await self._safe_enumerate(
            "ous",
            self.connector.search_ous(),
        )
        return self._parse_ous(raw)

    # ── Parsers ─────────────────────────────────────────────────

    def _parse_users(self, raw_entries: list[dict]) -> list[ADUser]:
        """Parse les entrées brutes LDAP en objets ADUser."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})

                # Dates AD (format Windows FILETIME → datetime)
                last_logon = self._parse_windows_timestamp(
                    attrs.get("lastLogon", [None])[0],
                )
                pwd_last_set = self._parse_windows_timestamp(
                    attrs.get("pwdLastSet", [None])[0],
                )
                account_expires = self._parse_windows_timestamp(
                    attrs.get("accountExpires", [None])[0],
                )
                when_created = self._parse_ldap_timestamp(
                    attrs.get("whenCreated", [None])[0],
                )
                when_changed = self._parse_ldap_timestamp(
                    attrs.get("whenChanged", [None])[0],
                )

                user = ADUser(
                    dn=entry.get("dn", ""),
                    cn=str(attrs.get("cn", [""])[0] or ""),
                    sam_account_name=str(
                        attrs.get("sAMAccountName", [""])[0] or "",
                    ),
                    user_principal_name=str(
                        attrs.get("userPrincipalName", [""])[0] or "",
                    ),
                    display_name=str(
                        attrs.get("displayName", [""])[0] or "",
                    ),
                    mail=str(attrs.get("mail", [""])[0] or ""),
                    title=str(attrs.get("title", [""])[0] or ""),
                    department=str(attrs.get("department", [""])[0] or ""),
                    company=str(attrs.get("company", [""])[0] or ""),
                    office=str(
                        attrs.get("physicalDeliveryOfficeName", [""])[0] or "",
                    ),
                    phone=str(
                        attrs.get("telephoneNumber", [""])[0] or "",
                    ),
                    member_of=[str(m) for m in attrs.get("memberOf", []) if m],
                    primary_group_id=int(
                        attrs.get("primaryGroupID", [513])[0] or 513,
                    ),
                    user_account_control=int(
                        attrs.get("userAccountControl", [512])[0] or 512,
                    ),
                    bad_pwd_count=int(
                        attrs.get("badPwdCount", [0])[0] or 0,
                    ),
                    last_logon=last_logon,
                    pwd_last_set=pwd_last_set,
                    account_expires=account_expires,
                    admin_count=int(
                        attrs.get("adminCount", [0])[0] or 0,
                    ),
                    service_principal_names=[
                        str(s) for s in attrs.get("servicePrincipalName", []) if s
                    ],
                    logon_count=int(
                        attrs.get("logonCount", [0])[0] or 0,
                    ),
                    home_directory=str(
                        attrs.get("homeDirectory", [""])[0] or "",
                    ),
                    script_path=str(
                        attrs.get("scriptPath", [""])[0] or "",
                    ),
                    profile_path=str(
                        attrs.get("profilePath", [""])[0] or "",
                    ),
                    description=str(
                        attrs.get("description", [""])[0] or "",
                    ),
                    when_created=when_created,
                    when_changed=when_changed,
                    raw_attributes=attrs,
                )
                parsed.append(user)
            except Exception as e:
                self._errors.append(
                    f"Parse user '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    def _parse_groups(self, raw_entries: list[dict]) -> list[ADGroup]:
        """Parse les entrées brutes LDAP en objets ADGroup."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})
                group = ADGroup(
                    dn=entry.get("dn", ""),
                    cn=str(attrs.get("cn", [""])[0] or ""),
                    sam_account_name=str(
                        attrs.get("sAMAccountName", [""])[0] or "",
                    ),
                    group_type=int(
                        attrs.get("groupType", [-2147483646])[0] or -2147483646,
                    ),
                    members=[str(m) for m in attrs.get("member", []) if m],
                    member_of=[str(m) for m in attrs.get("memberOf", []) if m],
                    admin_count=int(
                        attrs.get("adminCount", [0])[0] or 0,
                    ),
                    description=str(
                        attrs.get("description", [""])[0] or "",
                    ),
                    when_created=self._parse_ldap_timestamp(
                        attrs.get("whenCreated", [None])[0],
                    ),
                    when_changed=self._parse_ldap_timestamp(
                        attrs.get("whenChanged", [None])[0],
                    ),
                    raw_attributes=attrs,
                )
                parsed.append(group)
            except Exception as e:
                self._errors.append(
                    f"Parse group '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    def _parse_computers(self, raw_entries: list[dict]) -> list[ADComputer]:
        """Parse les entrées brutes LDAP en objets ADComputer."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})
                computer = ADComputer(
                    dn=entry.get("dn", ""),
                    cn=str(attrs.get("cn", [""])[0] or ""),
                    sam_account_name=str(
                        attrs.get("sAMAccountName", [""])[0] or "",
                    ),
                    dns_hostname=str(
                        attrs.get("dNSHostName", [""])[0] or "",
                    ),
                    operating_system=str(
                        attrs.get("operatingSystem", [""])[0] or "",
                    ),
                    operating_system_version=str(
                        attrs.get("operatingSystemVersion", [""])[0] or "",
                    ),
                    operating_system_service_pack=str(
                        attrs.get("operatingSystemServicePack", [""])[0] or "",
                    ),
                    member_of=[str(m) for m in attrs.get("memberOf", []) if m],
                    user_account_control=int(
                        attrs.get("userAccountControl", [4096])[0] or 4096,
                    ),
                    last_logon=self._parse_windows_timestamp(
                        attrs.get("lastLogon", [None])[0],
                    ),
                    service_principal_names=[
                        str(s) for s in attrs.get("servicePrincipalName", []) if s
                    ],
                    description=str(
                        attrs.get("description", [""])[0] or "",
                    ),
                    when_created=self._parse_ldap_timestamp(
                        attrs.get("whenCreated", [None])[0],
                    ),
                    when_changed=self._parse_ldap_timestamp(
                        attrs.get("whenChanged", [None])[0],
                    ),
                    raw_attributes=attrs,
                )
                parsed.append(computer)
            except Exception as e:
                self._errors.append(
                    f"Parse computer '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    def _parse_ous(self, raw_entries: list[dict]) -> list[ADOU]:
        """Parse les entrées brutes LDAP en objets ADOU."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})
                # gPLink contient des DNs de GPOs au format LDAP
                gpo_links = []
                gp_link = attrs.get("gPLink", [""])[0] or ""
                if gp_link:
                    gpo_links = self._parse_gplink(gp_link)

                ou = ADOU(
                    dn=entry.get("dn", ""),
                    cn=str(attrs.get("cn", [""])[0] or ""),
                    ou_name=str(attrs.get("ou", [""])[0] or ""),
                    gpo_links=gpo_links,
                    description=str(
                        attrs.get("description", [""])[0] or "",
                    ),
                    when_created=self._parse_ldap_timestamp(
                        attrs.get("whenCreated", [None])[0],
                    ),
                    when_changed=self._parse_ldap_timestamp(
                        attrs.get("whenChanged", [None])[0],
                    ),
                    raw_attributes=attrs,
                )
                parsed.append(ou)
            except Exception as e:
                self._errors.append(
                    f"Parse OU '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    def _parse_gpos(self, raw_entries: list[dict]) -> list[ADGPO]:
        """Parse les entrées brutes LDAP en objets ADGPO."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})
                flags = int(attrs.get("flags", [0])[0] or 0)
                status_map = {
                    0: "Enabled",
                    1: "UserDisabled",
                    2: "ComputerDisabled",
                    3: "AllDisabled",
                }
                gpo = ADGPO(
                    dn=entry.get("dn", ""),
                    cn=str(attrs.get("cn", [""])[0] or ""),
                    display_name=str(
                        attrs.get("displayName", [""])[0] or "",
                    ),
                    gpo_status=status_map.get(flags, "Unknown"),
                    path=str(
                        attrs.get("gPCFileSysPath", [""])[0] or "",
                    ),
                    version=int(
                        attrs.get("versionNumber", [0])[0] or 0,
                    ),
                    description=str(
                        attrs.get("description", [""])[0] or "",
                    ),
                    when_created=self._parse_ldap_timestamp(
                        attrs.get("whenCreated", [None])[0],
                    ),
                    when_changed=self._parse_ldap_timestamp(
                        attrs.get("whenChanged", [None])[0],
                    ),
                    raw_attributes=attrs,
                )
                parsed.append(gpo)
            except Exception as e:
                self._errors.append(
                    f"Parse GPO '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    def _parse_trusts(
        self,
        raw_entries: list[dict],
        source_domain: str,
    ) -> list[ADTrust]:
        """Parse les entrées brutes LDAP en objets ADTrust."""
        parsed = []
        for entry in raw_entries:
            try:
                attrs = entry.get("attributes", {})
                direction_raw = str(
                    attrs.get("trustDirection", ["0"])[0] or "0",
                )
                type_raw = str(
                    attrs.get("trustType", ["2"])[0] or "2",
                )
                trust_attrs = int(
                    attrs.get("trustAttributes", [0])[0] or 0,
                )

                target = str(
                    attrs.get("trustPartner", [""])[0] or "",
                )
                # Nettoyer le domaine cible (peut avoir des suffixes)
                if target:
                    target = target.rsplit("\\", maxsplit=1)[-1].strip()

                trust = ADTrust(
                    source_domain=source_domain,
                    target_domain=target,
                    direction=TRUST_DIRECTION_MAP.get(
                        direction_raw,
                        f"Unknown({direction_raw})",
                    ),
                    type=TRUST_TYPE_MAP.get(
                        type_raw,
                        f"Unknown({type_raw})",
                    ),
                    transitive=(trust_attrs != 0 and not (trust_attrs & TRUST_ATTR_NON_TRANSITIVE)),
                    sid_filtering=not bool(
                        trust_attrs & TRUST_ATTR_WITHIN_FOREST,
                    ),
                )
                parsed.append(trust)
            except Exception as e:
                self._errors.append(
                    f"Parse trust '{entry.get('dn', '?')}': {e}",
                )
        return parsed

    async def _enumerate_domain_info(self) -> ADDomain:
        """Récupère les informations du domaine via RootDSE."""
        try:
            info = await self.connector.get_domain_info()

            functional_level_raw = str(
                info.get("domainControllerFunctionality", "7") or "7",
            )
            functional_level = FUNCTIONAL_LEVEL_MAP.get(
                functional_level_raw,
                f"Unknown({functional_level_raw})",
            )

            # Trouver le SID du domaine (depuis le DN base)
            sid = ""
            # Tenter de récupérer le SID via une requête sur le domaine
            try:
                sid_entries = await self.connector.search(
                    "(objectClass=domain)",
                    scope="base",
                    attributes=["objectSid"],
                )
                if sid_entries:
                    raw_sid = (
                        sid_entries[0]
                        .get("attributes", {})
                        .get(
                            "objectSid",
                            [""],
                        )[0]
                    )
                    if raw_sid:
                        sid = self._format_sid(raw_sid)
            except Exception:
                pass

            # Nom NetBIOS (depuis l'objet domain)
            netbios = ""
            try:
                nb_entries = await self.connector.search(
                    "(objectClass=crossRef)",
                    search_base=(f"CN=Partitions,{info.get('configurationNamingContext', '')}"),
                    attributes=["nETBIOSName"],
                )
                for entry in nb_entries:
                    netbios = entry.get("attributes", {}).get(
                        "nETBIOSName",
                        [""],
                    )[0]
                    if netbios:
                        break
            except Exception:
                logger.exception("netbios_lookup_failed")

            # Forest
            forest = (
                info.get("rootDomainNamingContext", "")
                .replace(
                    "DC=",
                    "",
                )
                .replace(",", ".")
            )

            # Liste des DCs
            dc_hostnames: list[str] = []
            try:
                dc_entries = await self.connector.search(
                    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    attributes=["dNSHostName"],
                )
                for entry in dc_entries:
                    hostname = entry.get("attributes", {}).get(
                        "dNSHostName",
                        [""],
                    )[0]
                    if hostname:
                        dc_hostnames.append(hostname)
            except Exception:
                logger.warning("dc_hostname_search_failed")

            return ADDomain(
                name=self.connector.config.domain,
                netbios_name=netbios,
                sid=sid,
                functional_level=functional_level,
                forest=forest,
                dc_hostnames=dc_hostnames,
            )
        except Exception as e:
            self._errors.append(f"Domain info: {e}")
            return ADDomain(name=self.connector.config.domain)

    # ── Helpers ─────────────────────────────────────────────────

    async def _safe_enumerate(
        self,
        name: str,
        coro,
    ) -> list[dict]:
        """Exécute une coroutine d'énumération en capturant les erreurs."""
        try:
            result = await coro
            if isinstance(result, list):
                return result
            return list(result) if result else []
        except Exception as e:
            self._errors.append(f"{name} enumeration: {e}")
            logger.exception("enumeration_error", type=name, error=str(e))
            return []

    def _parse_gplink(self, gplink: str) -> list[str]:
        """Parse un attribut gPLink en liste de DNs de GPO."""
        # Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;0]
        import re

        dn_pattern = re.compile(r"LDAP://([^;\]]+)")
        return dn_pattern.findall(gplink)

    @staticmethod
    def _parse_windows_timestamp(timestamp) -> datetime | None:
        """Convertit un timestamp Windows FILETIME (100ns depuis 1601) en datetime."""
        if not timestamp:
            return None
        try:
            ts = int(timestamp)
            if ts in {0, 9223372036854775807}:  # Never
                return None
            # 100-nanosecond intervals since 1601-01-01
            epoch_diff = 116444736000000000  # 1601 → 1970 in 100ns
            unix_ts = (ts - epoch_diff) / 10000000
            return datetime.fromtimestamp(unix_ts)
        except (ValueError, OSError, OverflowError):
            return None

    @staticmethod
    def _parse_ldap_timestamp(timestamp_str) -> datetime | None:
        """Parse un timestamp LDAP (format 'YYYYMMDDHHMMSS.0Z')."""
        if not timestamp_str:
            return None
        try:
            ts = str(timestamp_str).split(".")[0].rstrip("Z")
            return datetime.strptime(ts, "%Y%m%d%H%M%S")
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _format_sid(raw_sid) -> str:
        """Convertit un SID binaire en chaîne lisible."""
        try:
            # Tentative de formatage via ldap3
            import struct

            if isinstance(raw_sid, bytes):
                # Parse binaire manuellement
                version = raw_sid[0]
                sub_authority_count = raw_sid[1]
                identifier_authority = int.from_bytes(
                    raw_sid[2:8],
                    "big",
                )
                sid = f"S-{version}-{identifier_authority}"
                for i in range(sub_authority_count):
                    offset = 8 + (i * 4)
                    sub_auth = struct.unpack(
                        "<I",
                        raw_sid[offset : offset + 4],
                    )[0]
                    sid += f"-{sub_auth}"
                return sid
            return str(raw_sid)
        except Exception:
            return str(raw_sid)


# ── Fonction utilitaire ────────────────────────────────────────


async def quick_enumeration(
    server: str,
    domain: str,
    username: str,
    password: str,
    use_ssl: bool = True,
) -> DomainMap:
    """Énumération rapide en une ligne (pour les tests/scripts).

    Usage:
        domain_map = await quick_enumeration(
            "dc.corp.local", "corp.local", "admin@corp.local", "password"
        )
    """
    from .connector import ADAuthMethod, ADConfig

    config = ADConfig(
        server=server,
        domain=domain,
        username=username,
        password=password,
        auth_method=ADAuthMethod.SIMPLE,
        use_ssl=use_ssl,
    )

    connector = ADConnector(config)
    await connector.connect()

    try:
        enumerator = ADEnumerator(connector)
        return await enumerator.enumerate_all()
    finally:
        await connector.close()
