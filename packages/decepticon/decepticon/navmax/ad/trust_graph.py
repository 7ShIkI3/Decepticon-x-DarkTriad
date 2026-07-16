"""AD Trust Graph — graphe d'attaque dynamique (BloodHound-like).

Construit un graphe orienté NetworkX à partir d'une DomainMap,
modélisant les relations de confiance, appartenance aux groupes,
et privilèges dans un domaine Active Directory.

Usage:
    graph = ADTrustGraph()
    graph.build(domain_map)

    # Requêtes
    paths = graph.find_path_to_da("jdoe@corp.local")
    admins = graph.get_effective_domain_admins()
    exposed = graph.find_kerberoastable_paths()

    # Export
    json_data = graph.export_bloodhound_json()
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Types de nœuds et relations ────────────────────────────────


class NodeType(StrEnum):
    """Types de nœuds dans le graphe d'attaque AD."""

    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"


class EdgeType(StrEnum):
    """Types de relations dans le graphe d'attaque AD."""

    # Relations standard
    MEMBER_OF = "MemberOf"  # User/Group/Computer → Group
    ADMIN_TO = "AdminTo"  # User/Group → Computer
    HAS_SESSION = "HasSession"  # User → Computer
    TRUSTED_BY = "TrustedBy"  # Domain → Domain

    # Privilèges étendus (ACL-based)
    GENERIC_ALL = "GenericAll"  # Contrôle total sur l'objet
    WRITE_DACL = "WriteDacl"  # Modifier les permissions
    WRITE_OWNER = "WriteOwner"  # Changer le propriétaire
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"  # Réinitialiser mot de passe
    ADD_MEMBER = "AddMember"  # Ajouter au groupe
    READ_LAPS_PASSWORD = "ReadLAPSPassword"  # Lire le mot de passe LAPS

    # Primitives d'attaque
    CAN_RDP = "CanRDP"  # RDP disponible
    CAN_PSREMOTE = "CanPSRemote"  # PowerShell Remoting
    SQL_ADMIN = "SQLAdmin"  # Admin SQL Server
    EXECUTE_DCOM = "ExecuteDCOM"  # DCOM execution
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"  # Délégation Kerberos

    # Spécifique Kerberos
    HAS_SPN = "HasSPN"  # Kerberoastable
    ASREP_ROASTABLE = "ASREPRoastable"  # AS-REP Roasting
    TRUSTED_FOR_DELEGATION = "TrustedForDelegation"
    CONSTRAINED_DELEGATION = "ConstrainedDelegation"


@dataclass
class GraphNode:
    """Nœud du graphe d'attaque."""

    id: str  # DN ou SID
    type: NodeType
    name: str  # sAMAccountName, dnsHostname...
    domain: str = ""
    high_value: bool = False  # Cible prioritaire
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Relation entre deux nœuds."""

    source: str  # ID du nœud source
    target: str  # ID du nœud cible
    type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Chemin d'attaque identifié."""

    path: list[str]  # IDs des nœuds (source → cible)
    path_labels: list[str]  # Noms lisibles
    edge_types: list[EdgeType]  # Types de chaque saut
    length: int
    risk_score: float = 0.0  # 0-100
    description: str = ""


# ── Groupes à haute valeur ─────────────────────────────────────

HIGH_VALUE_GROUPS = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "schema admins",
    "dnsadmins",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "domain controllers",
    "cert publishers",
    "group policy creator owners",
}

HIGH_VALUE_COMPUTERS = {
    "domain controllers",
    "certificate authorities",
    "exchange servers",
    "sql servers",
    "file servers",
}


# ── Constructeur du graphe ─────────────────────────────────────


class ADTrustGraph:
    """Graphe d'attaque Active Directory basé sur NetworkX.

    Construit un graphe orienté à partir d'une DomainMap,
    puis permet des requêtes de type BloodHound.

    Usage:
        graph = ADTrustGraph()
        graph.build(domain_map)
        paths = graph.find_shortest_path_to_da("jdoe")
    """

    def __init__(self) -> None:
        self._graph: Any = None  # networkx.DiGraph
        self._node_index: dict[str, GraphNode] = {}  # ID → GraphNode
        self._domain: str = ""
        self._domain_sid: str = ""

    @property
    def graph(self) -> Any:
        """Le DiGraph NetworkX sous-jacent."""
        return self._graph

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes() if self._graph else 0

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges() if self._graph else 0

    # ── Construction ────────────────────────────────────────────

    def build(self, domain_map) -> "ADTrustGraph":
        """Construit le graphe à partir d'une DomainMap.

        Args:
            domain_map: DomainMap issue de ADEnumerator.enumerate_all()

        Returns:
            self (pour le chaînage)

        """
        import networkx as nx

        self._graph = nx.DiGraph()
        self._domain = domain_map.domain.name
        self._domain_sid = domain_map.domain.sid

        logger.info(
            "building_trust_graph",
            domain=self._domain,
            users=len(domain_map.users),
            groups=len(domain_map.groups),
            computers=len(domain_map.computers),
        )

        # ── Ajouter les nœuds ──────────────────────────────────
        self._add_domain_node(domain_map)
        self._add_user_nodes(domain_map)
        self._add_group_nodes(domain_map)
        self._add_computer_nodes(domain_map)

        # ── Ajouter les relations ───────────────────────────────
        self._add_member_of_edges(domain_map)
        self._add_admin_edges(domain_map)
        self._add_trust_edges(domain_map)
        self._add_kerberos_edges(domain_map)
        self._add_delegation_edges(domain_map)

        logger.info("trust_graph_built", nodes=self.node_count, edges=self.edge_count)

        return self

    def _add_domain_node(self, domain_map) -> None:
        """Ajoute le nœud domaine."""
        domain_id = domain_map.domain.sid or domain_map.domain.name
        node = GraphNode(
            id=domain_id,
            type=NodeType.DOMAIN,
            name=domain_map.domain.name,
            domain=domain_map.domain.name,
            high_value=True,
            properties={
                "netbios": domain_map.domain.netbios_name,
                "functional_level": domain_map.domain.functional_level,
                "forest": domain_map.domain.forest,
            },
        )
        self._add_node(node)

    def _add_user_nodes(self, domain_map) -> None:
        """Ajoute les nœuds utilisateur."""
        for user in domain_map.users:
            node_id = user.dn
            is_high_value = user.is_admin or user.sam_account_name.lower() in {
                "administrator",
                "krbtgt",
            }

            # Déterminer si l'utilisateur est dans un groupe à haute valeur
            # (vérifié via le graphe après construction)

            node = GraphNode(
                id=node_id,
                type=NodeType.USER,
                name=user.sam_account_name,
                domain=self._domain,
                high_value=is_high_value,
                properties={
                    "sam": user.sam_account_name,
                    "upn": user.user_principal_name,
                    "display_name": user.display_name,
                    "enabled": user.is_enabled,
                    "admin_count": user.admin_count,
                    "spns": user.service_principal_names,
                    "asrep_roastable": user.is_asrep_roastable,
                    "trusted_for_delegation": user.is_trusted_for_delegation,
                },
            )
            self._add_node(node)

    def _add_group_nodes(self, domain_map) -> None:
        """Ajoute les nœuds groupe."""
        for group in domain_map.groups:
            node_id = group.dn
            sam_lower = group.sam_account_name.lower()
            is_high_value = sam_lower in HIGH_VALUE_GROUPS or group.admin_count == 1

            node = GraphNode(
                id=node_id,
                type=NodeType.GROUP,
                name=group.sam_account_name,
                domain=self._domain,
                high_value=is_high_value,
                properties={
                    "sam": group.sam_account_name,
                    "scope": group.scope,
                    "security": group.is_security_group,
                    "admin_count": group.admin_count,
                },
            )
            self._add_node(node)

    def _add_computer_nodes(self, domain_map) -> None:
        """Ajoute les nœuds ordinateur."""
        for computer in domain_map.computers:
            node_id = computer.dn
            hostname = computer.dns_hostname or computer.sam_account_name
            is_high_value = computer.is_domain_controller or any(
                kw in hostname.lower() for kw in HIGH_VALUE_COMPUTERS
            )

            node = GraphNode(
                id=node_id,
                type=NodeType.COMPUTER,
                name=hostname.rstrip("$"),
                domain=self._domain,
                high_value=is_high_value,
                properties={
                    "dns_hostname": computer.dns_hostname,
                    "os": computer.operating_system,
                    "os_version": computer.operating_system_version,
                    "is_dc": computer.is_domain_controller,
                    "enabled": computer.is_enabled,
                    "unconstrained_delegation": ((computer.user_account_control & 0x80000) != 0),
                },
            )
            self._add_node(node)

    # ── Relations ──────────────────────────────────────────────

    def _add_member_of_edges(self, domain_map) -> None:
        """Relations MemberOf (appartenance aux groupes)."""
        edge_count = 0

        for user in domain_map.users:
            for group_dn in user.member_of:
                if group_dn in self._node_index:
                    self._add_edge(EdgeType.MEMBER_OF, user.dn, group_dn)
                    edge_count += 1

        for group in domain_map.groups:
            for parent_dn in group.member_of:
                if parent_dn in self._node_index:
                    self._add_edge(EdgeType.MEMBER_OF, group.dn, parent_dn)
                    edge_count += 1

        for computer in domain_map.computers:
            for group_dn in computer.member_of:
                if group_dn in self._node_index:
                    self._add_edge(EdgeType.MEMBER_OF, computer.dn, group_dn)
                    edge_count += 1

        logger.debug("member_of_edges_added", count=edge_count)

    def _add_admin_edges(self, domain_map) -> None:
        """Relations AdminTo (administrateurs locaux/délégués).

        Infère les relations AdminTo à partir de l'appartenance
        aux groupes d'administration et des ACLs.
        """
        edge_count = 0

        # Trouver les groupes d'administration
        admin_groups = set()
        for group in domain_map.groups:
            if group.admin_count == 1 or group.sam_account_name.lower() in HIGH_VALUE_GROUPS:
                admin_groups.add(group.dn)

        # Pour chaque utilisateur dans un groupe admin → AdminTo sur les DCs
        # (simplifié : dans BloodHound, c'est via les sessions/ACLs)
        for user in domain_map.users:
            if user.is_admin:
                for dc in domain_map.domain_controllers:
                    self._add_edge(EdgeType.ADMIN_TO, user.dn, dc.dn)
                    edge_count += 1

        logger.debug("admin_edges_added", count=edge_count)

    def _add_trust_edges(self, domain_map) -> None:
        """Relations de confiance inter-domaine."""
        for trust in domain_map.trusts:
            # Le trust va de la source vers la cible
            # Pour le graphe, on ajoute dans les deux sens si bidirectionnel
            source_id = domain_map.domain.sid or domain_map.domain.name
            target_id = trust.target_domain

            # Créer un nœud pour le domaine cible s'il n'existe pas
            if target_id not in self._node_index:
                target_node = GraphNode(
                    id=target_id,
                    type=NodeType.DOMAIN,
                    name=trust.target_domain,
                    domain=trust.target_domain,
                )
                self._add_node(target_node)

            self._add_edge(
                EdgeType.TRUSTED_BY,
                target_id,  # Le domaine cible est "trusted by" le domaine source
                source_id,
                properties={
                    "direction": trust.direction,
                    "type": trust.type,
                    "transitive": trust.transitive,
                    "sid_filtering": trust.sid_filtering,
                },
            )

    def _add_kerberos_edges(self, domain_map) -> None:
        """Relations spécifiques Kerberos (SPN, AS-REP, délégation)."""
        for user in domain_map.kerberoastable_users:
            # L'utilisateur a un SPN → nœud spécial "kerberoastable"
            self._add_edge(
                EdgeType.HAS_SPN,
                user.dn,
                user.dn,  # Self-loop pour marquer
            )

        for user in domain_map.asrep_roastable_users:
            self._add_edge(
                EdgeType.ASREP_ROASTABLE,
                user.dn,
                user.dn,
            )

    def _add_delegation_edges(self, domain_map) -> None:
        """Relations de délégation Kerberos."""
        for computer in domain_map.unconstrained_delegation_computers:
            # La machine peut déléguer → marquer
            self._add_edge(
                EdgeType.TRUSTED_FOR_DELEGATION,
                computer.dn,
                computer.dn,
            )

    # ── Requêtes de graphe ─────────────────────────────────────

    def find_shortest_path_to_da(
        self,
        user_sam: str,
    ) -> AttackPath | None:
        """Trouve le chemin le plus court d'un utilisateur vers Domain Admins.

        Args:
            user_sam: sAMAccountName de l'utilisateur

        Returns:
            AttackPath ou None si aucun chemin

        """
        user_dn = self._find_user_dn(user_sam)
        if not user_dn:
            return None

        da_group_dn = self._find_group_dn("Domain Admins")
        if not da_group_dn:
            return None

        return self._shortest_path(
            user_dn, da_group_dn, description=f"Chemin de {user_sam} vers Domain Admins",
        )

    def find_shortest_path_to_target(
        self,
        source_sam: str,
        target_sam: str,
    ) -> AttackPath | None:
        """Trouve le chemin le plus court entre deux entités.

        Args:
            source_sam: Point de départ (utilisateur ou groupe)
            target_sam: Cible (utilisateur ou groupe)

        Returns:
            AttackPath ou None

        """
        source_dn = self._find_entity_dn(source_sam)
        target_dn = self._find_entity_dn(target_sam)

        if not source_dn or not target_dn:
            return None

        return self._shortest_path(
            source_dn, target_dn, description=f"Chemin de {source_sam} vers {target_sam}",
        )

    def find_all_paths_to_da(
        self,
        user_sam: str,
        max_paths: int = 5,
    ) -> list[AttackPath]:
        """Trouve tous les chemins (jusqu'à max_paths) vers Domain Admins.

        Args:
            user_sam: sAMAccountName de l'utilisateur
            max_paths: Nombre maximum de chemins

        Returns:
            Liste d'AttackPath (du plus court au plus long)

        """
        user_dn = self._find_user_dn(user_sam)
        da_group_dn = self._find_group_dn("Domain Admins")

        if not user_dn or not da_group_dn:
            return []

        return self._all_shortest_paths(
            user_dn, da_group_dn, max_paths, f"Chemins de {user_sam} vers Domain Admins",
        )

    def get_effective_domain_admins(self) -> list[str]:
        """Retourne tous les utilisateurs qui sont Domain Admins (directs ou nested).

        Returns:
            Liste de sAMAccountNames

        """
        da_group_dn = self._find_group_dn("Domain Admins")
        if not da_group_dn:
            return []

        admins = set()
        for node_id, node in self._node_index.items():
            if node.type != NodeType.USER:
                continue
            try:
                # Vérifier s'il existe un chemin de l'utilisateur vers DA
                import networkx as nx

                if nx.has_path(self._graph, node_id, da_group_dn):
                    admins.add(node.name)
            except (nx.NodeNotFound, nx.NetworkXError):
                continue

        return sorted(admins)

    def find_kerberoastable_paths(self) -> list[AttackPath]:
        """Trouve les chemins d'attaque via comptes Kerberoastable.

        Un attaquant peut kerberoaster un compte SPN → casser le hash →
        devenir admin si le compte est privilégié.

        Returns:
            Liste d'AttackPath triée par risque

        """
        paths = []
        da_group_dn = self._find_group_dn("Domain Admins")

        for node_id, node in self._node_index.items():
            if node.type != NodeType.USER:
                continue
            if not node.properties.get("spns"):
                continue

            # Vérifier si ce compte kerberoastable mène à DA
            if da_group_dn:
                try:
                    import networkx as nx

                    if nx.has_path(self._graph, node_id, da_group_dn):
                        attack_path = self._shortest_path(
                            node_id,
                            da_group_dn,
                            description=f"Kerberoasting: {node.name}",
                        )
                        if attack_path:
                            attack_path.risk_score = self._compute_risk(
                                attack_path,
                                is_kerberoastable=True,
                            )
                            paths.append(attack_path)
                except (nx.NodeNotFound, nx.NetworkXError):
                    continue

        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def find_asrep_roastable_targets(self) -> list[str]:
        """Retourne les utilisateurs vulnérables à l'AS-REP Roasting."""
        targets = []
        for node in self._node_index.values():
            if node.type == NodeType.USER and node.properties.get("asrep_roastable"):
                targets.append(node.name)
        return targets

    def find_unconstrained_delegation_hosts(self) -> list[str]:
        """Retourne les machines avec délégation non contrainte."""
        hosts = []
        for node in self._node_index.values():
            if node.type == NodeType.COMPUTER and node.properties.get(
                "unconstrained_delegation",
            ):
                hosts.append(node.name)
        return hosts

    def get_high_value_targets(self) -> list[GraphNode]:
        """Retourne tous les nœuds marqués comme haute valeur."""
        return [n for n in self._node_index.values() if n.high_value]

    def get_user_effective_groups(self, user_sam: str) -> list[str]:
        """Retourne tous les groupes auxquels l'utilisateur appartient (direct+nested).

        Args:
            user_sam: sAMAccountName

        Returns:
            Liste de noms de groupes

        """
        user_dn = self._find_user_dn(user_sam)
        if not user_dn:
            return []

        groups = set()
        for node_id, node in self._node_index.items():
            if node.type != NodeType.GROUP:
                continue
            try:
                import networkx as nx

                if nx.has_path(self._graph, user_dn, node_id):
                    groups.add(node.name)
            except (nx.NodeNotFound, nx.NetworkXError):
                continue

        return sorted(groups)

    # ── Analyse avancée ────────────────────────────────────────

    def find_cross_domain_attack_paths(self) -> list[AttackPath]:
        """Trouve les chemins d'attaque inter-domaines (via trusts).

        Returns:
            Liste d'AttackPath traversant des frontières de domaine

        """
        paths = []

        # Trouver les arêtes TRUSTED_BY
        trust_edges = [
            (u, v)
            for u, v, d in self._graph.edges(data=True)
            if d.get("type") == EdgeType.TRUSTED_BY
        ]

        for src_domain, dst_domain in trust_edges:
            # Chercher des utilisateurs dans le domaine source
            # qui peuvent atteindre des cibles haute valeur dans le domaine cible
            for node_id, node in self._node_index.items():
                if node.type != NodeType.USER:
                    continue
                if (
                    node.domain
                    != self._node_index.get(
                        src_domain,
                        GraphNode(
                            id="",
                            type=NodeType.DOMAIN,
                            name="",
                        ),
                    ).name
                ):
                    continue

                # Vérifier s'il peut atteindre un objet dans le domaine cible
                for target_id, target_node in self._node_index.items():
                    if target_node.domain == dst_domain and target_node.high_value:
                        try:
                            import networkx as nx

                            if nx.has_path(self._graph, node_id, target_id):
                                attack_path = self._shortest_path(
                                    node_id,
                                    target_id,
                                    description=f"Cross-domain: {node.name} → {target_node.name}",
                                )
                                if attack_path:
                                    attack_path.risk_score = self._compute_risk(
                                        attack_path,
                                        is_cross_domain=True,
                                    )
                                    paths.append(attack_path)
                                    break  # Un seul chemin par utilisateur
                        except (nx.NodeNotFound, nx.NetworkXError):
                            continue

        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def find_most_exposed_users(self, top_n: int = 10) -> list[dict]:
        """Identifie les utilisateurs les plus exposés (plus de chemins vers DA).

        Args:
            top_n: Nombre de résultats

        Returns:
            Liste de dicts {user, path_count, shortest_path_length}

        """
        da_group_dn = self._find_group_dn("Domain Admins")
        if not da_group_dn:
            return []

        exposure = []
        for node_id, node in self._node_index.items():
            if node.type != NodeType.USER:
                continue
            if not node.properties.get("enabled", True):
                continue

            try:
                import networkx as nx

                path = nx.shortest_path(self._graph, node_id, da_group_dn)
                # Compter tous les chemins simples (limité pour les grands graphes)
                all_paths = list(
                    nx.all_simple_paths(
                        self._graph,
                        node_id,
                        da_group_dn,
                        cutoff=len(path) + 2,
                    ),
                )
                exposure.append(
                    {
                        "user": node.name,
                        "dn": node_id,
                        "path_count": min(len(all_paths), 100),
                        "shortest_path_length": len(path) - 1,  # -1 car on compte les sauts
                    },
                )
            except (nx.NodeNotFound, nx.NetworkXNoPath, nx.NetworkXError):
                exposure.append(
                    {
                        "user": node.name,
                        "dn": node_id,
                        "path_count": 0,
                        "shortest_path_length": -1,
                    },
                )

        exposure.sort(key=lambda x: (x["shortest_path_length"], -x["path_count"]))
        return exposure[:top_n]

    # ── Export ─────────────────────────────────────────────────

    def export_bloodhound_json(self) -> dict:
        """Exporte le graphe au format compatible BloodHound (JSON).

        Format:
        {
            "nodes": { "id": { ... }, ... },
            "edges": [ { "source": "...", "target": "...", "type": "..." }, ... ]
        }
        """
        nodes = {}
        for node_id, node in self._node_index.items():
            nodes[node_id] = {
                "type": node.type,
                "name": node.name,
                "domain": node.domain,
                "high_value": node.high_value,
                "properties": node.properties,
            }

        edges = []
        for u, v, data in self._graph.edges(data=True):
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "type": data.get("type", "Unknown"),
                    "properties": data.get("properties", {}),
                },
            )

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "domain": self._domain,
                "domain_sid": self._domain_sid,
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "version": "1.0",
                "generator": "NavMAX AD Trust Graph",
            },
        }

    def summary(self) -> str:
        """Résumé textuel du graphe."""
        da_count = len(self.get_effective_domain_admins())
        kerberoastable = len(self.find_kerberoastable_paths())
        high_value = len(self.get_high_value_targets())

        return (
            f"=== AD Trust Graph ===\n"
            f"  Domain: {self._domain}\n"
            f"  Nodes: {self.node_count}\n"
            f"    Users: {sum(1 for n in self._node_index.values() if n.type == NodeType.USER)}\n"
            f"    Groups: {sum(1 for n in self._node_index.values() if n.type == NodeType.GROUP)}\n"
            f"    Computers: {sum(1 for n in self._node_index.values() if n.type == NodeType.COMPUTER)}\n"
            f"    Domains: {sum(1 for n in self._node_index.values() if n.type == NodeType.DOMAIN)}\n"
            f"  Edges: {self.edge_count}\n"
            f"  Effective Domain Admins: {da_count}\n"
            f"  Kerberoastable attack paths: {kerberoastable}\n"
            f"  High-value targets: {high_value}\n"
        )

    # ── Helpers ────────────────────────────────────────────────

    def _add_node(self, node: GraphNode) -> None:
        """Ajoute un nœud au graphe et à l'index."""
        self._graph.add_node(node.id, **node.__dict__)
        self._node_index[node.id] = node

    def _add_edge(
        self,
        edge_type: EdgeType,
        source: str,
        target: str,
        properties: dict | None = None,
    ) -> None:
        """Ajoute une relation orientée."""
        if source not in self._node_index or target not in self._node_index:
            return
        self._graph.add_edge(
            source,
            target,
            type=edge_type,
            properties=properties or {},
        )

    def _find_user_dn(self, sam: str) -> str | None:
        """Trouve le DN d'un utilisateur par sAMAccountName."""
        for node_id, node in self._node_index.items():
            if node.type == NodeType.USER and node.name.lower() == sam.lower():
                return node_id
        return None

    def _find_group_dn(self, sam: str) -> str | None:
        """Trouve le DN d'un groupe par sAMAccountName."""
        for node_id, node in self._node_index.items():
            if node.type == NodeType.GROUP and node.name.lower() == sam.lower():
                return node_id
        return None

    def _find_entity_dn(self, name: str) -> str | None:
        """Trouve le DN d'une entité (user, group, computer) par nom."""
        for node_id, node in self._node_index.items():
            if node.name.lower() == name.lower():
                return node_id
        return None

    def _shortest_path(
        self,
        source_dn: str,
        target_dn: str,
        description: str = "",
    ) -> AttackPath | None:
        """Calcule le chemin le plus court entre deux nœuds."""
        import networkx as nx

        try:
            path = nx.shortest_path(self._graph, source_dn, target_dn)
        except (nx.NodeNotFound, nx.NetworkXNoPath, nx.NetworkXError):
            return None

        edge_types = []
        for i in range(len(path) - 1):
            edge_data = self._graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                edge_types.append(edge_data.get("type", EdgeType.MEMBER_OF))
            else:
                edge_types.append(EdgeType.MEMBER_OF)

        path_labels = [
            self._node_index.get(
                n,
                GraphNode(
                    id=n,
                    type=NodeType.USER,
                    name=n,
                ),
            ).name
            for n in path
        ]

        return AttackPath(
            path=path,
            path_labels=path_labels,
            edge_types=edge_types,
            length=len(path) - 1,
            description=description,
        )

    def _all_shortest_paths(
        self,
        source_dn: str,
        target_dn: str,
        max_paths: int,
        description: str = "",
    ) -> list[AttackPath]:
        """Trouve tous les chemins les plus courts entre deux nœuds."""
        import networkx as nx

        try:
            all_paths = list(
                nx.all_shortest_paths(
                    self._graph,
                    source_dn,
                    target_dn,
                ),
            )[:max_paths]
        except (nx.NodeNotFound, nx.NetworkXNoPath, nx.NetworkXError):
            return []

        results = []
        for path in all_paths:
            edge_types = []
            for i in range(len(path) - 1):
                edge_data = self._graph.get_edge_data(path[i], path[i + 1])
                if edge_data:
                    edge_types.append(edge_data.get("type", EdgeType.MEMBER_OF))
                else:
                    edge_types.append(EdgeType.MEMBER_OF)

            path_labels = [
                self._node_index.get(
                    n,
                    GraphNode(
                        id=n,
                        type=NodeType.USER,
                        name=n,
                    ),
                ).name
                for n in path
            ]

            results.append(
                AttackPath(
                    path=path,
                    path_labels=path_labels,
                    edge_types=edge_types,
                    length=len(path) - 1,
                    description=description,
                ),
            )

        return results

    def _compute_risk(
        self,
        attack_path: AttackPath,
        *,
        is_kerberoastable: bool = False,
        is_cross_domain: bool = False,
    ) -> float:
        """Calcule un score de risque (0-100) pour un chemin d'attaque.

        Facteurs:
        - Longueur du chemin (plus court = plus risqué)
        - Types d'arêtes (AdminTo > MemberOf)
        - Kerberoastable (+30)
        - Cross-domain (+20)
        """
        score = 100.0

        # Pénalité de longueur
        score -= attack_path.length * 15

        # Bonus pour les arêtes AdminTo
        admin_count = sum(1 for e in attack_path.edge_types if e == EdgeType.ADMIN_TO)
        score += admin_count * 10

        # Bonus Kerberoastable
        if is_kerberoastable:
            score += 30

        # Bonus cross-domain
        if is_cross_domain:
            score += 20

        return max(0.0, min(100.0, score))
