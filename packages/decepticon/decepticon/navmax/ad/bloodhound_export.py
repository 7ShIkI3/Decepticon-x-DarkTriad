"""BloodHound Export — export du graphe d'attaque au format BloodHound JSON."""

import json
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ExportResult:
    filepath: str = ""
    node_count: int = 0
    edge_count: int = 0
    domain: str = ""
    file_size_bytes: int = 0
    errors: list[str] = field(default_factory=list)


class BloodHoundExporter:
    NODE_TYPE_MAP = {
        "User": "User",
        "Group": "Group",
        "Computer": "Computer",
        "Domain": "Domain",
        "OU": "OU",
        "GPO": "GPO",
    }

    EDGE_KIND_MAP = {
        "MemberOf": 1,
        "AdminTo": 2,
        "HasSession": 3,
        "TrustedBy": 4,
        "GenericAll": 5,
        "WriteDacl": 6,
        "WriteOwner": 7,
        "ForceChangePassword": 8,
        "AddMember": 9,
        "ReadLAPSPassword": 10,
        "CanRDP": 11,
        "CanPSRemote": 12,
        "SQLAdmin": 13,
        "ExecuteDCOM": 14,
        "AllowedToDelegate": 15,
        "HasSPN": 16,
        "ASREPRoastable": 17,
        "TrustedForDelegation": 18,
        "ConstrainedDelegation": 19,
    }

    def export(self, trust_graph) -> dict:
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        graph = trust_graph.graph
        if graph is None or graph.number_of_nodes() == 0:
            return {
                "data": [{"Nodes": {}, "Edges": []}],
                "meta": {
                    "version": 5,
                    "counts": {
                        "nodes": 0,
                        "edges": 0,
                        "users": 0,
                        "groups": 0,
                        "computers": 0,
                        "domains": 0,
                    },
                },
            }

        for node_id in graph.nodes():
            node_data = graph.nodes[node_id]
            node_type = node_data.get("type", "User")
            display_name = node_data.get("name", node_id)

            bh_node = {
                "ObjectIdentifier": node_id,
                "Properties": {
                    "name": display_name,
                    "domain": node_data.get("domain", ""),
                    "highvalue": node_data.get("high_value", False),
                    "enabled": node_data.get("enabled", True),
                    "admincount": node_data.get("admin_count", 0),
                },
                "Label": self.NODE_TYPE_MAP.get(node_type, node_type),
            }
            nodes[node_id] = bh_node

        for u, v, data in graph.edges(data=True):
            edge_type = str(data.get("type", "MemberOf"))
            kind = self.EDGE_KIND_MAP.get(edge_type, 1)
            edges.append(
                {
                    "Source": u,
                    "Target": v,
                    "Kind": kind,
                    "Label": edge_type,
                    "Properties": {"isenforced": False, "isacl": kind in (5, 6, 7, 8, 9, 10)},
                },
            )

        return {
            "data": [{"Nodes": nodes, "Edges": edges}],
            "meta": {
                "version": 5,
                "type": "NavMAX BloodHound Export",
                "counts": {
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "users": sum(1 for n in nodes.values() if n["Label"] == "User"),
                    "groups": sum(1 for n in nodes.values() if n["Label"] == "Group"),
                    "computers": sum(1 for n in nodes.values() if n["Label"] == "Computer"),
                    "domains": sum(1 for n in nodes.values() if n["Label"] == "Domain"),
                },
            },
        }

    def save(self, data: dict, filepath: str) -> ExportResult:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            import os

            file_size = os.path.getsize(filepath)
            meta = data.get("meta", {}).get("counts", {})
            return ExportResult(
                filepath=filepath,
                node_count=meta.get("nodes", 0),
                edge_count=meta.get("edges", 0),
                file_size_bytes=file_size,
            )
        except Exception as e:
            return ExportResult(filepath=filepath, errors=[str(e)])

    def export_and_save(self, trust_graph, filepath: str) -> ExportResult:
        data = self.export(trust_graph)
        return self.save(data, filepath)
