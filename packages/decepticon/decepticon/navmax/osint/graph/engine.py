"""Moteur de graphe basé sur NetworkX.

Stocke et interroge les entités et relations découvertes par les collecteurs OSINT.
"""

import json
from typing import Any

import networkx as nx

from decepticon.navmax.core.logging import get_logger

from .entities import Entity, EntityType, Relation, RelationType

logger = get_logger(__name__)


class GraphEngine:
    """Moteur de graphe NavMAX.
    Chaque nœud est une Entity, chaque arête est une Relation.
    """

    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()
        self._entity_index: dict[str, Entity] = {}  # value:type → id

    # ------------------------------------------------------------------
    # CRUD Entités
    # ------------------------------------------------------------------
    def add_entity(self, entity: Entity) -> str:
        """Ajoute une entité au graphe. Retourne son ID."""
        key = f"{entity.value}:{entity.type.value}"
        if key in self._entity_index:
            return self._entity_index[key]

        self._graph.add_node(
            entity.id,
            type=entity.type.value,
            value=entity.value,
            label=entity.label or entity.value,
            properties=entity.properties,
            sources=entity.sources,
        )
        self._entity_index[key] = entity.id
        return entity.id

    def get_entity(self, entity_id: str) -> Entity | None:
        """Récupère une entité par ID."""
        if entity_id not in self._graph.nodes:
            return None
        node = self._graph.nodes[entity_id]
        return Entity(
            id=entity_id,
            type=EntityType(node.get("type", "unknown")),
            value=node.get("value", ""),
            label=node.get("label", ""),
            properties=node.get("properties", {}),
            sources=node.get("sources", []),
        )

    def find_entity(self, value: str, entity_type: EntityType | None = None) -> Entity | None:
        """Trouve une entité par valeur (et optionnellement type)."""
        key = f"{value}:{entity_type.value}" if entity_type else None

        if key and key in self._entity_index:
            return self.get_entity(self._entity_index[key])

        # Recherche lente si pas de type
        for nid, data in self._graph.nodes(data=True):
            if data.get("value") == value:
                if entity_type is None or data.get("type") == entity_type.value:
                    return self.get_entity(nid)
        return None

    # ------------------------------------------------------------------
    # CRUD Relations
    # ------------------------------------------------------------------
    def add_relation(
        self,
        src: Entity,
        tgt: Entity,
        rel_type: RelationType,
        confidence: float = 1.0,
        **props: Any,
    ) -> None:
        """Ajoute une relation entre deux entités."""
        src_id = self.add_entity(src)
        tgt_id = self.add_entity(tgt)

        self._graph.add_edge(
            src_id,
            tgt_id,
            key=rel_type.value,
            type=rel_type.value,
            confidence=confidence,
            properties=props,
        )

    # ------------------------------------------------------------------
    # Requêtes
    # ------------------------------------------------------------------
    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def get_neighbors(self, entity_id: str, depth: int = 1) -> list[tuple[Entity, Relation]]:
        """Récupère les voisins d'une entité jusqu'à une profondeur donnée.

        Returns:
            Liste de (entity, relation) pour chaque voisin.

        """
        results: list[tuple[Entity, Relation]] = []
        visited: set[str] = {entity_id}

        current_layer = {entity_id}
        for _ in range(depth):
            next_layer: set[str] = set()
            for nid in current_layer:
                for _, neighbor, data in self._graph.out_edges(nid, data=True):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_layer.add(neighbor)
                        entity = self.get_entity(neighbor)
                        if entity:
                            rel = Relation(
                                source=self.get_entity(nid) or Entity(),
                                target=entity,
                                type=RelationType(data.get("type", "related_to")),
                                confidence=data.get("confidence", 1.0),
                            )
                            results.append((entity, rel))
                for predecessor, _, data in self._graph.in_edges(nid, data=True):
                    if predecessor not in visited:
                        visited.add(predecessor)
                        next_layer.add(predecessor)
                        entity = self.get_entity(predecessor)
                        if entity:
                            rel = Relation(
                                source=entity,
                                target=self.get_entity(nid) or Entity(),
                                type=RelationType(data.get("type", "related_to")),
                                confidence=data.get("confidence", 1.0),
                            )
                            results.append((entity, rel))
            current_layer = next_layer

        return results

    def search(self, query: str) -> list[Entity]:
        """Recherche textuelle dans les entités."""
        results: list[Entity] = []
        q = query.lower()
        for nid in self._graph.nodes:
            entity = self.get_entity(nid)
            if entity and (q in entity.value.lower() or q in entity.label.lower()):
                results.append(entity)
        return results

    def get_all_entities(self, entity_type: EntityType | None = None) -> list[Entity]:
        """Liste toutes les entités, optionnellement filtrées par type."""
        results: list[Entity] = []
        for nid in self._graph.nodes:
            entity = self.get_entity(nid)
            if entity and (entity_type is None or entity.type == entity_type):
                results.append(entity)
        return results

    def get_subgraph(self, entity_ids: list[str], depth: int = 1) -> dict[str, Any]:
        """Exporte un sous-graphe en format JSON structuré."""
        nodes_set: set[str] = set(entity_ids)
        edges_set: set[tuple[str, str, str]] = set()

        if depth > 0:
            for eid in entity_ids:
                for _, neighbor, data in self._graph.out_edges(eid, data=True):
                    nodes_set.add(neighbor)
                    edges_set.add((eid, neighbor, data.get("type", "")))
                for pred, _, data in self._graph.in_edges(eid, data=True):
                    nodes_set.add(pred)
                    edges_set.add((pred, eid, data.get("type", "")))

        nodes = [
            {
                "id": nid,
                "type": self._graph.nodes[nid].get("type", "unknown"),
                "value": self._graph.nodes[nid].get("value", ""),
                "label": self._graph.nodes[nid].get("label", ""),
                "properties": self._graph.nodes[nid].get("properties", {}),
            }
            for nid in nodes_set
        ]
        edges = [{"source": s, "target": t, "type": etype} for s, t, etype in edges_set]

        return {"nodes": nodes, "edges": edges}

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------
    def export_json(self) -> str:
        """Exporte tout le graphe en JSON."""
        data = {
            "nodes": [
                {
                    "id": nid,
                    "type": self._graph.nodes[nid].get("type", "unknown"),
                    "value": self._graph.nodes[nid].get("value", ""),
                    "label": self._graph.nodes[nid].get("label", ""),
                    "properties": self._graph.nodes[nid].get("properties", {}),
                    "sources": self._graph.nodes[nid].get("sources", []),
                }
                for nid in self._graph.nodes
            ],
            "edges": [
                {
                    "source": s,
                    "target": t,
                    "type": data.get("type", "related_to"),
                    "confidence": data.get("confidence", 1.0),
                }
                for s, t, data in self._graph.edges(data=True)
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def export_cytoscape(self) -> dict:
        """Exporte au format Cytoscape.js."""
        elements: list[dict] = []

        for nid in self._graph.nodes:
            node = self._graph.nodes[nid]
            elements.append(
                {
                    "data": {
                        "id": nid,
                        "label": node.get("label", node.get("value", "")),
                        "type": node.get("type", "unknown"),
                        "value": node.get("value", ""),
                    },
                    "classes": node.get("type", "unknown"),
                },
            )

        for s, t, data in self._graph.edges(data=True):
            elements.append(
                {
                    "data": {
                        "id": f"{s}_{t}_{data.get('type', '')}",
                        "source": s,
                        "target": t,
                        "label": data.get("type", "related_to"),
                        "confidence": data.get("confidence", 1.0),
                    },
                },
            )

        return {"elements": elements}

    def export_sigmajs(self) -> dict:
        """Exporte au format Sigma.js."""
        nodes = [
            {
                "key": nid,
                "attributes": {
                    "label": self._graph.nodes[nid].get("label", ""),
                    "type": self._graph.nodes[nid].get("type", "unknown"),
                    "size": 5,
                },
            }
            for nid in self._graph.nodes
        ]
        edges = [
            {
                "key": f"{s}_{t}_{data.get('type', '')}",
                "source": s,
                "target": t,
                "attributes": {
                    "label": data.get("type", "related_to"),
                },
            }
            for s, t, data in self._graph.edges(data=True)
        ]
        return {"nodes": nodes, "edges": edges}

    def clear(self) -> None:
        """Vide le graphe."""
        self._graph.clear()
        self._entity_index.clear()
