"""SemanticGraphSearch — interrogation du graphe NetworkX en langage naturel via l'IA.

Transforme des questions comme "Montre-moi tous les sous-domaines qui hébergent
un formulaire de connexion et qui sont liés à une IP en Russie" en opérations
sur le graphe.
"""

import json
from dataclasses import dataclass, field

from decepticon.navmax.core.logging import get_logger

logger = get_logger(__name__)


# ── System Prompt ──────────────────────────────────────────────

SEMANTIC_GRAPH_SYSTEM = """You are a graph query translator for NavMAX OSINT.
The knowledge graph contains entities (domains, IPs, services, certificates, etc.)
connected by relationships (resolves_to, hosts, uses_cert, related_to, etc.).

Given a natural language question, translate it into graph operations.

Available entity types: domain, ip_address, service, certificate, email, organization
Available relationship types: resolves_to, hosts, uses_cert, belongs_to, related_to

GRAPH OPERATIONS (output as JSON):
{
  "operations": [
    {
      "type": "find_entities",
      "entity_type": "domain",
      "filters": {"value_contains": "admin"}
    },
    {
      "type": "get_neighbors",
      "entity_id": "<from previous result>",
      "depth": 1,
      "relation_filter": "hosts"
    },
    {
      "type": "search",
      "query": "login",
      "entity_type": "service"
    }
  ],
  "explanation": "What this query does in plain language"
}

Output ONLY valid JSON — no markdown, no explanations."""


# ── Data Models ────────────────────────────────────────────────


@dataclass
class GraphQueryResult:
    """Résultat d'une requête sémantique sur le graphe."""

    question: str
    explanation: str
    entities: list[dict] = field(default_factory=list)
    relations: list[dict] = field(default_factory=list)
    raw_plan: dict | None = None
    error: str | None = None

    @property
    def count(self) -> int:
        return len(self.entities)


# ── Semantic Graph Search ─────────────────────────────────────


class SemanticGraphSearch:
    """Recherche sémantique sur le graphe OSINT.

    Usage:
        search = SemanticGraphSearch(graph_engine, ai_engine)
        result = await search.search(
            "Tous les sous-domaines avec un formulaire de login liés à une IP russe"
        )
        for entity in result.entities:
            print(entity["value"])
    """

    def __init__(self, graph_engine, ai_engine) -> None:
        self.graph = graph_engine
        self.ai = ai_engine

    async def search(self, question: str) -> GraphQueryResult:
        """Interroge le graphe en langage naturel.

        Args:
            question: Question en langage naturel

        Returns:
            GraphQueryResult avec entités et relations trouvées

        """
        # Étape 1: Traduire la question en opérations graphe
        try:
            plan = await self._translate(question)
        except Exception as e:
            return GraphQueryResult(
                question=question,
                explanation="Translation failed",
                error=str(e),
            )

        # Étape 2: Exécuter les opérations
        entities, relations = self._execute(plan.get("operations", []))

        # Étape 3: Formater
        return GraphQueryResult(
            question=question,
            explanation=plan.get("explanation", ""),
            entities=entities,
            relations=relations,
            raw_plan=plan,
        )

    async def _translate(self, question: str) -> dict:
        """Traduit la question NL en plan d'opérations graphe."""
        from decepticon.navmax.ai.providers.base import ModelTier

        result = await self.ai.generate(
            prompt=f"Question: {question}\n\nTranslate into graph operations.",
            tier=ModelTier.MEDIUM,
            system=SEMANTIC_GRAPH_SYSTEM,
            temperature=0.2,
            max_tokens=2048,
            json_mode=True,
        )

        # Extraire le JSON
        text = result.text.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        # Find JSON object
        brace = text.find("{")
        if brace >= 0:
            depth = 0
            for i in range(brace, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        text = text[brace : i + 1]
                        break

        return json.loads(text)

    def _execute(self, operations: list[dict]) -> tuple[list[dict], list[dict]]:
        """Exécute les opérations sur le graphe."""
        entities = []
        relations = []
        context: dict[str, list[str]] = {}  # var_name → [entity_ids]

        for i, op in enumerate(operations):
            op_type = op.get("type", "")

            if op_type == "find_entities":
                result = self._op_find(op)
                context[f"result_{i}"] = [e["id"] for e in result]
                entities.extend(result)

            elif op_type == "get_neighbors":
                source_ids = self._resolve_ref(op.get("entity_id", ""), context)
                for eid in source_ids:
                    neighbors = self.graph.get_neighbors(eid, depth=op.get("depth", 1))
                    for entity, rel in neighbors:
                        if hasattr(entity, "id"):
                            entities.append(
                                {
                                    "id": entity.id,
                                    "type": entity.type.value
                                    if hasattr(entity.type, "value")
                                    else str(entity.type),
                                    "value": entity.value
                                    if hasattr(entity, "value")
                                    else str(entity),
                                },
                            )
                        relations.append(
                            {
                                "source": rel.source.value
                                if hasattr(rel.source, "value")
                                else str(rel.source),
                                "target": rel.target.value
                                if hasattr(rel.target, "value")
                                else str(rel.target),
                                "type": rel.type.value
                                if hasattr(rel.type, "value")
                                else str(rel.type),
                            },
                        )

            elif op_type == "search":
                query = op.get("query", "")
                op.get("entity_type")
                # Utiliser la méthode search du graph engine si dispo
                if hasattr(self.graph, "search"):
                    result = self.graph.search(query)
                else:
                    result = self._op_find(op)

                context[f"result_{i}"] = [e["id"] for e in result] if result else []
                entities.extend(result)

        return entities, relations

    def _op_find(self, op: dict) -> list[dict]:
        """Opération find_entities."""
        entity_type = op.get("entity_type")
        filters = op.get("filters", {})

        results = []
        # Parcourir tous les nœuds
        if hasattr(self.graph, "_graph"):
            for nid, data in self.graph._graph.nodes(data=True):
                if entity_type and data.get("type") != entity_type:
                    continue
                if "value_contains" in filters:
                    val = data.get("value", "")
                    if filters["value_contains"].lower() not in val.lower():
                        continue
                results.append(
                    {
                        "id": nid,
                        "type": data.get("type", ""),
                        "value": data.get("value", ""),
                    },
                )
        return results

    def _resolve_ref(self, ref: str, context: dict[str, list[str]]) -> list[str]:
        """Résout une référence (ex: 'result_0') vers des IDs d'entités."""
        if ref in context:
            return context[ref]
        return []
