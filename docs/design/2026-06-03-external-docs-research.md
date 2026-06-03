# KG Middleware Redesign — External Docs Research

- **Date:** 2026-06-03
- **Researcher:** document-specialist agent
- **Purpose:** External API/framework reference research to ground the KGMiddleware implementation
- **Feeds into:** `docs/design/2026-06-03-kg-middleware-redesign.md`
- **Prior art:** `docs/design/neo4j-research-notes.md` (13 topics, 1020 lines — Neo4j-specific findings; not repeated here)

---

## Topic 1 — LangChain `AgentMiddleware`: Latest Official API

**Source:** https://docs.langchain.com/oss/python/langchain/middleware/custom (accessed 2026-06-03)
**Reference API:** https://reference.langchain.com/python/langchain/middleware (accessed 2026-06-03)
**Version:** langchain v1.x (released 2025; middleware system added in v1.0.0a14)

### 1.1 Lifecycle hooks — complete set

There are two hook styles. Both are supported in `AgentMiddleware` subclasses and as standalone decorators.

**Node-style hooks** — run sequentially at fixed execution points; return `dict[str, Any] | None` (dict is merged into agent state via graph reducers; `None` means no-op):

| Hook | Timing | Fires |
|---|---|---|
| `before_agent` | Before agent starts | Once per invocation |
| `before_model` | Before each model call | Every model call |
| `after_model` | After each model response | Every model call |
| `after_agent` | After agent completes | Once per invocation |

All node-style hooks share the signature:
```python
def hook_name(self, state: AgentState, runtime: Runtime) -> dict[str, Any] | None
```

To return a jump instruction, include `"jump_to": "end"` in the returned dict (requires `@hook_config(can_jump_to=["end"])` annotation on the method).

**Wrap-style hooks** — nested wrappers; the first middleware in the stack wraps all others:

```python
def wrap_model_call(
    self,
    request: ModelRequest,
    handler: Callable[[ModelRequest], ModelResponse],
) -> ModelResponse | ExtendedModelResponse

def wrap_tool_call(
    self,
    request: ToolCallRequest,
    handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
) -> ToolMessage | Command[Any]
```

`request.override(model=..., tools=...)` lets wrap hooks substitute a different model or tool subset without replacing the handler.

Execution order: `before_*` hooks first-to-last; `after_*` hooks last-to-first (reverse stack); `wrap_*` hooks nested (first middleware is the outermost wrapper).

Async counterparts exist for all hooks: `abefore_agent`, `abefore_model`, `aafter_model`, `aafter_agent`, `awrap_model_call`, `awrap_tool_call`.

### 1.2 `self.tools` — how tools merge at `create_agent` time

`AgentMiddleware` subclasses may declare a `tools` class attribute (a tuple of tool objects). The agent factory reads this attribute **at compile time** (when `create_agent` is called) and merges the middleware's tools into the agent's tool list alongside the tools passed explicitly. All tools must be registered upfront at `create_agent` time; `wrap_model_call` can then filter down to a subset at runtime via `request.override(tools=relevant_subset)`.

```python
class KGMiddleware(AgentMiddleware):
    state_schema = KGState
    tools = ()  # populated dynamically in __init__ via build_kg_tools()

    def __init__(self, *, store, enabled_tools):
        super().__init__()
        # tools must be reassigned on instance, not class, for dynamic builds:
        self.tools = build_kg_tools(store, enabled_tools)
```

The factory also reads `state_schema` and `transformers` class attributes at compile time.

### 1.3 `state_schema` — merging with `AgentState`

Declare a `TypedDict` subclass of `AgentState` with `NotRequired` fields, assign it to `state_schema`:

```python
from langchain.agents.middleware import AgentState, AgentMiddleware
from typing_extensions import NotRequired
from typing import Any

class KGState(AgentState):
    kg_context: NotRequired[dict]          # active subgraph for this turn
    kg_ingest_count: NotRequired[int]      # writes this session

class KGMiddleware(AgentMiddleware[KGState]):
    state_schema = KGState
```

Custom fields become available in all hooks and in any tool that receives `InjectedState`.

### 1.4 `InjectedState` and `InjectedToolCallId` — import paths and typing pattern

**`InjectedState`** lives in `langgraph.prebuilt` (not `langchain_core`):

```python
from langgraph.prebuilt import InjectedState
from typing import Annotated

@tool
def kg_query(
    query: str,
    state: Annotated[dict, InjectedState],          # full state
    # or a specific field:
    kg_context: Annotated[dict, InjectedState("kg_context")],
) -> str:
    ...
```

Injected parameters are invisible to the LLM's tool-calling schema. `ToolNode` handles injection automatically.

**`InjectedToolCallId`** lives in `langchain_core.tools`:

```python
from langchain_core.tools import InjectedToolCallId
from typing import Annotated

@tool
def kg_ingest(
    scanner_kind: str,
    path: str,
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> ToolMessage:
    ...
```

**Known issue (as of 2025):** There are open GitHub issues (langchain-ai/langchain #31688, #32729) reporting that `InjectedState` / `InjectedToolCallId` parameters must be explicitly included in `args_schema` for injection to work correctly, and that if the LLM generates a value for an injected parameter the injection silently uses the LLM-generated value. The current recommendation from the LangChain team is to use `ToolRuntime` as the single interface to state, context, store, and execution metadata for new code.

### 1.5 Tool-specific middleware scoping

No `tools=[]` per-middleware scoping parameter was found in the official docs. Tool scoping is achieved at runtime via `wrap_model_call` + `request.override(tools=subset)`. All tools from all middleware are registered at `create_agent` time; runtime filtering is the mechanism for per-middleware scoping.

### 1.6 Upgrade guide / release notes

The middleware system shipped with `langchain v1.0.0`. Migration guide at https://docs.langchain.com/oss/python/migrate/langchain-v1. The `state_schema` pattern for middleware is documented there alongside `wrap_model_call` examples.

---

## Topic 2 — LangGraph `BaseStore`: Can It Host Neo4j?

**Source:** https://reference.langchain.com/python/langgraph/config/get_store (accessed 2026-06-03)
**Source:** https://docs.langchain.com/oss/python/langgraph/add-memory (accessed 2026-06-03)
**Version:** langgraph 0.4.x+

### 2.1 `BaseStore` abstract interface

The `BaseStore` interface exposes five operations: `put`, `get`, `search`, `delete`, `list_namespaces`. The `search` method supports optional vector-based semantic search when the store is configured with an `index` (embedding function + dimension + fields to embed). `get_store()` returns a `BaseStore` from the current runtime context.

```python
# Confirmed method signatures from reference docs and usage examples:
store.put(namespace: tuple[str, ...], key: str, value: dict) -> None
store.get(namespace: tuple[str, ...], key: str) -> Item | None
store.search(namespace: tuple[str, ...], *, query: str, limit: int = 10) -> list[Item]
store.delete(namespace: tuple[str, ...], key: str) -> None
```

`StoreConfig.index` configures the vector index: `embed` (embedding function), `dims` (int), `fields` (list of JSON keys to embed).

### 2.2 Existing backend implementations

- `InMemoryStore` — ephemeral, in-process, no persistence.
- `PostgresStore` / `AsyncPostgresStore` — relational backend with optional vector support (pgvector).
- `OracleStore` — demonstrated in docs using `init_embeddings` for semantic search.
- `RedisStore` — via `langgraph-redis` package (separate install).

Third-party `Neo4jStore(BaseStore)` implementations exist (e.g., `langchain-neo4j` integration package) but are not part of the `langgraph` core distribution.

### 2.3 Can `Neo4jStore` implement `BaseStore`? What gaps exist?

**Feasible for key-value-like access:** `put`/`get`/`delete`/`search` can map to Neo4j MERGE/MATCH/DELETE + full-text or vector index search. Neo4j's native vector index (available since 5.13) maps well to `BaseStore`'s vector search interface.

**Structural gaps that prevent conformance for an attack graph:**

1. **No edge/relationship primitive.** `BaseStore` models `Item` objects (key → dict value), not graph edges. Storing attack-path relationships — `(:Host)-[:CAN_EXPLOIT]->(:Service)` — has no natural representation in `put`/`get`. A `BaseStore` conforming implementation can only store node properties as dicts; edges become invisible.
2. **No Cypher passthrough.** `BaseStore.search` is a semantic/keyword search over stored values, not a graph traversal query. Decepticon's `kg_query_paths` tool (Dijkstra shortest path, reachability subgraphs) cannot be expressed as a `search(namespace, query=str)` call.
3. **No batch transaction semantics.** `put` is single-item; atomic batch upserts across node + edge sets require multi-statement Cypher transactions.

**Conclusion:** Implementing `BaseStore` for Neo4j is feasible for the scalar-memory use case (storing agent findings as blobs) but cannot express graph-native operations. The KGMiddleware should maintain a **separate `KGStore`** (wrapping `neo4j.AsyncDriver`) alongside the LangGraph store, rather than trying to conform to `BaseStore`. The existing `Neo4jStore` in `packages/decepticon/decepticon/tools/research/neo4j_store.py` (787 LOC) is the right foundation.

---

## Topic 3 — DeepAgents Middleware System

**Source:** https://docs.langchain.com/oss/python/deepagents/middleware (accessed 2026-06-03)
**Source:** https://reference.langchain.com/python/deepagents/middleware/filesystem/FilesystemMiddleware (accessed 2026-06-03)
**Source:** https://github.com/langchain-ai/deepagents (accessed 2026-06-03)
**Version:** deepagents (latest, 2025-2026)

### 3.1 `MemoryMiddleware`

`MemoryMiddleware` is a lightweight middleware that loads agent memory from `AGENTS.md` files (markdown skill catalogs) at `before_agent` time. It does not use the LangGraph `BaseStore` interface — it reads from the filesystem via the agent's backend. Decepticon already has an equivalent mechanism via its skill catalog system (markdown files in `packages/decepticon/decepticon/skills/`).

### 3.2 `FilesystemMiddleware`

The flagship DeepAgents middleware. Full constructor signature:

```python
FilesystemMiddleware(
    *,
    backend: BACKEND_TYPES | None = None,       # defaults to StateBackend (ephemeral)
    system_prompt: str | None = None,
    custom_tool_descriptions: Mapping[str, str] | None = None,
    tool_token_limit_before_evict: int | None = 20000,
    human_message_token_limit_before_evict: int | None = 50000,
    max_execute_timeout: int = 3600,
    _permissions: list[FilesystemPermission] | None = None,
)
```

Exposed tools: `ls`, `read_file`, `write_file`, `edit_file`, `glob`, `grep` (+ `execute` when a sandbox-compatible backend is provided).

Storage model: dual-tier via `CompositeBackend`. `StateBackend` handles short-term in-state storage; `StoreBackend` routes paths prefixed with `/memories/` to persistent cross-thread storage (any LangGraph `BaseStore` implementation). Extends `AgentMiddleware` and implements `wrap_model_call`, `awrap_model_call`, `wrap_tool_call`, `awrap_tool_call`.

**Intersection with Decepticon:** Decepticon agents already write `findings/`, `recon/` files via `DockerSandbox.execute_tmux()`. `FilesystemMiddleware` uses a different execution surface (its own `backend`). These are parallel systems — `FilesystemMiddleware` manages an in-graph virtual filesystem; Decepticon's sandbox writes to the real container filesystem. They should not be merged without intentional design. The `KGMiddleware` is not a `FilesystemMiddleware` replacement.

### 3.3 `SubAgentMiddleware`

Configures subagent dispatch. Subagents are defined with: `name`, `description`, `system_prompt`, `tools`, optional `model`, optional `middleware`. A general-purpose subagent always exists for context-isolation tasks. Subagents can be either simple config objects or `CompiledSubAgent` wrappers around prebuilt LangGraph graphs.

**Relevance to Decepticon's 16-specialist architecture:** Decepticon's specialists are spawned with clean context windows via `create_agent` factory calls in `packages/decepticon/decepticon/agents/`. These are not `SubAgentMiddleware`-managed subagents — they are peer agents in the graph, not children of a supervisor middleware. The `SubAgentMiddleware` pattern is for a different architecture (hierarchical supervisor with delegated subtasks). No migration needed.

### 3.4 Composition of DeepAgents middleware with custom `AgentMiddleware`

Yes — DeepAgents is "built entirely on `create_agent`." `create_deep_agent` automatically attaches `TodoListMiddleware`, `FilesystemMiddleware`, and `SubAgentMiddleware`, but a caller can pass additional `middleware=[..., KGMiddleware()]` items alongside the built-in stack. Custom `AgentMiddleware` subclasses (including `KGMiddleware`) compose cleanly with DeepAgents built-ins using the standard middleware list ordering.

---

## Topic 4 — Neo4j Python Driver: `execute_write` / Transaction Patterns

**Source:** https://github.com/neo4j/neo4j-python-driver/blob/6.x/docs/source/api.md (accessed 2026-06-03)
**Source:** https://neo4j.com/docs/cypher-manual/current/indexes/syntax/ (accessed 2026-06-03)
**Source:** https://neo4j.com/docs/apoc/current/overview/apoc.algo/apoc.algo.dijkstra/ (accessed 2026-06-03)
**Version:** neo4j Python driver 6.x; Neo4j 5.24 CE; APOC 5.26 (current LTS)

### 4.1 `execute_write` / `execute_read` — per-operation pattern

Managed transactions are the recommended pattern (confirms and extends neo4j-research-notes §1 and §2):

```python
def write_node_tx(tx, node_id: str, props: dict) -> str:
    result = tx.run(
        "MERGE (n:Host {id: $id}) SET n += $props RETURN n.id AS id",
        id=node_id, props=props
    )
    return result.single()["id"]

with driver.session(database="neo4j") as session:
    node_id = session.execute_write(write_node_tx, node_id, props)
```

Results **must be fully consumed inside the transaction function**. Returning a live result object breaks retry guarantees and connection management. Only aggregate or status values should be returned from the function.

Async variant:
```python
async with driver.session() as session:
    node_id = await session.execute_write(write_node_tx, node_id, props)
```

### 4.2 Retry semantics on `DeadlockDetected`

`session.execute_write` automatically retries on any `Neo.TransientError` — including `Neo.TransientError.Transaction.DeadlockDetected` — within the configured timeout. No manual retry logic is needed. This is explicitly documented in the driver API. The driver calls the transaction function "one or more times, within a configurable time limit, until it succeeds." Explicit `begin_transaction()` / `commit()` patterns do NOT get automatic retry.

### 4.3 Composite range index — verified Cypher syntax for Neo4j 5.24

```cypher
CREATE INDEX index_name [IF NOT EXISTS]
FOR (n:Label)
ON (n.property1, n.property2)
```

Example from official docs:
```cypher
CREATE INDEX composite_range_node_index_name FOR (n:Person) ON (n.age, n.country)
```

The `RANGE` keyword is optional (range is the default index type). The `IF NOT EXISTS` clause prevents errors on re-application.

For Decepticon's schema (e.g., Host nodes by engagement + ip):
```cypher
CREATE INDEX host_scope_idx IF NOT EXISTS
FOR (n:Host) ON (n.engagement_id, n.ip)
```

Source: https://neo4j.com/docs/cypher-manual/current/indexes/syntax/

### 4.4 Vector index syntax (Neo4j 5.13+)

```cypher
CREATE VECTOR INDEX index_name [IF NOT EXISTS]
FOR (n:Label)
ON (n.embedding_property)
OPTIONS {
  indexConfig: {
    `vector.dimensions`: 1536,
    `vector.similarity_function`: 'cosine'
  }
}
```

Dimensions should always be specified explicitly. Supported similarity functions: `cosine`, `euclidean`. Available since Neo4j 5.13; no Enterprise Edition restriction on the index creation itself.

Source: https://neo4j.com/docs/cypher-manual/current/indexes/syntax/

### 4.5 APOC vs GDS for Dijkstra — recommendation

**`apoc.algo.dijkstra` (APOC Core)**

Signature:
```
apoc.algo.dijkstra(startNode, endNode, relTypesAndDirections, weightPropertyName
                   [, defaultWeight, numberOfWantedPaths]) :: (path, weight)
```

Available in APOC Core (not Extended), which ships as part of Neo4j 5.x community builds. Returns `(path, weight)` pairs directly in Cypher without requiring a graph projection step. The current APOC LTS is 5.26. The procedure `apoc.algo.dijkstra` is documented in APOC Core (not APOC Extended), which means it is available in Community Edition.

**GDS `gds.shortestPath.dijkstra`**

Requires: (1) GDS plugin installed separately, (2) a named graph projection created first (`gds.graph.project`), (3) a dedicated algorithm call. GDS is recommended for production analytic workloads requiring optimized performance, integration with other graph algorithms, or parallelism. GDS does NOT ship with Neo4j Community Edition by default — it requires a separate install and a GDS license for production.

**Verdict for Decepticon (5.24 CE, real-time attack path queries):**
Keep `apoc.algo.dijkstra` as used in `chain.py`. APOC Core is available in 5.24 CE, returns paths in-query without a projection step, and is appropriate for the query-time (not analytic-batch) pattern Decepticon uses. GDS would require a separate license and a graph projection that must be maintained in sync with live writes — overkill for attack-path lookup during agent turns.

---

## Topic 5 — Reference Implementations

### 5.1 BloodHound CE (SpecterOps) — 2026 patterns

**Sources:**
- https://bloodhound.specterops.io/get-started/custom-installation (accessed 2026-06-03)
- https://specterops.io/blog/2026/04/15/whats-new-in-the-bloodhound-query-library-byol-opengraph-multi-server-and-more/ (accessed 2026-06-03)

BloodHound CE architecture as of 2026: Go-based REST API backend + embedded React/Sigma.js frontend + PostgreSQL application database + Neo4j graph database. The dual-database pattern is notable — PostgreSQL for application state (users, jobs, configs), Neo4j exclusively for the attack graph.

**Multi-writer handling:** BloodHound CE does not expose its internal multi-writer Cypher patterns publicly. Based on architecture docs, data ingestion is handled by a single ingestor service pipeline (not concurrent agent writes). This is architecturally different from Decepticon where 16 agents write concurrently.

**Schema migration (2026):** The Query Library is deprecating `system_tags`-based conditions in favor of label-based `Privilege Zones` (deadline July 2026, requires BH v2026.03.23+). This is a UI/query migration, not a Neo4j schema migration.

**Programmatic API:** BH CE exposes a REST HTTP API that can be used to drive queries programmatically. The `BloodHound Query Library` (queries.specterops.io, YAML format) was released June 2025. **Bring Your Own Library (BYOL)** (April 2026) allows pointing the query UI at a custom JSON endpoint following the query schema. No formal agent SDK is documented; Decepticon's attack-graph queries are better served by direct Cypher than by proxying through the BH API.

**OpenGraph (2026):** Extends BloodHound beyond AD/Azure to arbitrary identity platforms (Jamf, GitHub, Okta, custom). This is directly relevant to Decepticon's multi-cloud graph model.

### 5.2 Cartography (Lyft / CNCF) — incremental MERGE pattern

**Source:** https://github.com/cartography-cncf/cartography (accessed 2026-06-03)
**Source:** https://lyft.github.io/cartography/usage/schema.html (accessed 2026-06-03)

Cartography is the most mature open-source reference for incremental Neo4j sync from scanner adapters. Its sync pattern is directly applicable to Decepticon's scanner-to-graph ingestion:

**Core pattern:**

1. **`update_tag`** — a timestamp integer passed to every sync function. All MERGE statements `SET n.lastupdated = $update_tag` on every touched node.
2. **`firstseen`** — set only on first MERGE via `ON CREATE SET n.firstseen = $update_tag`.
3. **Stale cleanup** — after a full sync pass, a cleanup query deletes nodes where `n.lastupdated < $update_tag` (i.e., not seen in this run). Relationships get the same treatment.
4. **MERGE on stable identity key** — MERGE matches on the node's canonical identity property (e.g., ARN for AWS, IP+port for network assets). Properties are updated via `SET n += $props`.

```cypher
-- Cartography-style upsert
MERGE (h:Host {id: $id})
ON CREATE SET h.firstseen = $update_tag
SET h.lastupdated = $update_tag,
    h.ip = $ip,
    h.engagement_id = $engagement_id
```

**Duplicate-on-rescan handling:** Because MERGE is idempotent on the identity key, re-scanning the same asset updates in place. No deduplication logic needed in Python; Cypher handles it.

**For Decepticon:** The `kg_ingest` dispatcher should pass `update_tag = int(time.time())` to all write transaction functions. Stale-node cleanup can run as a `before_agent` hook in `KGMiddleware`, scoped to `engagement_id` (never clean across engagements).

### 5.3 Graphiti (Zep) — bi-temporal provenance model

**Sources:**
- https://help.getzep.com/graphiti/getting-started/overview (accessed 2026-06-03)
- https://arxiv.org/abs/2501.13956 — "Zep: A Temporal Knowledge Graph Architecture for Agent Memory" (January 2025)
- https://github.com/getzep/graphiti (accessed 2026-06-03)

Graphiti is a temporally aware knowledge graph engine from Zep AI, production-grade as of 2025. Key architectural concepts:

**Bi-temporal model:** Every graph edge carries four timestamps:
- `t_created` / `t_expired` — when the fact was recorded/invalidated in the system (ingestion time)
- `t_valid` / `t_invalid` — when the fact was actually true in the world (event time)

Contradictions cause edge `t_expired` to be set rather than deletion, preserving history.

**Episode subgraph:** Raw inputs (agent messages, tool outputs, structured data) are stored as `Episode` nodes. Every derived entity and relationship traces back to the episodes that produced it, giving full lineage from derived fact to source.

**Community subgraphs:** Related entities are clustered into `Community` nodes for higher-level summarization and search.

**Relevance for Decepticon provenance tracking:** Graphiti's episode → entity provenance model directly addresses the question "which agent in which OPPLAN step created which node?" Decepticon could borrow this by:
- Adding `created_by` (agent name string), `created_at_step` (OPPLAN phase), and `episode_id` (UUID linking to the raw tool output) properties on every `Host`, `Service`, `Finding` node.
- Setting `lastupdated_by` on each MERGE write.
- Not implementing the full Graphiti bi-temporal model (it requires LLM calls for conflict resolution) — but the property schema is worth adopting.

### 5.4 Cognee — ECL pipeline customization

**Source:** https://github.com/topoteretes/cognee (accessed indirectly via search; direct fetch not performed)

Cognee implements an Extract-Chunk-Load (ECL) pipeline for building knowledge graphs from unstructured documents. Its plugin architecture allows custom `DataPoint` types and custom graph transformation steps. The pattern is relevant for Decepticon plugin authors who want to add new scanner adapters (e.g., a BloodHound ingestor or a custom recon tool output parser) that feed into the attack graph.

The key Cognee pattern for Decepticon: each scanner adapter is a pure function `(raw_output: str) -> list[DataPoint]` where `DataPoint` is a Pydantic model. The `kg_ingest(scanner_kind, path)` dispatcher maps `scanner_kind` to a registered adapter function. This mirrors Decepticon's planned collapsing of 12 `kg_ingest_*` tools into a single dispatcher.

---

## Implications for KGMiddleware Design

1. **Use `state_schema = KGState` with `NotRequired` fields; populate `self.tools` dynamically in `__init__`.** The `AgentMiddleware` compile-time protocol reads both attributes from the instance. `KGState` should add `kg_context: NotRequired[dict]` (active subgraph snapshot for the current turn) and `kg_ingest_count: NotRequired[int]`. Source: LangChain middleware docs, confirmed `state_schema` merging behavior.

2. **Do NOT implement `BaseStore` for Neo4j — the `put`/`get` model cannot express edges.** Maintain the existing `Neo4jStore` (787 LOC in `neo4j_store.py`) as the KGMiddleware's private store. The LangGraph `BaseStore` (passed via `graph.compile(store=...)`) is for scalar memory blobs only; the attack graph requires a separate graph-native API. These are parallel stores with distinct purposes.

3. **Use `InjectedState` from `langgraph.prebuilt` (not `langchain_core`) for tools that need graph context.** Pattern: `state: Annotated[dict, InjectedState("kg_context")]`. Flag the open injection reliability issues (langchain-ai/langchain #31688, #32729) — consider `ToolRuntime` as the forward-compatible alternative once it stabilizes.

4. **Neo4j 5.24 composite range index syntax verified:** `CREATE INDEX name IF NOT EXISTS FOR (n:Label) ON (n.a, n.b)`. Use `IF NOT EXISTS` in migration scripts; RANGE is the default so the keyword is optional. Vector index: `CREATE VECTOR INDEX name IF NOT EXISTS FOR (n:Label) ON (n.embedding) OPTIONS { indexConfig: { \`vector.dimensions\`: 1536, \`vector.similarity_function\`: 'cosine' } }`. Available since 5.13, no EE requirement.

5. **Keep `apoc.algo.dijkstra` (APOC Core) for attack-path queries; do not migrate to GDS.** APOC Core ships with Neo4j 5.24 CE, requires no graph projection, and returns paths inline in Cypher. GDS requires a separate license and a maintained graph projection — both are unsuitable for Decepticon's real-time query-during-agent-turn pattern.

6. **Adopt Cartography's `update_tag` + `lastupdated` + `firstseen` pattern for all `kg_ingest` writes.** Pass `update_tag = int(time.time())` to every `execute_write` transaction function. `firstseen` is set `ON CREATE`. Add a `KGMiddleware.before_agent` hook that runs stale-node cleanup (`lastupdated < engagement_start_ts`) scoped to `engagement_id`. This eliminates ghost nodes from partial scans without complex deduplication logic.

7. **Borrow Graphiti's provenance property schema without adopting its full bi-temporal model.** Add `created_by: str` (agent name), `created_at_phase: str` (OPPLAN phase label), and `source_episode_id: str` (UUID of the raw tool output that triggered the write) to all node MERGE `SET` clauses. This gives audit-quality lineage ("finding X was created by ad_operator in LATERAL_MOVEMENT phase, from nmap output abc123") without requiring LLM conflict resolution or the four-timestamp edge model.

---

*Research completed 2026-06-03. All URLs accessed on this date. LangChain middleware system is at v1.x; Neo4j Python driver at 6.x; APOC at 5.26 LTS. Re-verify InjectedState injection reliability issues before finalizing tool implementations.*
