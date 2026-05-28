import { requireAuth, AuthError } from "@/lib/auth-bridge";
import { prisma } from "@/lib/prisma";
import { NextRequest, NextResponse } from "next/server";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  // 1. Auth - returns 401 if not authorized.
  let userId: string;
  try {
    ({ userId } = await requireAuth());
  } catch (e) {
    if (e instanceof AuthError) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    throw e;
  }

  // 2. Engagement ownership check via Prisma. Previous version of this
  //    route consumed `params` then ran `MATCH (n) OPTIONAL MATCH (n)-[r]->(m)`
  //    against the full Neo4j graph, which was a cross-engagement data leak
  //    (any authenticated user could read any other engagement's findings).
  const { id } = await params;
  const engagement = await prisma.engagement.findFirst({
    where: { id, userId },
  });
  if (!engagement) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  // 3. Neo4j connection - require explicit password, do NOT fall back to
  //    the documented public default. A misconfigured deployment should
  //    fail loud, not serve graph data with the well-known password.
  const neo4jUri = process.env.NEO4J_URI ?? "bolt://neo4j:7687";
  const neo4jUser = process.env.NEO4J_USER ?? "neo4j";
  const neo4jPassword = process.env.NEO4J_PASSWORD;
  if (!neo4jPassword || neo4jPassword === "decepticon-graph") {
    return NextResponse.json(
      {
        error:
          "NEO4J_PASSWORD missing or set to the public default. Refusing to query the graph. " +
          "See docs/security/neo4j-hardening.md.",
      },
      { status: 503 },
    );
  }

  try {
    const neo4j = await import("neo4j-driver");
    const driver = neo4j.default.driver(
      neo4jUri,
      neo4j.default.auth.basic(neo4jUser, neo4jPassword),
    );
    const session_db = driver.session({ database: "neo4j" });

    try {
      // 4. Engagement-scoped query. Only nodes that carry an
      //    `engagement` property matching the engagement name are
      //    returned. Edges are filtered to those connecting two
      //    in-engagement nodes. New writes tag nodes via
      //    decepticon.tools.research._engagement_scope; legacy
      //    nodes without the property surface as empty until the
      //    operator runs the migration (see docs/security/neo4j-hardening.md).
      const cypher = `
        MATCH (n)
        WHERE n.engagement = $engagement
        OPTIONAL MATCH (n)-[r]->(m)
        WHERE m.engagement = $engagement
        RETURN
          collect(DISTINCT {
            id: elementId(n),
            labels: labels(n),
            properties: properties(n)
          }) AS nodes,
          collect(DISTINCT CASE WHEN r IS NOT NULL THEN {
            id: elementId(r),
            source: elementId(n),
            target: elementId(m),
            type: type(r),
            properties: properties(r)
          } END) AS edges
      `;
      const result = await session_db.run(cypher, { engagement: engagement.name });

      const record = result.records[0];
      const rawNodes = record?.get("nodes") ?? [];
      const rawEdges = (record?.get("edges") ?? []).filter(Boolean);

      interface Neo4jNode {
        id: string;
        labels: string[];
        properties: Record<string, unknown>;
      }
      interface Neo4jEdge {
        id: string;
        source: string;
        target: string;
        type: string;
        properties: Record<string, unknown>;
      }

      // Transform for React Flow
      const nodes = (rawNodes as Neo4jNode[]).map((n, i) => ({
        id: n.id,
        type: "custom",
        data: {
          label: (n.properties.hostname ?? n.properties.ip ?? n.properties.name ?? n.properties.title ?? n.properties.cve_id ?? n.properties.username ?? n.labels[0]) as string,
          nodeType: n.labels[0],
          properties: n.properties,
        },
        position: { x: (i % 6) * 200, y: Math.floor(i / 6) * 150 },
      }));

      const nodeIds = new Set(nodes.map((n) => n.id));
      const edges = (rawEdges as Neo4jEdge[])
        .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
        .map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.type,
          data: e.properties,
        }));

      return NextResponse.json({ nodes, edges });
    } finally {
      await session_db.close();
      await driver.close();
    }
  } catch (err: unknown) {
    console.error("Neo4j query error:", err instanceof Error ? err.message : err);
    return NextResponse.json(
      { error: "Knowledge graph unavailable", nodes: [], edges: [] },
      { status: 503 }
    );
  }
}
