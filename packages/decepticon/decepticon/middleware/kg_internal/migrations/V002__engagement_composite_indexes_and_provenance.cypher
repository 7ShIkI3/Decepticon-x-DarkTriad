-- KG schema v002 — engagement-scoped composite range indexes and
-- provenance lookups for the Cartography update_tag pattern.

-- High-traffic engagement-scoped read paths from the agent (kg_record
-- + summary block) and from the web dashboard graph view.
CREATE INDEX engagement_host_explored IF NOT EXISTS
  FOR (n:Host) ON (n.engagement, n.explored);
CREATE INDEX engagement_vuln_severity IF NOT EXISTS
  FOR (n:Vulnerability) ON (n.engagement, n.severity);
CREATE INDEX engagement_finding_status IF NOT EXISTS
  FOR (n:Finding) ON (n.engagement, n.status);
CREATE INDEX engagement_entrypoint IF NOT EXISTS
  FOR (n:Entrypoint) ON (n.engagement);
CREATE INDEX engagement_crown_jewel IF NOT EXISTS
  FOR (n:CrownJewel) ON (n.engagement);

-- Provenance lookups — Cartography stale-cleanup sweep and Graphiti-
-- style "which agent created this finding" forensics.
CREATE INDEX vuln_lastupdated IF NOT EXISTS
  FOR (n:Vulnerability) ON (n.engagement, n.lastupdated);
CREATE INDEX vuln_created_by IF NOT EXISTS
  FOR (n:Vulnerability) ON (n.engagement, n.created_by);

-- Future-proof vector index for semantic vulnerability recall (Neo4j
-- 5.13+). The embedding pipeline is opt-in at runtime — schema-only
-- landing here keeps PR-B free of migration noise. The dimension is
-- locked to OpenAI text-embedding-3-small (1536) as the OSS default;
-- enterprise plugins can drop this index and create their own.
CREATE VECTOR INDEX vuln_embedding IF NOT EXISTS
  FOR (n:Vulnerability) ON (n.embedding)
  OPTIONS {
    indexConfig: {
      `vector.dimensions`: 1536,
      `vector.similarity_function`: 'cosine'
    }
  };
