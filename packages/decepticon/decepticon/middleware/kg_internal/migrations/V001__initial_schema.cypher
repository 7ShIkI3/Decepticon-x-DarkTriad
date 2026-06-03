-- KG schema v001 — engagement-scoped composite uniqueness constraints.
--
-- Every canonical node label gets a unique constraint on
-- (key, engagement) so the same key in two different engagements is
-- two nodes (multi-tenant invariant) and the same key in the same
-- engagement is one node (idempotent MERGE for record_observations).
--
-- Plugin-supplied labels not listed here are unconstrained at the
-- schema level; KGStore.record_observations enforces the dedup key
-- application-side.

CREATE CONSTRAINT host_key_engagement IF NOT EXISTS
  FOR (n:Host) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT network_key_engagement IF NOT EXISTS
  FOR (n:Network) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT domain_key_engagement IF NOT EXISTS
  FOR (n:Domain) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT service_key_engagement IF NOT EXISTS
  FOR (n:Service) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT url_key_engagement IF NOT EXISTS
  FOR (n:URL) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT cloud_resource_key_engagement IF NOT EXISTS
  FOR (n:CloudResource) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT container_key_engagement IF NOT EXISTS
  FOR (n:Container) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT user_key_engagement IF NOT EXISTS
  FOR (n:User) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT group_key_engagement IF NOT EXISTS
  FOR (n:Group) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT credential_key_engagement IF NOT EXISTS
  FOR (n:Credential) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT secret_key_engagement IF NOT EXISTS
  FOR (n:Secret) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT session_key_engagement IF NOT EXISTS
  FOR (n:Session) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT vulnerability_key_engagement IF NOT EXISTS
  FOR (n:Vulnerability) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT cve_key_engagement IF NOT EXISTS
  FOR (n:CVE) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT misconfiguration_key_engagement IF NOT EXISTS
  FOR (n:Misconfiguration) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT weakness_key_engagement IF NOT EXISTS
  FOR (n:Weakness) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT repository_key_engagement IF NOT EXISTS
  FOR (n:Repository) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT source_file_key_engagement IF NOT EXISTS
  FOR (n:SourceFile) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT code_location_key_engagement IF NOT EXISTS
  FOR (n:CodeLocation) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT contract_key_engagement IF NOT EXISTS
  FOR (n:Contract) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT technique_key_engagement IF NOT EXISTS
  FOR (n:Technique) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT entrypoint_key_engagement IF NOT EXISTS
  FOR (n:Entrypoint) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT crown_jewel_key_engagement IF NOT EXISTS
  FOR (n:CrownJewel) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT attack_path_key_engagement IF NOT EXISTS
  FOR (n:AttackPath) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT finding_key_engagement IF NOT EXISTS
  FOR (n:Finding) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT candidate_key_engagement IF NOT EXISTS
  FOR (n:Candidate) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT hypothesis_key_engagement IF NOT EXISTS
  FOR (n:Hypothesis) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT patch_key_engagement IF NOT EXISTS
  FOR (n:Patch) REQUIRE (n.key, n.engagement) IS UNIQUE;

CREATE CONSTRAINT detection_fired_key_engagement IF NOT EXISTS
  FOR (n:DetectionFired) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT defense_action_key_engagement IF NOT EXISTS
  FOR (n:DefenseAction) REQUIRE (n.key, n.engagement) IS UNIQUE;

-- MigrationLog tracks applied schema versions so a re-running container
-- skips already-applied migrations. Single-property uniqueness on name.
CREATE CONSTRAINT migration_log_name IF NOT EXISTS
  FOR (n:MigrationLog) REQUIRE n.name IS UNIQUE;
