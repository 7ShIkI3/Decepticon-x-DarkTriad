# Getting Started

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose v2
- An LLM provider credential — one of:
  - **Tier-mapped API keys** (works out of the box): Anthropic, OpenAI, Google Gemini, MiniMax, DeepSeek, xAI, Mistral, OpenRouter, Nvidia NIM
  - **Local LLM**: Ollama (`OLLAMA_API_BASE` + `OLLAMA_MODEL`)
  - **Subscription OAuth** (no per-token billing): Claude Max/Pro/Team, ChatGPT Pro/Plus/Team, Gemini Advanced, Microsoft Copilot Pro, xAI SuperGrok, Perplexity Pro
  - **Other providers** (Groq, Cohere, Together, Fireworks, Perplexity API, Azure, AWS Bedrock, Replicate, custom OpenAI-compatible gateway): supported via `DECEPTICON_MODEL` / `DECEPTICON_LITELLM_MODELS` ad-hoc registration

That's it. Everything else runs inside containers.

---

## Install

**One command** (recommended):
```bash
curl -fsSL https://raw.githubusercontent.com/7ShIkI3/Decepticon-x-DarkTriad/main/install.sh | bash
```

**Manual install**:
```bash
git clone https://github.com/7ShIkI3/Decepticon-x-DarkTriad.git ~/.decepticon-darktriad
cd ~/.decepticon-darktriad
cp .env.example .env
# Edit .env → add your API key (DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, etc.)
make smoke
```

The install script or `make smoke` will:
1. Clone the repo to `~/.decepticon-darktriad`
2. Create `.env` from `.env.example`
3. Build all Docker images locally (~5-10 min first time)
4. Start all services (PostgreSQL, LiteLLM, LangGraph, Neo4j, sandbox, web dashboard)

---

## Configure

Edit `~/.decepticon-darktriad/.env` to set your LLM credentials:

```bash
DEEPSEEK_API_KEY=sk-your-key-here      # DeepSeek (default)
# ANTHROPIC_API_KEY=sk-ant-...          # Anthropic
# OPENAI_API_KEY=sk-...                 # OpenAI
# OLLAMA_API_BASE=http://host.docker.internal:11434  # Local Ollama
# OLLAMA_MODEL=qwen3-coder:30b
```

See [Setup Guide](docs/setup-guide.md) for all providers (OAuth, Azure, AWS Bedrock, etc.).

---

## Launch

**Web Dashboard** → `http://localhost:3000`

The dashboard is the primary interface. All agents (including NavMAX Dark Triad) are available from the engagement picker.

**Make targets** (from the install directory):
```bash
cd ~/.decepticon-darktriad
make status          # Show running services
make logs            # Follow LangGraph logs
make logs SVC=litellm  # Follow a specific service
make health          # Health checks (KG + Neo4j + Web)
```

---

## First Real Engagement

1. Open <http://localhost:3000>
2. The **Soundwave** agent interviews you to define the engagement:
   - Target scope (IP range, URL, Git repo, file upload, or local path)
   - Threat actor profile
   - Rules of Engagement (authorized scope, timing, exclusions)
3. Soundwave writes the eight-document engagement bundle (RoE, Threat Profile, CONOPS, Deconfliction, Contact, Data Handling, Abort, Cleanup)
4. The orchestrator builds the OPPLAN from the bundle — you review and approve it
5. The autonomous loop begins — NavMAX Dark Triad agents auto-activate based on target type

> **Important**: Only run Decepticon against systems you own or have explicit written authorization to test. See the disclaimer in the main README.

---

## Stopping Services

```bash
cd ~/.decepticon-darktriad
make clean          # Stop + remove all containers and volumes (resets everything)
# Or just stop without wiping:
docker compose --profile cli down
```

---

## Check Service Status

```bash
cd ~/.decepticon-darktriad
make status          # Show running services
make logs            # Follow LangGraph logs (default)
make logs SVC=litellm  # Follow LiteLLM logs
make health          # KG + Neo4j + Web health checks
```

---

## Next Steps

| Topic | Doc |
|-------|-----|
| All CLI commands and keyboard shortcuts | [CLI Reference](cli-reference.md) |
| All `make` targets | [Makefile Reference](makefile-reference.md) |
| Agent roles and middleware | [Agents](agents.md) |
| Model profiles and fallback chain | [Models](models.md) |
| Engagement workflow (RoE → Execution) | [Engagement Workflow](engagement-workflow.md) |
| Web dashboard features | [Web Dashboard](web-dashboard.md) |
| Contributing to Decepticon | [Contributing](contributing.md) |
