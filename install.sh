#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    🜏  Decepticon × Dark Triad  🜏                          ║
# ║                      Autonomous Red Team Platform                            ║
# ║                     Installer v2 · Production Grade                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/7ShIkI3/Decepticon-x-DarkTriad/main/install.sh | bash
#
# Env vars: DECEPTICON_HOME, DECEPTICON_BRANCH, SKIP_BUILD, SKIP_HEALTH,
#           DRY_RUN, VERBOSE, DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY,
#           DECEPTICON_MODEL_PROFILE, DECEPTICON_STARTUP_TIMEOUT_SECONDS

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
readonly REPO="7ShIkI3/Decepticon-x-DarkTriad"
readonly REPO_URL="https://github.com/${REPO}.git"
readonly MIN_DISK_GB=12
readonly MIN_RAM_MB=4096
readonly MIN_DOCKER_MAJOR=20
readonly REQUIRED_PORTS=(3000 2024 4000 5432 7474 7687)
readonly STACK_SERVICES=(postgres litellm langgraph sandbox neo4j)

# ═══════════════════════════════════════════════════════════════════════════════
# COLORS — Dark Triad palette (bash 3.2+ compatible, no associative arrays)
# ═══════════════════════════════════════════════════════════════════════════════
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B_='\033[0;34m'
M='\033[0;35m'; C_='\033[0;36m'; W='\033[1;37m'; D='\033[0;2m'
N='\033[0m';    H='\033[0;90m'

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════════════════════
INSTALL_DIR="${DECEPTICON_HOME:-$HOME/.decepticon-darktriad}"
BRANCH="${DECEPTICON_BRANCH:-main}"
COMPOSE=""
CONTAINER_RT=""
START_TIME=$(date +%s)
STEP_CURRENT=0
STEP_TOTAL=6
WARNINGS=()
ERRORS=()

# System info (populated during audit)
SYS_OS="" SYS_ARCH="" SYS_KERNEL="" SYS_DISTRO="" SYS_CPU=0 SYS_RAM_GB=0
SYS_DISK_FREE=0 SYS_DISK_TOTAL=0 SYS_DOCKER_VER="" SYS_DOCKER_DRIVER="" SYS_DOCKER_USED=""

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
_ts()    { printf '%(%H:%M:%S)T' -1; }
_bar()   { printf '%*s' "${1:-40}" '' | tr ' ' '─'; }
_div()   { local w; w=$(tput cols 2>/dev/null || echo 80); echo -e "${H}$(_bar $((w - 2)))${N}"; }
_ok()    { echo -e "  ${G}✓${N} $*"; }
_fail()  { echo -e "  ${R}✗${N} $*"; }
_warn()  { echo -e "  ${Y}⚠${N} $*"; }
_info()  { echo -e "  ${D}→${N} $*"; }
_tip()   { echo -e "  ${C_}💡${N} ${D}$*${N}"; }
_step()  { STEP_CURRENT=$((STEP_CURRENT + 1)); echo -e "\n${M}┌─ ${W}[${STEP_CURRENT}/${STEP_TOTAL}]${N} ${M}$*${N}\n${M}│${N}"; }
_step_end() { echo -e "${M}└─${N} ${G}Done${N}\n"; }
_debug() { [[ "${VERBOSE:-}" == "true" ]] && echo -e "  ${H}[DEBUG]${N} $*" >&2; return 0; }
_dry()   { [[ "${DRY_RUN:-}" == "true" ]] && { echo -e "  ${Y}[DRY-RUN]${N} $*"; return 0; }; return 1; }
_fix()   { echo -e "  ${C_}🛠${N} ${D}Fix: $*${N}"; }

# Cross-platform sed -i (GNU sed uses -i, BSD/macOS uses -i '')
_sedi() {
    local file="$1" pattern="$2" replacement="$3"
    if sed --version 2>/dev/null | grep -q GNU; then
        sed -i "s|${pattern}|${replacement}|" "$file"
    else
        sed -i '' "s|${pattern}|${replacement}|" "$file"
    fi
}

_die() {
    echo -e "\n${R}╔══════════════════════════════════════════════════════════════╗${N}"
    echo -e "${R}║${N}  ${W}Installation failed${N} — $1"
    echo -e "${R}╚══════════════════════════════════════════════════════════════╝${N}"
    [[ ${#ERRORS[@]} -gt 0 ]] && { echo -e "\n${R}Errors:${N}"; for e in "${ERRORS[@]}"; do echo -e "  ${R}•${N} $e"; done; }
    echo -e "\n${D}Troubleshooting: https://github.com/${REPO}/issues${N}"
    exit 1
}

# ── Trap for clean interrupt ────────────────────────────────────────
_on_interrupt() {
    echo -e "\n\n${Y}Installation interrupted.${N}"
    echo -e "${D}Partial files may remain in: ${INSTALL_DIR}${N}"
    echo -e "${D}Remove with: rm -rf ${INSTALL_DIR}${N}"
    exit 130
}
trap _on_interrupt INT TERM

# ═══════════════════════════════════════════════════════════════════════════════
# ASCII BANNER
# ═══════════════════════════════════════════════════════════════════════════════
banner() {
    clear 2>/dev/null || true
    echo -e "${M}"
    echo '       ┌─────────────────────────────────────────────┐'
    echo '       │                                             │'
    echo '       │   🜏   Decepticon  ×  Dark Triad   🜏       │'
    echo '       │                                             │'
    echo '       │     Autonomous Red Team Platform            │'
    echo '       │                                             │'
    echo '       │  🪞  Narcissus · 🔪  Psychopath · 🕸️  Machiavelli  │'
    echo '       │                                             │'
    echo -e '       └─────────────────────────────────────────────┘'"${N}"
    echo -e "  ${D}Installer v2 · $(date +%Y-%m-%d) · ${REPO}${N}"
    _div
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1/6 — ENVIRONMENT AUDIT
# ═══════════════════════════════════════════════════════════════════════════════
audit_system() {
    _step 'System Audit'

    local os arch kernel distro cpu_cores ram_mb ram_gb disk_free_gb disk_total_gb

    # ── OS detection ──────────────────────────────────────────────────
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    kernel=$(uname -r)

    case "$os" in
        linux)   SYS_OS="Linux"   ;;
        darwin)  SYS_OS="macOS"   ;;
        *)       SYS_OS="$os"     ;;
    esac

    case "$arch" in
        x86_64|amd64) SYS_ARCH="x86_64" ;;
        aarch64|arm64) SYS_ARCH="arm64"  ;;
        *)             SYS_ARCH="$arch"  ;;
    esac

    SYS_KERNEL="$kernel"

    if command -v lsb_release &>/dev/null; then
        SYS_DISTRO="$(lsb_release -ds 2>/dev/null || echo 'unknown')"
    elif [[ -f /etc/os-release ]]; then
        SYS_DISTRO="$(. /etc/os-release && echo "$PRETTY_NAME")"
    else
        SYS_DISTRO="unknown"
    fi

    # ── CPU & RAM ─────────────────────────────────────────────────────
    cpu_cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
    ram_mb=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || \
             sysctl -n hw.memsize 2>/dev/null | awk '{printf "%d", $1/1024/1024}' || echo 0)
    ram_gb=$((ram_mb / 1024))

    SYS_CPU="$cpu_cores"
    SYS_RAM_GB="$ram_gb"

    # ── Disk ──────────────────────────────────────────────────────────
    read -r disk_total_gb disk_free_gb < <(
        df -BG "${INSTALL_DIR:-$HOME}" 2>/dev/null | awk 'NR==2 {gsub(/G/,""); print $3, $4}' || echo "0 0"
    )
    SYS_DISK_FREE="$disk_free_gb"
    SYS_DISK_TOTAL="$disk_total_gb"

    # ── Render audit table ────────────────────────────────────────────
    echo -e "  ${W}Host${N}       ${SYS_DISTRO:-unknown}"
    echo -e "  ${W}Kernel${N}     ${SYS_KERNEL} (${SYS_ARCH})"
    echo -e "  ${W}CPU${N}        ${SYS_CPU} cores"
    echo -e "  ${W}RAM${N}        ${SYS_RAM_GB} GB"
    echo -e "  ${W}Disk${N}       ${SYS_DISK_FREE} GB free / ${SYS_DISK_TOTAL} GB total"
    echo ""

    # ── Validation ────────────────────────────────────────────────────
    [[ "$cpu_cores" -lt 2 ]] && WARNINGS+=("Only ${cpu_cores} CPU core. 4+ recommended.")
    [[ "$ram_mb" -lt "$MIN_RAM_MB" ]] && WARNINGS+=("Only ${ram_gb}GB RAM. ${MIN_RAM_MB}MB minimum.")
    [[ "$disk_free_gb" -lt "$MIN_DISK_GB" ]] && \
        ERRORS+=("Insufficient disk: ${disk_free_gb}GB free, need ${MIN_DISK_GB}GB+")

    _step_end
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2/6 — DEPENDENCY VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
verify_deps() {
    _step 'Dependency Verification'

    # ── git ───────────────────────────────────────────────────────────
    if command -v git &>/dev/null; then
        _ok "git $(git --version | grep -oP '[\d.]+' | head -1)"
    else
        _fix "sudo apt install git / brew install git"
        ERRORS+=("git not found")
    fi

    # ── Container runtime ─────────────────────────────────────────────
    if [[ -n "${DECEPTICON_CONTAINER_RUNTIME:-}" ]]; then
        CONTAINER_RT="$DECEPTICON_CONTAINER_RUNTIME"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        CONTAINER_RT="docker"
    elif command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
        CONTAINER_RT="podman"
    else
        _fix "Install Docker: https://docs.docker.com/get-docker/"
        ERRORS+=("No working container runtime")
    fi

    if [[ -n "$CONTAINER_RT" ]]; then
        local ver major driver disk_used
        ver=$("$CONTAINER_RT" --version 2>/dev/null | grep -oP '[\d]+\.[\d]+' | head -1 || echo "?")
        major="${ver%%.*}"

        if [[ "$CONTAINER_RT" == "docker" ]]; then
            driver=$(docker info --format '{{.Driver}}' 2>/dev/null || echo "?")
            disk_used=$(docker system df --format '{{.Size}}' 2>/dev/null || echo "?")
        else
            driver="podman"
            disk_used="?"
        fi
        SYS_DOCKER_VER="$ver"
        SYS_DOCKER_DRIVER="$driver"
        SYS_DOCKER_USED="$disk_used"

        _ok "$CONTAINER_RT v${ver} (storage: ${driver})"
        [[ "$major" -lt "$MIN_DOCKER_MAJOR" ]] && \
            WARNINGS+=("Docker v${ver} is old — v${MIN_DOCKER_MAJOR}+ recommended")
    fi

    # ── Docker Compose v2 ─────────────────────────────────────────────
    if [[ "$CONTAINER_RT" == "docker" ]]; then
        if docker compose version &>/dev/null 2>&1; then
            _ok "Docker Compose v$(docker compose version --short 2>/dev/null || echo '?')"
            COMPOSE="docker compose"
        else
            _fix "sudo apt install docker-compose-plugin"
            ERRORS+=("Docker Compose v2 not available")
        fi
    elif [[ "$CONTAINER_RT" == "podman" ]]; then
        if podman compose --help &>/dev/null 2>&1; then
            _ok "Podman Compose (built-in)"
            COMPOSE="podman compose"
        elif command -v podman-compose &>/dev/null; then
            _ok "podman-compose"
            COMPOSE="podman-compose"
        else
            _fix "pip install podman-compose"
            ERRORS+=("podman-compose not found")
        fi
    fi

    # ── curl ──────────────────────────────────────────────────────────
    command -v curl &>/dev/null && _ok "curl $(curl --version 2>/dev/null | head -1 | grep -oP '[\d.]+' | head -1)" || \
        { _fix "sudo apt install curl"; ERRORS+=("curl not found"); }

    # ── GitHub connectivity ───────────────────────────────────────────
    local gh_ok=0
    curl -fsS --connect-timeout 5 --max-time 10 "https://github.com" &>/dev/null && gh_ok=1 || true
    [[ "$gh_ok" -eq 1 ]] && _ok "Network: github.com reachable" || \
        { _warn "Cannot reach github.com — clone will fail"; _fix "Check proxy: export https_proxy=..."; }

    # ── inotify limits (Linux) ────────────────────────────────────────
    if [[ "$(uname -s)" == "Linux" ]]; then
        local inotify_max
        inotify_max=$(cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null || echo 0)
        [[ "$inotify_max" -lt 65536 ]] && \
            WARNINGS+=("inotify watches: ${inotify_max} (increase to 65536 for large workspaces)")
    fi

    # ── Port conflicts ────────────────────────────────────────────────
    local port_conflicts=()
    for port in "${REQUIRED_PORTS[@]}"; do
        if command -v ss &>/dev/null; then
            ss -tlnp 2>/dev/null | grep -q ":${port}\b" && port_conflicts+=("$port")
        elif command -v lsof &>/dev/null; then
            lsof -i:"$port" -sTCP:LISTEN &>/dev/null && port_conflicts+=("$port")
        fi
    done
    [[ ${#port_conflicts[@]} -gt 0 ]] && \
        WARNINGS+=("Ports in use: ${port_conflicts[*]}. Override via WEB_PORT / LITELLM_PORT env vars.")

    # ── Abort on hard errors ─────────────────────────────────────────
    [[ ${#ERRORS[@]} -gt 0 ]] && _die "Prerequisites not met"
    [[ ${#WARNINGS[@]} -gt 0 ]] && { for w in "${WARNINGS[@]}"; do _warn "$w"; done; echo ""; }

    _step_end
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3/6 — CLONE REPOSITORY
# ═══════════════════════════════════════════════════════════════════════════════
clone_repo() {
    _step 'Repository Setup'

    _info "Target: ${INSTALL_DIR}"
    _info "Remote: ${REPO_URL} (@${BRANCH})"

    if _dry; then _step_end; return; fi

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        _info "Existing repository — updating..."
        cd "$INSTALL_DIR"
        local before after
        before=$(git rev-parse HEAD 2>/dev/null || echo "?")
        git fetch origin "$BRANCH" --quiet 2>/dev/null || true
        git checkout "$BRANCH" --quiet 2>/dev/null || true
        git pull origin "$BRANCH" --quiet 2>/dev/null || {
            _warn "Pull failed, attempting reset..."
            git fetch origin "$BRANCH" --quiet
            git reset --hard "origin/${BRANCH}" --quiet
        }
        after=$(git rev-parse HEAD 2>/dev/null || echo "?")
        if [[ "$before" != "$after" ]]; then
            _ok "Updated: ${before:0:7} → ${after:0:7}"
        else
            _ok "Already up to date (${after:0:7})"
        fi
    else
        _info "Cloning from ${REPO_URL} ..."
        mkdir -p "$(dirname "$INSTALL_DIR")"

        if ! git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
            _info "Shallow clone unavailable — full clone..."
            rm -rf "$INSTALL_DIR"
            git clone "$REPO_URL" "$INSTALL_DIR" || {
                _fix "Check network: ping github.com"
                ERRORS+=("Git clone failed")
                _die "Cannot clone repository"
            }
            cd "$INSTALL_DIR"
            git checkout "$BRANCH" 2>/dev/null || true
        fi

        local ver
        ver=$(cd "$INSTALL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "?")
        _ok "Cloned → ${INSTALL_DIR} (${ver})"
    fi

    cd "$INSTALL_DIR"
    _info "Latest: $(git log --oneline -1 --format='%s' 2>/dev/null | cut -c1-70)"
    _step_end
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4/6 — CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
configure() {
    _step 'Configuration'

    cd "$INSTALL_DIR"

    if [[ -f "${INSTALL_DIR}/.env" ]]; then
        _ok ".env exists — preserving your configuration"
        if ! grep -q "^DECEPTICON_HOME=" "${INSTALL_DIR}/.env" 2>/dev/null; then
            echo "DECEPTICON_HOME=${INSTALL_DIR}" >> "${INSTALL_DIR}/.env"
            _info "Added DECEPTICON_HOME"
        fi
        _step_end; return
    fi

    _info "Creating .env from .env.example..."
    cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"

    # ── Inject metadata ─────────────────────────────────────────────
    {
        echo ""
        echo "# ═══════════════════════════════════════════════"
        echo "# 🜏 Decepticon × Dark Triad — Auto-generated"
        echo "# ═══════════════════════════════════════════════"
        echo "DECEPTICON_HOME=${INSTALL_DIR}"
        echo "DECEPTICON_MODEL_PROFILE=${DECEPTICON_MODEL_PROFILE:-eco}"
    } >> "${INSTALL_DIR}/.env"

    # ── API key ─────────────────────────────────────────────────────
    local key_configured=false

    if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
        _info "DEEPSEEK_API_KEY ← environment"
        _sedi "${INSTALL_DIR}/.env" "^DEEPSEEK_API_KEY=.*" "DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}"
        key_configured=true
    fi
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        _info "ANTHROPIC_API_KEY ← environment"
        _sedi "${INSTALL_DIR}/.env" "^ANTHROPIC_API_KEY=.*" "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}"
        key_configured=true
    fi
    if [[ -n "${OPENAI_API_KEY:-}" ]]; then
        _info "OPENAI_API_KEY ← environment"
        _sedi "${INSTALL_DIR}/.env" "^OPENAI_API_KEY=.*" "OPENAI_API_KEY=${OPENAI_API_KEY}"
        key_configured=true
    fi

    if ! $key_configured && [[ -t 0 ]]; then
        echo ""
        echo -e "  ${W}╭─ LLM Provider ──────────────────────────────────────╮${N}"
        echo -e "  ${W}│${N}  Choose your AI backend. You can change this later      ${W}│${N}"
        echo -e "  ${W}│${N}  by editing ${INSTALL_DIR}/.env ${W}│${N}"
        echo -e "  ${W}╰──────────────────────────────────────────────────────╯${N}"
        echo ""
        echo -e "  ${W}[1]${N} DeepSeek    ${D}(sk-...)${N}"
        echo -e "  ${W}[2]${N} Anthropic   ${D}(sk-ant-...)${N}"
        echo -e "  ${W}[3]${N} OpenAI      ${D}(sk-.../sk-proj-...)${N}"
        echo -e "  ${W}[4]${N} OpenRouter  ${D}(sk-or-...)${N}"
        echo -e "  ${W}[5]${N} Ollama      ${D}(local, free)${N}"
        echo -e "  ${W}[6]${N} Skip        ${D}(configure later)${N}"
        echo ""

        local choice key
        read -r -p "  Choice [1-6]: " choice

        case "${choice:-1}" in
            1) read -r -p "  DeepSeek API key: " key
               [[ -n "$key" ]] && _sedi "${INSTALL_DIR}/.env" "^DEEPSEEK_API_KEY=.*" "DEEPSEEK_API_KEY=${key}" && _ok "DeepSeek configured" ;;
            2) read -r -p "  Anthropic API key: " key
               [[ -n "$key" ]] && _sedi "${INSTALL_DIR}/.env" "^ANTHROPIC_API_KEY=.*" "ANTHROPIC_API_KEY=${key}" && _ok "Anthropic configured" ;;
            3) read -r -p "  OpenAI API key: " key
               [[ -n "$key" ]] && _sedi "${INSTALL_DIR}/.env" "^OPENAI_API_KEY=.*" "OPENAI_API_KEY=${key}" && _ok "OpenAI configured" ;;
            4) read -r -p "  OpenRouter API key: " key
               [[ -n "$key" ]] && _sedi "${INSTALL_DIR}/.env" "^OPENROUTER_API_KEY=.*" "OPENROUTER_API_KEY=${key}" && _ok "OpenRouter configured" ;;
            5) _info "Ollama selected — set OLLAMA_API_BASE + OLLAMA_MODEL in .env" ;;
            6|"") _info "Skipped — edit ${INSTALL_DIR}/.env to add keys later" ;;
        esac
    elif ! $key_configured; then
        _warn "Non-interactive mode — no API key set. Edit .env manually."
    fi

    mkdir -p "${INSTALL_DIR}/workspace"
    _ok "Workspace ready: ${INSTALL_DIR}/workspace"
    _step_end
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5/6 — BUILD & LAUNCH
# ═══════════════════════════════════════════════════════════════════════════════
build_and_launch() {
    _step 'Build & Launch'

    cd "$INSTALL_DIR"

    if _dry; then _info "[DRY-RUN] Would build + start stack"; _step_end; return; fi

    # ── Build ─────────────────────────────────────────────────────────
    if [[ "${SKIP_BUILD:-}" == "true" ]]; then
        _info "Build skipped (SKIP_BUILD=true)"
    else
        echo -e "  ${W}Building Docker images...${N}"
        echo -e "  ${D}⏱  First build: ~5-10 min. Cached rebuild: ~30s.${N}"
        echo ""

        local build_start
        build_start=$(date +%s)

        DECEPTICON_VERSION="${DECEPTICON_VERSION:-dev}" \
        DECEPTICON_HOME="$INSTALL_DIR" \
            $COMPOSE --profile cli build --progress=plain 2>&1 | while IFS= read -r line; do
            case "$line" in
                *"#0 building"*|*"#1"*|*"#2"*|*"#3"*|*"#4"*|*"#5"*|*"#6"*|*"#7"*) echo -e "  ${D}${line}${N}" ;;
                *"ERROR"*|*"error"*|*"failed"*|*"FAILED"*) echo -e "  ${R}${line}${N}" ;;
            esac
        done || _die "Docker build failed. Check the errors above."

        local build_min=$(( ($(date +%s) - build_start) / 60 ))
        _ok "Images built in ${build_min} min"
    fi

    # ── Stop previous stack ───────────────────────────────────────────
    _info "Stopping any previous stack..."
    $COMPOSE --profile cli down --remove-orphans 2>/dev/null || true

    # ── Launch ────────────────────────────────────────────────────────
    local timeout="${DECEPTICON_STARTUP_TIMEOUT_SECONDS:-600}"
    echo ""
    echo -e "  ${W}Launching services (timeout: ${timeout}s)...${N}"
    echo ""

    local launch_start
    launch_start=$(date +%s)

    DECEPTICON_VERSION="${DECEPTICON_VERSION:-dev}" \
    DECEPTICON_HOME="$INSTALL_DIR" \
        $COMPOSE --profile cli up -d --wait --wait-timeout "$timeout" 2>&1 | while IFS= read -r line; do
        echo -e "  ${D}${line}${N}"
    done || {
        _warn "Some services may still be starting — checking status..."
    }

    local launch_sec=$(($(date +%s) - launch_start))
    _ok "Stack launched in ${launch_sec}s"

    # ── Service summary ───────────────────────────────────────────────
    echo ""
    echo -e "  ${W}Service Status:${N}"
    for svc in "${STACK_SERVICES[@]}"; do
        local status
        status=$($COMPOSE ps --format '{{.Status}}' "$svc" 2>/dev/null | head -1 || echo "not found")
        case "$status" in
            *"Up"*|*"healthy"*) echo -e "  ${G}●${N} ${svc}: ${status}" ;;
            *"starting"*)       echo -e "  ${Y}●${N} ${svc}: ${status}" ;;
            *)                  echo -e "  ${R}●${N} ${svc}: ${status:-not running}" ;;
        esac
    done

    _step_end
}

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6/6 — HEALTH CHECK & FINISH
# ═══════════════════════════════════════════════════════════════════════════════
health_and_finish() {
    _step 'Health Check'

    if _dry; then _info "[DRY-RUN] Would verify services"; _step_end; return; fi

    if [[ "${SKIP_HEALTH:-}" == "true" ]]; then
        _info "Health check skipped (SKIP_HEALTH=true)"
        _step_end; return
    fi

    cd "$INSTALL_DIR"
    local web_ok=0 api_ok=0 llm_ok=0
    local web_port="${WEB_PORT:-3000}" api_port="${LANGGRAPH_PORT:-2024}" llm_port="${LITELLM_PORT:-4000}"

    # ── Web Dashboard ─────────────────────────────────────────────────
    for i in {1..10}; do
        if curl -sf "http://localhost:${web_port}" &>/dev/null 2>&1; then
            _ok "Web Dashboard  → http://localhost:${web_port}"; web_ok=1; break
        fi
        sleep 2
    done
    [[ "$web_ok" -eq 0 ]] && _info "Web Dashboard → http://localhost:${web_port} (still starting...)"

    # ── LangGraph API ─────────────────────────────────────────────────
    curl -sf "http://localhost:${api_port}/ok" &>/dev/null 2>&1 && { api_ok=1; _ok "LangGraph API → port ${api_port}"; } || \
        _info "LangGraph API → port ${api_port} (still starting...)"

    # ── LiteLLM ───────────────────────────────────────────────────────
    curl -sf "http://localhost:${llm_port}/health/readiness" &>/dev/null 2>&1 && { llm_ok=1; _ok "LiteLLM Proxy → port ${llm_port}"; } || \
        _info "LiteLLM Proxy → port ${llm_port} (still starting...)"

    _step_end

    # ═══════════════════════════════════════════════════════════════════
    # DONE BANNER
    # ═══════════════════════════════════════════════════════════════════
    local total_sec=$(( $(date +%s) - START_TIME ))
    local total_min=$(( total_sec / 60 )) total_sec_rem=$(( total_sec % 60 ))

    echo ""
    echo -e "${M}"
    echo '  ╔══════════════════════════════════════════════════════════════╗'
    echo '  ║                                                              ║'
    echo '  ║         🜏   Decepticon × Dark Triad   🜏                    ║'
    echo '  ║                    ▸  R E A D Y  ◂                            ║'
    echo '  ║                                                              ║'
    echo -e '  ╚══════════════════════════════════════════════════════════════╝'"${N}"
    echo ""

    echo -e "  ${W}Install Summary${N}"
    echo -e "  ${H}────────────────────────────────────────────────────${N}"
    echo -e "  ${W}Directory${N}    ${INSTALL_DIR}"
    echo -e "  ${W}Dashboard${N}   http://localhost:${web_port}"
    echo -e "  ${W}Version${N}     $(cd "${INSTALL_DIR}" && git describe --tags --always 2>/dev/null || echo 'dev')"
    echo -e "  ${W}Duration${N}    ${total_min}m ${total_sec_rem}s"
    echo ""

    echo -e "  ${W}Quick Commands${N}"
    echo -e "  ${H}────────────────────────────────────────────────────${N}"
    echo -e "  ${C_}make status${N}   ${D}# View all running services${N}"
    echo -e "  ${C_}make logs${N}     ${D}# Follow LangGraph logs${N}"
    echo -e "  ${C_}make health${N}   ${D}# Full health check${N}"
    echo -e "  ${C_}make clean${N}    ${D}# Stop + remove everything${N}"
    echo ""

    echo -e "  ${W}Dark Triad Personalities${N}"
    echo -e "  ${H}────────────────────────────────────────────────────${N}"
    echo -e "  ${M}🪞  Narcissus${N}    ${D}Aggressive, fast, auto-execute${N}"
    echo -e "  ${R}🔪  Psychopath${N}   ${D}Relentless, parallel, no limits${N}"
    echo -e "  ${C_}🕸️  Machiavelli${N}  ${D}Strategic, stealthy, minimal footprint${N}"
    echo -e "  ${Y}👻 Ghost${N}        ${D}90% Machiavel + 10% Psychopath${N}"
    echo -e "  ${R}⚔️  Berserker${N}    ${D}70% Psychopath + 30% Narcissus${N}"
    echo ""

    echo -e "  ${Y}⚠  Security${N}"
    echo -e "  ${H}────────────────────────────────────────────────────${N}"
    echo -e "  ${D}• Change NEO4J_PASSWORD for production deployments${N}"
    echo -e "  ${D}• All ports are localhost-only — safe for dev workstations${N}"
    echo -e "  ${D}• Never expose this stack to the public internet${N}"
    echo ""

    local ok_count=$(( web_ok + api_ok + llm_ok ))
    if [[ "$ok_count" -eq 3 ]]; then
        echo -e "  ${G}✓ All services healthy. Open http://localhost:${web_port} to begin.${N}"
    else
        echo -e "  ${Y}⚠  ${ok_count}/3 services ready. Others may still be starting.${N}"
        echo -e "  ${D}Run 'cd ${INSTALL_DIR} && make status' to check.${N}"
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner

    if [[ "${DRY_RUN:-}" == "true" ]]; then
        echo -e "  ${Y}⚡ DRY RUN — no changes will be made${N}\n"
    fi

    audit_system
    verify_deps
    clone_repo
    configure
    build_and_launch
    health_and_finish

    exit 0
}

main "$@"
