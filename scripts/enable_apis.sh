#!/usr/bin/env bash
# Requires bash 3.2+ (macOS default) or bash 4+/5+ on Linux
# =============================================================================
# enable_apis.sh — Enable all GCP APIs required by gcp-abuse-scanner
#
# Usage:
#   bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT
#   bash scripts/enable_apis.sh --projects "proj-a,proj-b" --scanner-project SCANNER_PROJECT
#   bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT --dry-run
#   bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT --skip-org-apis
#   bash scripts/enable_apis.sh --org ORG_ID --scanner-project SCANNER_PROJECT --skip-project-apis
#
# Options:
#   --org ORG_ID              GCP organization ID (e.g. 822344232743)
#   --scanner-project ID      Project where the scanner runs / SA lives
#   --projects "a,b,c"        Comma-separated list of project IDs to enable project-level APIs
#                             (alternative to --org; skips project enumeration)
#   --dry-run                 Print what would be enabled without making any changes
#   --skip-org-apis           Skip enabling APIs in the scanner project
#   --skip-project-apis       Skip enabling APIs in scanned projects
#   --parallel N              Max concurrent gcloud calls (default: 10)
#   --help                    Show this help
#
# Requirements:
#   - gcloud CLI authenticated (gcloud auth login or ADC)
#   - resourcemanager.projects.list permission on the org (for --org mode)
#   - serviceusage.services.enable permission on each project
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
header()  { echo -e "\n${BOLD}${CYAN}$*${RESET}"; echo -e "${CYAN}$(printf '─%.0s' {1..70})${RESET}"; }

# ── APIs ─────────────────────────────────────────────────────────────────────

# APIs that must be enabled in the SCANNER PROJECT (org-level access)
ORG_APIS=(
  "cloudasset.googleapis.com"       # IAMCollector: org-wide IAM policy search + project enumeration
  "cloudbilling.googleapis.com"     # BillingCollector: billing account info
  "billingbudgets.googleapis.com"   # BillingCollector: budget alerts (CMN-001, CMN-002, CM-060, GEM-051)
  "orgpolicy.googleapis.com"        # OrgPolicyCollector: constraint policies (CM-002, CM-011, GEM-050)
)

# APIs that must be enabled in EACH SCANNED PROJECT
PROJECT_APIS=(
  "serviceusage.googleapis.com"     # ServiceUsageCollector: gates all other collectors — MUST BE FIRST
  "iam.googleapis.com"              # IAMCollector: service accounts + keys (CM-040..044, GEM-020..023)
  "compute.googleapis.com"          # ComputeCollector + NetworkCollector: VMs, firewalls (CM-001..009, CM-050)
  "container.googleapis.com"        # GKECollector: GKE clusters + node pools (CM-020..026)
  "run.googleapis.com"              # CloudRunCollector: Cloud Run services (CM-030, CM-031)
  "aiplatform.googleapis.com"       # VertexAICollector: Vertex AI endpoints (GEM-030, GEM-040)
  "apikeys.googleapis.com"          # APIKeysCollector: API keys + restrictions (GEM-001..006)
  "recommender.googleapis.com"      # RecommenderCollector: IAM recommender insights (CM-045)
)

# ── Defaults ─────────────────────────────────────────────────────────────────
ORG_ID=""
SCANNER_PROJECT=""
EXPLICIT_PROJECTS=""
DRY_RUN=false
SKIP_ORG_APIS=false
SKIP_PROJECT_APIS=false
PARALLEL=10

# ── Argument parsing ─────────────────────────────────────────────────────────
usage() {
  sed -n '/^# Usage:/,/^# =/p' "$0" | grep '^#' | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)              ORG_ID="$2";              shift 2 ;;
    --scanner-project)  SCANNER_PROJECT="$2";     shift 2 ;;
    --projects)         EXPLICIT_PROJECTS="$2";   shift 2 ;;
    --dry-run)          DRY_RUN=true;             shift   ;;
    --skip-org-apis)    SKIP_ORG_APIS=true;       shift   ;;
    --skip-project-apis) SKIP_PROJECT_APIS=true;  shift   ;;
    --parallel)         PARALLEL="$2";            shift 2 ;;
    --help|-h)          usage ;;
    *) error "Unknown option: $1"; usage ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "${SCANNER_PROJECT}" ]]; then
  error "--scanner-project is required."
  exit 1
fi

if [[ -z "${ORG_ID}" && -z "${EXPLICIT_PROJECTS}" ]]; then
  error "Either --org or --projects is required."
  exit 1
fi

if ! command -v gcloud &>/dev/null; then
  error "gcloud CLI not found. Install it: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
enable_apis() {
  local project="$1"
  shift
  local apis=("$@")

  if [[ "${DRY_RUN}" == true ]]; then
    echo -e "  ${YELLOW}[DRY-RUN]${RESET} gcloud services enable ${apis[*]} --project=${project}"
    return 0
  fi

  if gcloud services enable "${apis[@]}" --project="${project}" --quiet 2>&1; then
    success "Enabled ${#apis[@]} API(s) in ${project}"
    return 0
  else
    warn "Failed to enable APIs in ${project} — check permissions"
    return 1
  fi
}

check_already_enabled() {
  local project="$1"
  shift
  local apis=("$@")
  local already_enabled
  already_enabled=$(gcloud services list --project="${project}" --enabled \
    --format="value(config.name)" 2>/dev/null || echo "")

  local missing=()
  for api in "${apis[@]}"; do
    if ! echo "${already_enabled}" | grep -q "^${api}$"; then
      missing+=("${api}")
    fi
  done
  echo "${missing[@]:-}"
}

# ── Step 1: Scanner project (org-level APIs) ──────────────────────────────────
if [[ "${SKIP_ORG_APIS}" == false ]]; then
  header "Step 1 — Scanner project: ${SCANNER_PROJECT}"
  info "Enabling ${#ORG_APIS[@]} org-level APIs..."

  for api in "${ORG_APIS[@]}"; do
    echo -e "  • ${api}"
  done
  echo ""

  if enable_apis "${SCANNER_PROJECT}" "${ORG_APIS[@]}"; then
    success "Scanner project APIs ready."
  else
    warn "Some scanner project APIs may not have been enabled. Continuing..."
  fi
else
  info "Skipping scanner project APIs (--skip-org-apis)"
fi

# ── Step 2: Collect project list ──────────────────────────────────────────────
header "Step 2 — Collecting project list"

PROJECTS=()

if [[ -n "${EXPLICIT_PROJECTS}" ]]; then
  IFS=',' read -ra PROJECTS <<< "${EXPLICIT_PROJECTS}"
  info "Using explicit project list: ${#PROJECTS[@]} project(s)"
elif [[ -n "${ORG_ID}" ]]; then
  info "Enumerating projects under org ${ORG_ID}..."
  while IFS= read -r line; do
    [[ -n "${line}" ]] && PROJECTS+=("${line}")
  done < <(
    gcloud projects list \
      --filter="parent.id=${ORG_ID} AND parent.type=organization AND lifecycleState=ACTIVE" \
      --format="value(projectId)" \
      2>/dev/null
  )
  info "Found ${#PROJECTS[@]} active project(s)"
fi

if [[ ${#PROJECTS[@]} -eq 0 ]]; then
  warn "No projects found. Nothing to do for project-level APIs."
  SKIP_PROJECT_APIS=true
fi

# ── Step 3: Enable project-level APIs ────────────────────────────────────────
if [[ "${SKIP_PROJECT_APIS}" == false ]]; then
  header "Step 3 — Project-level APIs (${#PROJECTS[@]} projects, parallel=${PARALLEL})"
  info "APIs to enable per project:"
  for api in "${PROJECT_APIS[@]}"; do
    echo -e "  • ${api}"
  done
  echo ""

  if [[ "${DRY_RUN}" == true ]]; then
    warn "DRY-RUN mode — no changes will be made"
    echo ""
  fi

  SUCCEEDED=0
  FAILED=0
  FAILED_PROJECTS=()

  # Process in parallel batches
  pids=()
  results_dir=$(mktemp -d)

  process_project() {
    local project="$1"
    local result_file="${results_dir}/${project//\//_}"

    if enable_apis "${project}" "${PROJECT_APIS[@]}" 2>&1; then
      echo "ok" > "${result_file}"
    else
      echo "fail" > "${result_file}"
    fi
  }

  batch=()
  for project in "${PROJECTS[@]}"; do
    batch+=("${project}")

    if [[ ${#batch[@]} -ge ${PARALLEL} ]]; then
      for p in "${batch[@]}"; do
        process_project "${p}" &
        pids+=($!)
      done
      wait "${pids[@]}" 2>/dev/null || true
      pids=()
      batch=()
    fi
  done

  # Process remaining
  for p in "${batch[@]}"; do
    process_project "${p}" &
    pids+=($!)
  done
  wait "${pids[@]}" 2>/dev/null || true

  # Tally results
  for project in "${PROJECTS[@]}"; do
    result_file="${results_dir}/${project//\//_}"
    if [[ -f "${result_file}" ]]; then
      result=$(cat "${result_file}")
      if [[ "${result}" == "ok" ]]; then
        ((SUCCEEDED++)) || true
      else
        ((FAILED++)) || true
        FAILED_PROJECTS+=("${project}")
      fi
    fi
  done

  rm -rf "${results_dir}"

  echo ""
  header "Results"
  success "Succeeded: ${SUCCEEDED} / ${#PROJECTS[@]} project(s)"
  if [[ ${FAILED} -gt 0 ]]; then
    warn "Failed:    ${FAILED} project(s)"
    echo ""
    warn "The following projects could not be updated (check permissions):"
    for p in "${FAILED_PROJECTS[@]}"; do
      echo -e "  ${RED}✗${RESET} ${p}"
    done
    echo ""
    warn "To retry failed projects:"
    echo -e "  bash scripts/enable_apis.sh \\"
    echo -e "    --projects \"$(IFS=','; echo "${FAILED_PROJECTS[*]}")\" \\"
    echo -e "    --scanner-project ${SCANNER_PROJECT}"
  fi
else
  info "Skipping project-level APIs (--skip-project-apis)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "Summary"

if [[ "${DRY_RUN}" == true ]]; then
  warn "DRY-RUN — no changes were made. Remove --dry-run to apply."
else
  echo -e "${GREEN}${BOLD}Setup complete.${RESET}"
  echo ""
  echo "Next steps:"
  echo "  1. Assign IAM roles to the scanner service account:"
  echo "     See docs/iam-setup.md"
  echo ""
  echo "  2. Run a scan:"
  if [[ -n "${ORG_ID}" ]]; then
    echo "     gcp-abuse-scanner scan --org ${ORG_ID} --format console"
  else
    echo "     gcp-abuse-scanner scan --project PROJECT_ID --format console"
  fi
  echo ""
  echo "  3. Full API reference:"
  echo "     docs/apis.md"
fi
