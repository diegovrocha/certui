#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  bump.sh — version bump + tag + push for certui
#
#  Usage:
#    ./scripts/bump.sh patch    # v1.3.0 → v1.3.1
#    ./scripts/bump.sh minor    # v1.3.0 → v1.4.0
#    ./scripts/bump.sh major    # v1.3.0 → v2.0.0
#    ./scripts/bump.sh 1.4.2    # explicit version
#
#  Checks:
#    - working tree is clean
#    - tests pass
#    - go vet passes
#    - tag doesn't already exist
# ─────────────────────────────────────────────────────────
set -euo pipefail

# Colors
RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
CYAN=$'\033[36m'
DIM=$'\033[2m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

info()  { echo "${CYAN}ℹ${RESET} $*"; }
ok()    { echo "${GREEN}✔${RESET} $*"; }
warn()  { echo "${YELLOW}⚠${RESET} $*"; }
fail()  { echo "${RED}✖${RESET} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $0 <patch|minor|major|X.Y.Z>

  patch   bump the patch version (bug fixes)
  minor   bump the minor version (new features, backwards compatible)
  major   bump the major version (breaking changes)
  X.Y.Z   set an explicit version

Examples:
  $0 patch
  $0 minor
  $0 1.5.0
EOF
    exit 1
}

[[ $# -eq 1 ]] || usage

cd "$(dirname "$0")/.."

# ─── Validate working tree
if [[ -n "$(git status --porcelain)" ]]; then
    fail "Working tree has uncommitted changes. Commit or stash them first."
fi

current_branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "$current_branch" != "main" ]]; then
    warn "You are on branch '$current_branch', not 'main'."
    read -rp "Continue anyway? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || fail "Aborted."
fi

# ─── Determine new version
last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
last_ver=${last_tag#v}

bump_kind="$1"

if [[ "$bump_kind" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    new_ver="$bump_kind"
else
    IFS='.' read -r major minor patch <<< "$last_ver"
    case "$bump_kind" in
        patch)
            patch=$((patch + 1))
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        *)
            usage
            ;;
    esac
    new_ver="${major}.${minor}.${patch}"
fi

new_tag="v${new_ver}"

# ─── Safety checks
if git rev-parse "$new_tag" >/dev/null 2>&1; then
    fail "Tag $new_tag already exists locally."
fi

if git ls-remote --tags origin | grep -q "refs/tags/${new_tag}$"; then
    fail "Tag $new_tag already exists on origin."
fi

# ─── Preview
echo
info "Release summary"
echo "  ${DIM}Last tag:${RESET}    $last_tag"
echo "  ${DIM}New tag:${RESET}     ${BOLD}${GREEN}$new_tag${RESET}"
echo "  ${DIM}Branch:${RESET}      $current_branch"
echo

# Show commits since last tag
info "Commits since $last_tag:"
git --no-pager log "$last_tag"..HEAD --oneline --no-decorate | sed 's/^/  /' || true
echo

# ─── Confirm
read -rp "Proceed with release $new_tag? [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || fail "Aborted."

# ─── Tests + vet
info "Running go vet..."
go vet ./... || fail "go vet failed"
ok "vet clean"

info "Running tests..."
go test ./... -count=1 >/dev/null || fail "tests failed"
ok "tests pass"

# ─── Tag and push
info "Pulling latest from origin..."
git pull --ff-only origin "$current_branch" || fail "git pull failed"

info "Creating tag $new_tag..."
git tag -a "$new_tag" -m "Release $new_tag"

info "Pushing branch and tag..."
git push origin "$current_branch"
git push origin "$new_tag"

echo
ok "Released ${BOLD}$new_tag${RESET}"
echo "  GitHub Actions will now build and publish the release."
echo "  Watch: ${CYAN}https://github.com/diegovrocha/certui/releases${RESET}"
