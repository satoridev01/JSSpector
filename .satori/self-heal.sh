#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

# Compile and launch the newest controller, rather than pulling after an older controller is
# already running in memory.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "self-heal: the JSSpector checkout must be clean before synchronization" >&2
  exit 1
fi
git pull --ff-only
if [[ "$(git rev-list --count '@{upstream}..HEAD')" != "0" ]]; then
  echo "self-heal: the current branch has unpublished commits; push or remove them first" >&2
  exit 1
fi
exec cargo xtask self-heal --push "$@"
