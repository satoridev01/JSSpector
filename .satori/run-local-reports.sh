#!/bin/sh
set -u

root=${JSSPECTOR_ROOT:-$(pwd)}
corpus=${CORPUS:?CORPUS is required}
organization=${SATORI_ORGANIZATION:-13}
local_playbook="$root/.satori/jsspector-local.yml"
target_index="$root/.satori/exploitability-targets.json"
class_filter=""

case "$corpus" in
  class:*)
    class_filter=${corpus#class:}
    case "$class_filter" in
      *[!a-z0-9-]*|'') echo "invalid corpus class: $class_filter" >&2; exit 2 ;;
    esac
    repos=$(jq --raw-output --arg class "$class_filter" '
      .targets[]
      | select(any(.cases[]; .class == $class))
      | "\(.repository)@\(.revision)"
    ' "$target_index")
    ;;
  *)
    if [ -f "$corpus" ]; then
      repos=$(sed 's/#.*//' "$corpus")
    else
      repos=$corpus
    fi
    ;;
esac

set -- $repos
total=$#
if [ "$total" -eq 0 ]; then
  echo "corpus is empty" >&2
  exit 2
fi

completed=0
failed=0

# Run one child report in its own process session. Some legacy applications detach workers during
# startup; if one survives the verifier it otherwise accumulates memory/file descriptors across the
# corpus and can make a later, unrelated app exit without a log. `setsid --wait` makes the child PID
# also identify its process group, so only that report's residual descendants are terminated.
run_isolated_child() {
  child_output=$(mktemp)
  child_tmp=$(mktemp -d)
  child_session=0
  if command -v setsid >/dev/null 2>&1; then
    setsid --wait env \
      TMPDIR="$child_tmp" \
      npm_config_cache="$child_tmp/npm-cache" \
      YARN_CACHE_FOLDER="$child_tmp/yarn-cache" \
      XDG_CACHE_HOME="$child_tmp/xdg-cache" \
      "$@" >"$child_output" 2>&1 &
    child_pid=$!
    child_session=1
  else
    env \
      TMPDIR="$child_tmp" \
      npm_config_cache="$child_tmp/npm-cache" \
      YARN_CACHE_FOLDER="$child_tmp/yarn-cache" \
      XDG_CACHE_HOME="$child_tmp/xdg-cache" \
      "$@" >"$child_output" 2>&1 &
    child_pid=$!
  fi
  wait "$child_pid"
  RUN_RC=$?
  if [ "$child_session" -eq 1 ]; then
    # JSSpector gives every launched application its own process group so it can tear down npm and
    # all of that app's children. That group still belongs to this `setsid` session, but it is no
    # longer the launcher's group: killing only `-$child_pid` misses it after an abnormal exit and
    # leaves servers holding deleted checkouts, ports and memory across the corpus. Kill every
    # process in the child's session; retain the group fallback for minimal images without `pkill`.
    if command -v pkill >/dev/null 2>&1; then
      pkill -TERM -s "$child_pid" >/dev/null 2>&1 || true
      sleep 1
      pkill -KILL -s "$child_pid" >/dev/null 2>&1 || true
    else
      kill -TERM "-$child_pid" >/dev/null 2>&1 || true
      sleep 1
      kill -KILL "-$child_pid" >/dev/null 2>&1 || true
    fi
  fi
  RUN_OUTPUT=$(cat "$child_output")
  rm -f "$child_output"
  rm -rf "$child_tmp"
}

for repo in "$@"; do
  completed=$((completed + 1))
  revision=""
  case "$repo" in
    *@*)
      revision=${repo##*@}
      repo=${repo%@*}
      ;;
  esac

  label=$repo
  if [ -n "$revision" ]; then
    label="$repo@$revision"
  fi
  echo "[$completed/$total] $label"

  JSS_VERIFY_FINGERPRINTS=""
  if [ -n "$revision" ] && [ -f "$target_index" ]; then
    if [ -n "$class_filter" ]; then
      JSS_VERIFY_FINGERPRINTS=$(jq --raw-output \
        --arg repository "$repo" \
        --arg revision "$revision" \
        --arg class "$class_filter" '
          .targets[]
          | select(.repository == $repository and .revision == $revision)
          | .cases[]
          | select(.class == $class)
          | .fingerprint
        ' "$target_index" | sort -u | tr '\n' ' ')
    else
      JSS_VERIFY_FINGERPRINTS=$(jq --raw-output \
        --arg repository "$repo" \
        --arg revision "$revision" \
        '.targets[] | select(.repository == $repository and .revision == $revision) | .fingerprints[]' \
        "$target_index" | sort -u | tr '\n' ' ')
    fi
  fi
  if [ -n "$revision" ] && [ -z "$JSS_VERIFY_FINGERPRINTS" ]; then
    echo "[$completed/$total] $label: no stable scanner fingerprints; not replayable" >&2
    failed=$((failed + 1))
    continue
  fi
  export JSS_VERIFY_FINGERPRINTS
  JSS_VERIFY_CASES_B64=""
  if [ -n "$revision" ] && [ -f "$target_index" ]; then
    JSS_VERIFY_CASES_B64=$(jq --compact-output \
      --arg repository "$repo" \
      --arg revision "$revision" \
      --arg class "$class_filter" '
        [.targets[] | select(.repository == $repository and .revision == $revision) |
          if has("cases") then
            .cases[] | select(($class == "") or (.class == $class))
          else
            .fingerprints[] | {fingerprint: .}
          end]
      ' "$target_index" | base64 | tr -d '\n')
  fi
  export JSS_VERIFY_CASES_B64
  export JSS_VERIFY_REPOSITORY="$label"

  # Public callback leases are intentionally short-lived. A single lease created before a long
  # corpus expires before later SSRF/command-injection targets run, turning a valid blind exploit
  # into `unknown or expired token`. Provision a fresh lease only for children whose evidence can
  # require an out-of-band callback; all other classes keep using the isolated local marker.
  unset JSS_VERIFY_CALLBACK_URL
  needs_callback=$(printf '%s' "$JSS_VERIFY_CASES_B64" | base64 -d \
    | jq --raw-output 'any(.[]; .class == "ssrf" or .class == "command-injection")')
  if [ "$needs_callback" = "true" ]; then
    if [ -z "${SATORI_TOKEN:-}" ]; then
      echo "[$completed/$total] $label: SATORI_TOKEN is required for callback verification" >&2
      failed=$((failed + 1))
      continue
    fi
    callback_url=$(curl --fail --silent --show-error --request POST \
      --header "Authorization: Bearer $SATORI_TOKEN" \
      --header "X-Satori-Organization: $organization" \
      https://api-v2.satori.ci/callbacks \
      | jq --raw-output --exit-status '.url | select(type == "string" and length > 0)')
    if [ -z "$callback_url" ]; then
      echo "[$completed/$total] $label: could not provision a verification callback" >&2
      failed=$((failed + 1))
      continue
    fi
    export JSS_VERIFY_CALLBACK_URL="$callback_url"
  fi

  checkout_root=""
  source=$root
  if [ -n "$revision" ]; then
    checkout_root=$(mktemp -d)
    source="$checkout_root/checkout"
    if ! git init -q "$source" \
      || ! git -C "$source" remote add origin "https://github.com/$repo.git" \
      || ! timeout 600 git -C "$source" fetch -q --depth 1 origin "$revision" \
      || ! git -C "$source" checkout -q --detach FETCH_HEAD
    then
      echo "[$completed/$total] $label: could not check out pinned revision" >&2
      rm -rf "$checkout_root"
      failed=$((failed + 1))
      continue
    fi
  fi

  child_attempt=1
  child_report=""
  while [ "$child_attempt" -le 3 ]; do
    if [ -n "$revision" ]; then
      run_isolated_child satori-v2 local "$source" \
        --playbook "$local_playbook" \
        --org "$organization" \
        --timeout 1800 \
        --sync \
        --report \
        --visibility private
    else
      run_isolated_child satori-v2 local "$source" \
        --playbook "$local_playbook" \
        --repo "$repo" \
        --org "$organization" \
        --timeout 1800 \
        --sync \
        --report \
        --visibility private
    fi
    run_output=$RUN_OUTPUT
    run_rc=$RUN_RC
    printf '%s\n' "$run_output"
    child_report=$(printf '%s\n' "$run_output" | sed -n \
      's/.*Report ID[[:space:]]*\([[:alnum:]]\{1,\}\).*/\1/p' | tail -n 1)
    [ -n "$child_report" ] && break
    if [ "$child_attempt" -lt 3 ]; then
      echo "[$completed/$total] $label: child creation produced no report; retrying ($child_attempt/3)" >&2
      sleep 5
    fi
    child_attempt=$((child_attempt + 1))
  done
  report_ok=1
  report_json=""
  if [ -n "$child_report" ]; then
    # `local --sync` can return while the uploaded report is still being parsed. Preserve the
    # verifier's 30-minute execution budget and allow up to its separate 10-minute completion grace
    # before judging assertions; otherwise a valid but still-RUNNING child is recorded as a failure.
    report_wait=0
    while [ "$report_wait" -lt 120 ]; do
      report_json=$(satori-v2 report "$child_report" --org "$organization" --json 2>/dev/null || true)
      report_status=$(printf '%s' "$report_json" | jq --raw-output '.status // empty' 2>/dev/null)
      [ "$report_status" != "RUNNING" ] && [ -n "$report_status" ] && break
      report_wait=$((report_wait + 1))
      sleep 5
    done
  fi
  if [ -z "$child_report" ] \
    || ! printf '%s' "$report_json" \
      | jq --exit-status '(.status == "FINISHED") and ((.report.total_fails // 1) == 0)' >/dev/null
  then
    report_ok=0
  fi
  if [ "$run_rc" -eq 0 ] && [ "$report_ok" -eq 1 ]
  then
    echo "[$completed/$total] $label: report created"
  else
    echo "[$completed/$total] $label: child report failed (cli exit $run_rc, report ${child_report:-missing})" >&2
    failed=$((failed + 1))
  fi
  if [ -n "$checkout_root" ]; then
    rm -rf "$checkout_root"
  fi

  # A corpus run installs unrelated dependency trees for dozens of repositories in one parent
  # container. Keep package-manager caches from consuming the container disk between targets; each
  # pinned checkout remains reproducible from its lockfile and can download its own dependencies.
  npm cache clean --force >/dev/null 2>&1 || true
  if command -v yarn >/dev/null 2>&1; then
    yarn cache clean >/dev/null 2>&1 || true
  fi
  if command -v pnpm >/dev/null 2>&1; then
    pnpm store prune >/dev/null 2>&1 || true
  fi
done

echo "completed=$completed failed=$failed"
[ "$failed" -eq 0 ]
