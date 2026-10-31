# Corpus research (seed data, 2026-10-31)

These files come from the planning session that produced [`docs/PLAN.md`](../../docs/PLAN.md). All data is public: published GitHub security advisories and repository metadata, collected with `gh api`. No repository code was executed.

| File | Contents |
|---|---|
| `cve-replay-seed.json` | 15 repos. Each lists all critical/high published advisories by class and has up to 8 deep-dived **replay candidates** (fix commit, vulnerable commit = `fix^1`, fix files, entry point, sink). An adversarial verifier re-checked every taint-style candidate against the fix diff and the sink line at the vulnerable commit: **84 pairs are replay-ready** (`verification.verdict` is `verified` or `corrected`). |
| `candidate-pool.json` | 148 candidate repos from three discovery angles (npm advisory DB, self-hosted Node apps, framework/entry-point coverage), with published critical/high counts, plus a critic's review notes and swaps. |
| `batches.json` | The approved corpus: 100 repos in 10 batches of 10, ordered by roadmap milestone, plus 15 reserves. The 10 holdout repos are drawn from the reserves with a fixed seed at M0. |

## How this data is used

- `xtask corpus import` turns these records into per-repo manifests in `corpus/repos/<owner>__<name>.toml`.
- `xtask corpus verify` then re-checks every pair (`fix^1`, JS/TS hunks inside the scan roots, anchors) before a batch starts.
- A repo with no resolvable in-scope advisory is swapped for a reserve.

## Caveats

- Advisory counts are repo-level *published* advisories as of 2026-10-31.
- Mixed-language repos (siyuan, open-webui) count only their JS/TS-relevant advisories.
- Authorization/logic, DoS, CI, supply-chain and dependency advisories are kept but labeled out of scope for taint recall.
- `FlowiseAI/Flowise` is archived. It is used for replay only.
