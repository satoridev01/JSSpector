"""Fast, dependency-free invariants for the bundled online controller."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ONLINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ONLINE))

import claude_limits  # noqa: E402
import controller  # noqa: E402
import discover  # noqa: E402
import github  # noqa: E402


class ControllerTests(unittest.TestCase):
    def test_only_structurally_verified_findings_cross_the_gate(self) -> None:
        verified = {
            "fingerprint": "verified",
            "exploitation": {"outcome": "verified", "how": "proof"},
        }
        report = {
            "findings": [
                verified,
                {
                    "fingerprint": "existence-only",
                    "exploitation": {
                        "outcome": "verified",
                        "impact": "file-existence-only",
                    },
                },
                {
                    "fingerprint": "static-only",
                    "exploitation": {"outcome": "not-reproduced"},
                },
                {"fingerprint": "model-only"},
            ]
        }
        self.assertEqual(controller.verified_findings(report), [verified])
        self.assertEqual(controller.filtered_report(report)["findings"], [verified])

    def test_sync_identity_is_order_independent_and_revision_pinned(self) -> None:
        findings = [{"fingerprint": "b"}, {"fingerprint": "a"}]
        first = controller.sync_key("Owner/Repo", "abc123", findings)
        second = controller.sync_key("owner/repo", "abc123", list(reversed(findings)))
        changed = controller.sync_key("owner/repo", "def456", findings)
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)

    def test_sync_replays_verified_only_output_as_jsspector_for_its_repository(self) -> None:
        verified = {
            "fingerprint": "verified",
            "exploitation": {"outcome": "verified", "how": "proof"},
        }
        unverified = {
            "fingerprint": "static-only",
            "exploitation": {"outcome": "not-reproduced"},
        }
        result = controller.ResearchResult(
            repository="owner/repo",
            revision="abc123",
            security_advisories="disabled",
            repository_forks=42,
            repository_stars=99,
            report={"findings": [verified, unverified]},
            findings=(verified,),
        )
        state = {"schema_version": 1, "processed": {}, "synced": {}}

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            report_searches = 0
            promoted = False

            def inspect_sync(command, **_kwargs):
                nonlocal report_searches, promoted
                if "reports" in command:
                    report_searches += 1
                    items = [] if report_searches == 1 else [{"id": "report-1"}]
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps({"items": items}),
                        stderr="",
                    )
                if "issues" in command:
                    return mock.Mock(
                        returncode=0,
                        stdout=json.dumps(
                            {
                                "items": [
                                    {
                                        "id": "finding-1",
                                        "source": "TOOL",
                                        "exploitability": "EXPLOITABLE",
                                        "repository": "owner/repo",
                                        "status": "TP" if promoted else "OPEN",
                                    }
                                ]
                            }
                        ),
                        stderr="",
                    )
                if "status" in command:
                    self.assertEqual(
                        command,
                        [
                            "satori-v2",
                            "issue",
                            "finding-1",
                            "status",
                            "TP",
                        ],
                    )
                    promoted = True
                    return mock.Mock(returncode=0, stdout="{}", stderr="")
                stage = Path(command[command.index("local") + 1])
                playbook = (stage / ".satori.yml").read_text(encoding="utf-8")
                report = json.loads((stage / "report.json").read_text(encoding="utf-8"))
                replay = stage / "jsspector"
                self.assertIn("jsspector", playbook)
                self.assertIn("--format json", playbook)
                self.assertTrue(os.access(replay, os.X_OK))
                self.assertEqual(report["findings"], [verified])
                self.assertEqual(report["security_advisories"], "disabled")
                self.assertEqual(command[command.index("--repo") + 1], "owner/repo")
                self.assertEqual(command[command.index("--visibility") + 1], "private")
                tag_values = {
                    command[index + 1]: command[index + 2]
                    for index, value in enumerate(command)
                    if value == "--tag"
                }
                self.assertEqual(tag_values["repository_forks"], "42")
                self.assertEqual(tag_values["repository_stars"], "99")
                self.assertIn("--sync", command)
                return mock.Mock(returncode=0)

            with mock.patch.object(controller, "run", side_effect=inspect_sync):
                self.assertTrue(
                    controller.synchronize(
                        result,
                        satori_cli="satori-v2",
                        state=state,
                        state_path=state_path,
                        state_lock=threading.Lock(),
                    )
                )

        self.assertEqual(len(state["synced"]), 1)
        self.assertEqual(next(iter(state["synced"].values()))["execution_id"], "report-1")
        self.assertEqual(
            next(iter(state["synced"].values()))["confirmed_status"], "TP"
        )

    def test_sync_resumes_an_existing_report_without_creating_a_duplicate(self) -> None:
        verified = {
            "fingerprint": "verified",
            "exploitation": {"outcome": "verified", "how": "proof"},
        }
        result = controller.ResearchResult(
            repository="owner/repo",
            revision="abc123",
            security_advisories="enabled",
            report={"findings": [verified]},
            findings=(verified,),
        )
        state = {"schema_version": 1, "processed": {}, "synced": {}}

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            promoted = False

            def existing_sync(command, **_kwargs):
                nonlocal promoted
                self.assertNotIn("local", command)
                if "reports" in command:
                    payload = {"items": [{"id": "report-1"}]}
                elif "issues" in command:
                    self.assertIn("issues", command)
                    payload = {
                        "items": [
                            {
                                "id": "finding-1",
                                "source": "TOOL",
                                "exploitability": "EXPLOITABLE",
                                "repository": "owner/repo",
                                "status": "TP" if promoted else "OPEN",
                            }
                        ]
                    }
                else:
                    self.assertIn("status", command)
                    promoted = True
                    payload = {}
                return mock.Mock(
                    returncode=0, stdout=json.dumps(payload), stderr=""
                )

            with mock.patch.object(controller, "run", side_effect=existing_sync):
                self.assertTrue(
                    controller.synchronize(
                        result,
                        satori_cli="satori-v2",
                        state=state,
                        state_path=state_path,
                        state_lock=threading.Lock(),
                    )
                )

        self.assertEqual(next(iter(state["synced"].values()))["execution_id"], "report-1")
        self.assertEqual(
            next(iter(state["synced"].values()))["confirmed_status"], "TP"
        )

    def test_sync_is_not_recorded_when_true_positive_promotion_fails(self) -> None:
        verified = {
            "fingerprint": "verified",
            "exploitation": {"outcome": "verified", "how": "proof"},
        }
        result = controller.ResearchResult(
            repository="owner/repo",
            revision="abc123",
            security_advisories="disabled",
            report={"findings": [verified]},
            findings=(verified,),
        )
        state = {"schema_version": 1, "processed": {}, "synced": {}}

        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"

            def failed_promotion(command, **_kwargs):
                if "reports" in command:
                    payload = {"items": [{"id": "report-1"}]}
                elif "issues" in command:
                    payload = {
                        "items": [
                            {
                                "id": "finding-1",
                                "source": "TOOL",
                                "exploitability": "EXPLOITABLE",
                                "repository": "owner/repo",
                                "status": "OPEN",
                            }
                        ]
                    }
                else:
                    self.assertIn("status", command)
                    return mock.Mock(returncode=1, stdout="", stderr="failed")
                return mock.Mock(
                    returncode=0, stdout=json.dumps(payload), stderr=""
                )

            with mock.patch.object(controller, "run", side_effect=failed_promotion):
                self.assertFalse(
                    controller.synchronize(
                        result,
                        satori_cli="satori-v2",
                        state=state,
                        state_path=state_path,
                        state_lock=threading.Lock(),
                    )
                )

        self.assertEqual(state["synced"], {})

    def test_lane_assignment_depends_on_inventory_index_not_completion_order(self) -> None:
        args = Namespace(parallel_no_ai=2, parallel_ai=2)
        self.assertEqual(
            [controller.choose_lane(index, args) for index in range(8)],
            ["no-ai", "no-ai", "ai", "ai", "no-ai", "no-ai", "ai", "ai"],
        )

    def test_timeout_results_are_retried_but_completed_results_are_skipped(self) -> None:
        state = {
            "processed": {
                "owner/clean": {"verified": 0},
                "owner/clone-timeout": {"status": "clone-timeout"},
                "owner/static-timeout": {"status": "static-timeout"},
                "owner/verify-timeout": {"status": "verify-timeout"},
                "owner/permanent-failure": {"status": "static-failed"},
            }
        }
        self.assertEqual(
            controller.completed_repositories(state),
            frozenset({"owner/clean", "owner/permanent-failure"}),
        )

    def test_public_recipe_promotion_is_selected_by_the_evolution_environment(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(controller.fix_learning_flag(), "--learn-fixes")
        with mock.patch.dict(
            os.environ, {"JSSPECTOR_PUBLISH_FIXES": "1"}, clear=True
        ):
            self.assertEqual(controller.fix_learning_flag(), "--publish-fixes")

    def test_verification_reuses_checkout_and_fixes_in_the_proof_pass(self) -> None:
        finding = {
            "fingerprint": "verified",
            "exploitation": {"outcome": "verified"},
            "fix": {"outcome": "proven"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            checkout.mkdir()
            static = controller.StaticResult(
                repository="owner/repo",
                revision="abc123",
                security_advisories="disabled",
                repository_forks=42,
                repository_stars=99,
                candidates=({"fingerprint": "verified"},),
                checkout=checkout,
            )
            args = Namespace(
                verify_threads=2,
                verify_startup_timeout=180,
                verify_candidate_soft_timeout=180,
                verify_candidate_hard_timeout=300,
                verify_timeout=900,
                verify_extended_timeout=1800,
                fix_attempts=1,
                fix_timeout=600,
                fix_model="claude-opus-5-5",
                learn_fixes=True,
            )

            def verified_once(command, **kwargs):
                self.assertNotIn("--repo", command)
                self.assertEqual(command[2], str(checkout))
                self.assertIn("--no-inline-ignores", command)
                self.assertNotIn("--no-fix", command)
                self.assertIn("--fix-attempts", command)
                self.assertIn("--learn-fixes", command)
                budgets = kwargs["budgets"]
                self.assertEqual(budgets.normal_s, 900)
                self.assertEqual(budgets.extended_s, 1800)
                self.assertEqual(budgets.fix_s, 600)
                output = Path(command[command.index("--output") + 1])
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps({"findings": [finding]}), encoding="utf-8"
                )
                return mock.Mock(returncode=0)

            cleanup = {
                "containers": (),
                "networks": (),
                "images": (),
                "failures": [],
            }
            with (
                mock.patch.object(
                    controller, "run_verification", side_effect=verified_once
                ) as run,
                mock.patch.object(
                    controller,
                    "cleanup_owned_docker_resources",
                    return_value=cleanup,
                ) as docker_cleanup,
            ):
                result = controller.verify_repository(
                    static,
                    candidates=static.candidates,
                    args=args,
                    scanner=Path("/tmp/jsspector"),
                    run_dir=root,
                    lane="no-ai",
                    docker_slots=threading.BoundedSemaphore(1),
                    run_label="online_test",
                )

        self.assertEqual(run.call_count, 1)
        self.assertEqual(docker_cleanup.call_count, 1)
        cleanup_label = docker_cleanup.call_args.args[0]
        self.assertLessEqual(len(cleanup_label), 64)
        self.assertNotEqual(cleanup_label, "online_test")
        self.assertEqual(result.findings, (finding,))
        self.assertEqual(result.repository_forks, 42)
        self.assertEqual(result.repository_stars, 99)
        self.assertTrue(result.fix_attempted)
        self.assertTrue(result.fix_proven)

    def test_interrupted_static_work_is_not_an_operational_failure(self) -> None:
        candidate = discover.Candidate(
            repo="owner/repo", security_advisories="disabled"
        )
        args = Namespace(scan_threads=1, static_timeout=600)
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            checkout = controller.checkout_directory(run_dir, candidate.repo)
            checkout.mkdir(parents=True)
            interrupted = mock.Mock(returncode=130)
            with (
                mock.patch.object(
                    controller,
                    "clone_repository",
                    return_value=(checkout, None),
                ),
                mock.patch.object(controller, "run", return_value=interrupted),
            ):
                result = controller.static_repository(
                    candidate,
                    args=args,
                    scanner=Path("/tmp/jsspector"),
                    run_dir=run_dir,
                )

        self.assertTrue(result.cancelled)
        self.assertFalse(result.failed)

    def test_tui_event_is_one_parseable_line(self) -> None:
        stream = io.StringIO()
        with mock.patch.dict(os.environ, {"JSSPECTOR_ONLINE_EVENTS": "1"}), contextlib.redirect_stdout(stream):
            controller.emit_event("verification_finished", repository="owner/repo", findings=2)
        line = stream.getvalue().strip()
        self.assertTrue(line.startswith(controller.EVENT_PREFIX))
        payload = json.loads(line.removeprefix(controller.EVENT_PREFIX))
        self.assertEqual(payload["schema"], 1)
        self.assertEqual(payload["type"], "verification_finished")
        self.assertEqual(payload["findings"], 2)

    def test_online_defaults_match_the_public_command(self) -> None:
        args = controller.parse_args([])
        self.assertEqual(args.since, 24 * 60 * 60)
        self.assertEqual(args.min_forks, 0)
        self.assertTrue(args.all_candidates)
        self.assertEqual(args.pvr, "off")
        self.assertEqual(args.static_parallel, 12)
        self.assertEqual(args.max_checkouts, 24)
        self.assertEqual(args.parallel_no_ai, 2)
        self.assertEqual(args.parallel_ai, 2)
        self.assertEqual(args.parallel_docker, 4)
        self.assertEqual(args.min_free_gb, 100)
        self.assertEqual(args.docker_cache_gb, 20)
        self.assertEqual(args.docker_gc_every, 8)
        self.assertEqual(controller.DISK_WATCHDOG_INTERVAL_S, 60)
        self.assertEqual(args.clone_timeout, 120)
        self.assertEqual(args.static_timeout, 600)
        self.assertEqual(args.max_repo_size_mb, 100)
        self.assertEqual(args.verify_startup_timeout, 180)
        self.assertEqual(args.verify_candidate_soft_timeout, 180)
        self.assertEqual(args.verify_candidate_hard_timeout, 300)
        self.assertEqual(args.verify_timeout, 900)
        self.assertEqual(args.verify_extended_timeout, 1800)
        self.assertEqual(args.ai_attempts, 1)
        self.assertEqual(args.ai_timeout, 60)
        self.assertEqual(args.fix_timeout, 600)
        self.assertEqual(args.satori_profile, "satoridev05")

    def test_adaptive_budget_only_extends_on_positive_evidence(self) -> None:
        budget = controller.VerificationBudgetState(
            started=0,
            startup_s=180,
            candidate_soft_s=180,
            candidate_hard_s=300,
            normal_s=900,
            extended_s=1800,
            fix_s=600,
        )
        budget.observe({"event": "candidate_started"}, 10)
        self.assertEqual(budget.timed_out(191), "verify-startup-timeout")

        budget.observe({"event": "app_ready"}, 200)
        budget.observe({"event": "request_activity"}, 210)
        self.assertIsNone(budget.timed_out(499))
        self.assertEqual(budget.timed_out(500), "verify-candidate-hard-timeout")

        budget.observe({"event": "positive_evidence"}, 220)
        self.assertIsNone(budget.timed_out(1000))
        self.assertEqual(budget.timed_out(1800), "verify-repository-timeout")
        budget.observe({"event": "fix_started"}, 1800)
        self.assertIsNone(budget.timed_out(2399))
        self.assertEqual(budget.timed_out(2400), "fix-timeout")

    def test_satori_blacklist_unions_account_issues_and_advisories(self) -> None:
        with mock.patch.object(
            controller,
            "_satori_paged_items",
            side_effect=[
                [{"repository": "Owner/Issue"}, {"repository": "shared/repo"}],
                [{"repository": "Owner/Advisory"}, {"repository": "shared/repo"}],
            ],
        ):
            inventory = controller.satori_repository_blacklist("satori-v2")
        self.assertEqual(inventory["issues"], ["Owner/Issue", "shared/repo"])
        self.assertEqual(
            inventory["advisories"], ["Owner/Advisory", "shared/repo"]
        )

    def test_online_refuses_to_start_below_the_disk_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            with (
                mock.patch.object(
                    controller,
                    "capture_docker_inventory",
                    return_value=controller.DockerInventory(frozenset(), frozenset()),
                ),
                mock.patch.object(
                    controller,
                    "cleanup_online_docker_storage",
                    return_value={"images": 0, "volumes": 0, "failures": []},
                ),
                mock.patch.object(controller, "free_disk_gb", return_value=50.0),
            ):
                with self.assertRaisesRegex(SystemExit, "requires 100 GiB"):
                    controller.main(
                        [
                            "--scanner",
                            controller.__file__,
                            "--out",
                            str(out),
                        ]
                    )
            # The failed preflight releases ownership so a later resumable run is possible.
            lock = controller.acquire_run_lock(out)
            lock.close()

    def test_security_advisory_state_is_explicit_and_conservative(self) -> None:
        candidate = discover.Candidate(repo="owner/repo")
        self.assertEqual(candidate.security_advisories, "unknown")

    def test_live_discovery_resolves_advisories_in_parallel_and_prioritizes_forks(self) -> None:
        candidates = [
            discover.Candidate(repo="owner/first", forks=3),
            discover.Candidate(repo="owner/second", forks=1),
            discover.Candidate(repo="owner/third", forks=8),
        ]
        pool = mock.Mock()
        pool.recommended_parallelism = 2
        pool.has_pvr.side_effect = {
            "owner/first": False,
            "owner/second": True,
            "owner/third": False,
        }.get
        discovery = discover.Discovery(
            pool,
            discover.Config(pvr_mode="off", pvr_parallel=3),
        )
        wanted = io.StringIO()
        rejected = io.StringIO()
        with mock.patch.object(
            discovery.searcher, "stream", return_value=iter(candidates)
        ):
            discovery._sweep(
                datetime.now(timezone.utc),
                {True: wanted, False: rejected},
                None,
                lambda: False,
            )
        self.assertEqual(
            wanted.getvalue().splitlines(), ["owner/third", "owner/first"]
        )
        self.assertEqual(rejected.getvalue().splitlines(), ["owner/second"])
        self.assertEqual(discovery.metrics.pvr_checks, 3)

    def test_default_discovery_has_no_fork_or_star_exclusion(self) -> None:
        cfg = discover.Config()
        self.assertEqual(cfg.min_forks, 0)
        self.assertTrue(cfg.all_candidates)
        query = discover.tier_query(
            cfg,
            "stars:0",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        self.assertNotIn("forks:", query)
        self.assertIn("stars:0", query)

    def test_discovery_filters_oversized_repositories_before_pvr(self) -> None:
        searcher = discover.Searcher(
            mock.Mock(), discover.Config(max_repo_size_kb=100 * 1024)
        )
        items = [
            {
                "full_name": "owner/too-large",
                "size": 100 * 1024 + 1,
                "owner": {},
            },
            {"full_name": "owner/kept", "size": 100 * 1024, "owner": {}},
        ]
        self.assertEqual(
            [candidate.repo for candidate in searcher._new(items, "stars:0")],
            ["owner/kept"],
        )
        self.assertEqual(searcher.metrics.oversized, 1)

    def test_unfiltered_discovery_batches_are_also_prioritized_by_forks(self) -> None:
        candidates = [
            discover.Candidate(repo="owner/least", forks=0),
            discover.Candidate(repo="owner/most", forks=20),
            discover.Candidate(repo="owner/middle", forks=4),
        ]
        discovery = discover.Discovery(
            mock.Mock(),
            discover.Config(pvr_mode="any"),
        )
        wanted = io.StringIO()
        rejected = io.StringIO()
        with mock.patch.object(
            discovery.searcher, "stream", return_value=iter(candidates)
        ):
            discovery._sweep(
                datetime.now(timezone.utc),
                {True: wanted, False: rejected},
                None,
                lambda: False,
            )
        self.assertEqual(
            wanted.getvalue().splitlines(),
            ["owner/most", "owner/middle", "owner/least"],
        )

    def test_static_analysis_starts_before_discovery_completes(self) -> None:
        static_started = threading.Event()
        discovery_completed = threading.Event()

        def fake_discovery(_path, *, on_found, **_kwargs):
            candidate = discover.Candidate(
                repo="owner/repo", security_advisories="disabled"
            )
            on_found(candidate)
            self.assertTrue(static_started.wait(2))
            discovery_completed.set()
            return [candidate], {"found": 1}

        def fake_static(candidate, **_kwargs):
            self.assertFalse(discovery_completed.is_set())
            static_started.set()
            return controller.StaticResult(
                repository=candidate.repo,
                revision="abc123",
                security_advisories=candidate.security_advisories,
            )

        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            inventory = Path(temporary) / "repos.txt"
            inventory.write_text("owner/repo\n", encoding="utf-8")
            cleanup = {"containers": (), "networks": (), "images": (), "failures": []}
            with (
                mock.patch.object(
                    controller, "candidates_from_file", side_effect=fake_discovery
                ),
                mock.patch.object(controller, "static_repository", side_effect=fake_static),
                mock.patch.object(
                    controller,
                    "cleanup_owned_docker_resources",
                    return_value=cleanup,
                ),
                mock.patch.object(
                    controller,
                    "capture_docker_inventory",
                    return_value=controller.DockerInventory(frozenset(), frozenset()),
                ),
                mock.patch.object(
                    controller,
                    "cleanup_online_docker_storage",
                    return_value={"images": 0, "volumes": 0, "failures": []},
                ),
                mock.patch.object(controller, "free_disk_gb", return_value=500.0),
            ):
                exit_code = controller.main(
                    [
                        "--scanner",
                        controller.__file__,
                        "--repos-file",
                        str(inventory),
                        "--pvr",
                        "any",
                        "--out",
                        str(out),
                    ]
                )

            run_directories = list((out / "runs").iterdir())
            self.assertEqual(len(run_directories), 1)
            persisted_log = (run_directories[0] / "online.log").read_text(
                encoding="utf-8"
            )
            failures = json.loads(
                (run_directories[0] / "failures.json").read_text(encoding="utf-8")
            )
            metrics = json.loads(
                (run_directories[0] / "online.json").read_text(encoding="utf-8")
            )

        self.assertEqual(exit_code, 0)
        self.assertTrue(discovery_completed.is_set())
        self.assertIn("ONLINE_START", persisted_log)
        self.assertIn("ONLINE_DONE", persisted_log)
        self.assertEqual(failures, {"failures": []})
        self.assertEqual(metrics["configuration"]["fix_attempts"], 0)
        self.assertEqual(metrics["configuration"]["ai_timeout"], 60)
        self.assertEqual(metrics["configuration"]["max_checkouts"], 24)
        self.assertIsNone(controller.LOG_PATH)

    def test_checkout_budget_backpressures_static_cloning(self) -> None:
        verification_started = threading.Event()
        allow_verification = threading.Event()
        static_repositories: list[str] = []
        static_lock = threading.Lock()

        candidates = [
            discover.Candidate(repo="owner/first", security_advisories="disabled"),
            discover.Candidate(repo="owner/second", security_advisories="disabled"),
        ]

        def fake_discovery(_path, *, on_found, **_kwargs):
            for candidate in candidates:
                on_found(candidate)
            self.assertTrue(verification_started.wait(2))
            with static_lock:
                self.assertEqual(static_repositories, ["owner/first"])
            allow_verification.set()
            return candidates, {"found": len(candidates)}

        def fake_static(candidate, *, run_dir, **_kwargs):
            with static_lock:
                static_repositories.append(candidate.repo)
            checkout = controller.checkout_directory(run_dir, candidate.repo)
            checkout.mkdir(parents=True)
            return controller.StaticResult(
                repository=candidate.repo,
                revision="abc123",
                security_advisories=candidate.security_advisories,
                candidates=({"fingerprint": candidate.repo},),
                checkout=checkout,
            )

        def fake_verify(static, **_kwargs):
            verification_started.set()
            self.assertTrue(allow_verification.wait(2))
            return controller.ResearchResult(
                repository=static.repository,
                revision=static.revision,
                security_advisories=static.security_advisories,
                report={"findings": []},
            )

        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "out"
            inventory = Path(temporary) / "repos.txt"
            inventory.write_text("owner/first\nowner/second\n", encoding="utf-8")
            cleanup = {"containers": (), "networks": (), "images": (), "failures": []}
            with (
                mock.patch.object(
                    controller, "candidates_from_file", side_effect=fake_discovery
                ),
                mock.patch.object(controller, "static_repository", side_effect=fake_static),
                mock.patch.object(controller, "verify_repository", side_effect=fake_verify),
                mock.patch.object(
                    controller,
                    "cleanup_owned_docker_resources",
                    return_value=cleanup,
                ),
                mock.patch.object(
                    controller,
                    "capture_docker_inventory",
                    return_value=controller.DockerInventory(frozenset(), frozenset()),
                ),
                mock.patch.object(
                    controller,
                    "cleanup_online_docker_storage",
                    return_value={"images": 0, "volumes": 0, "failures": []},
                ),
                mock.patch.object(controller, "free_disk_gb", return_value=500.0),
            ):
                exit_code = controller.main(
                    [
                        "--scanner",
                        controller.__file__,
                        "--repos-file",
                        str(inventory),
                        "--pvr",
                        "any",
                        "--out",
                        str(out),
                        "--max-checkouts",
                        "1",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(static_repositories, ["owner/first", "owner/second"])

    def test_claude_envelope_decoder_tolerates_cli_notices(self) -> None:
        value = 'notice\n{"result":"{\\"fingerprints\\":[\\"abc\\"]}"}\ntrailing'
        self.assertEqual(controller._decode_claude(value), {"fingerprints": ["abc"]})

    def test_usage_limit_reset_keeps_a_safety_margin(self) -> None:
        now = datetime(2026, 11, 25, 10, 0, tzinfo=timezone.utc)
        reset = claude_limits.resume_at("usage limit; resets at 11:30", now)
        self.assertEqual(reset.hour, 11)
        self.assertEqual(reset.minute, 31)

    def test_safe_shutdown_stops_every_registered_child(self) -> None:
        child = mock.Mock(pid=12345)
        controller.SHUTDOWN.clear()
        controller.ACTIVE_PROCESSES.clear()
        controller.ACTIVE_PROCESSES[child.pid] = child
        try:
            with mock.patch.object(controller, "terminate_process_tree") as terminate:
                controller.request_shutdown()
            self.assertTrue(controller.SHUTDOWN.is_set())
            terminate.assert_called_once_with(child)
        finally:
            controller.ACTIVE_PROCESSES.clear()
            controller.SHUTDOWN.clear()

    def test_github_waits_stop_without_starting_another_request(self) -> None:
        pool = github.TokenPool(["token"], should_stop=lambda: True)
        with mock.patch.object(github.urllib.request, "urlopen") as urlopen:
            items, total = pool.search("language:JavaScript")
        self.assertIsNone(items)
        self.assertEqual(total, 0)
        urlopen.assert_not_called()

    def test_docker_cleanup_queries_only_the_exact_run_label(self) -> None:
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(controller.subprocess, "run", return_value=completed) as run:
            resources = controller._owned_docker_resources("online_run_42")
        self.assertEqual(resources, {"containers": (), "networks": (), "images": ()})
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(calls), 3)
        for command in calls:
            self.assertIn(
                "label=ci.satori.jsspector.verify-run=online_run_42", command
            )

    def test_docker_gc_uses_image_ids_and_preserves_reusable_caches(self) -> None:
        def docker_output(command: list[str], **_kwargs):
            if command[1:3] == ["image", "ls"]:
                return mock.Mock(
                    returncode=0,
                    stdout=(
                        "session-id jsspector-verify:session\n"
                        "dangling-id <none>:<none>\n"
                        "cache-id jsspector-verify-cache:content\n"
                        "browser-base-id jsspector-verify-xss-browser:base\n"
                    ),
                )
            return mock.Mock(returncode=0, stdout="")

        with mock.patch.object(controller.subprocess, "run", side_effect=docker_output):
            resources = controller._owned_docker_resources("online_run_42")

        self.assertEqual(resources["images"], ("dangling-id", "session-id"))

    def test_online_storage_gc_only_targets_objects_created_after_start(self) -> None:
        baseline = controller.DockerInventory(
            images=frozenset({"existing-image"}),
            volumes=frozenset({"existing-volume"}),
        )
        current = controller.DockerInventory(
            images=frozenset({"existing-image", "run-image"}),
            volumes=frozenset({"existing-volume", "run-volume"}),
        )
        with (
            mock.patch.object(controller, "capture_docker_inventory", return_value=current),
            mock.patch.object(
                controller, "_docker_cleanup_command", return_value=None
            ) as cleanup,
        ):
            result = controller.cleanup_online_docker_storage(
                baseline,
                cache_gb=20,
                min_free_gb=100,
            )

        commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertIn(["docker", "image", "rm", "run-image"], commands)
        self.assertIn(["docker", "volume", "rm", "run-volume"], commands)
        self.assertNotIn("existing-image", str(commands))
        self.assertNotIn("existing-volume", str(commands))
        self.assertIn("--max-used-space", commands[-1])
        self.assertIn("--min-free-space", commands[-1])
        self.assertEqual(result["images"], 1)
        self.assertEqual(result["volumes"], 1)

    def test_docker_inventory_failure_disables_run_delta_deletion(self) -> None:
        with mock.patch.object(
            controller.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["docker"], 30),
        ):
            self.assertIsNone(controller.capture_docker_inventory())

    def test_verification_labels_are_unique_and_docker_safe(self) -> None:
        first = controller.verification_run_label(
            "online_20261126T003430991573Z_88491",
            "owner/first",
            "abc123",
            "no-ai",
        )
        second = controller.verification_run_label(
            "online_20261126T003430991573Z_88491",
            "owner/second",
            "abc123",
            "no-ai",
        )
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 64)
        self.assertRegex(first, r"^[A-Za-z0-9_-]+$")

    def test_one_controller_owns_each_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            first = controller.acquire_run_lock(out)
            try:
                with self.assertRaisesRegex(RuntimeError, "another jsspector online"):
                    controller.acquire_run_lock(out)
            finally:
                first.close()
            second = controller.acquire_run_lock(out)
            second.close()


if __name__ == "__main__":
    unittest.main()
