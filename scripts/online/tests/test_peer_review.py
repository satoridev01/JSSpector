"""Focused tests for the trusted Codex peer-review harness."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ONLINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ONLINE))

import peer_review  # noqa: E402


def finding(*, fixed: bool = False) -> dict:
    value = {
        "fingerprint": "finding-1",
        "class": "path-traversal",
        "exploitation": {
            "outcome": "verified",
            "impact": "confidentiality",
        },
        "poc": {"command": "curl /../../tmp/canary", "output": "CANARY token"},
    }
    if fixed:
        value["fix"] = {"outcome": "proven", "diff": "--- a/x\n+++ b/x\n"}
    return value


class PeerReviewTests(unittest.TestCase):
    def prepare(self, root: Path, *, fixed: bool = False) -> peer_review.ReviewBundle:
        subject = root / "subject"
        subject.mkdir(parents=True)
        selected = finding(fixed=fixed)
        return peer_review.prepare_review_bundle(
            root / "review",
            subject=subject,
            repository="owner/repo",
            revision="abc123",
            report={"findings": [selected], "version": 1},
            finding=selected,
            recipe_stage=(
                {
                    "schema_version": 1,
                    "source_fingerprint": "finding-1",
                    "recipe": {"id": "anonymous"},
                }
                if fixed
                else None
            ),
            recipe_stage_sha256="b" * 64 if fixed else None,
        )

    def verdict(
        self,
        bundle: peer_review.ReviewBundle,
        *,
        decision: str = "publish_unfixed",
        exploit: str = "real",
        reproduced: bool = True,
        fix: str = "absent",
        negative_controls: list[str] | None = None,
    ) -> dict:
        fixed = fix == "verified"
        return {
            "schema_version": 1,
            "finding_fingerprint": bundle.fingerprint,
            "reviewed_commit": bundle.revision,
            "artifact_sha256": bundle.artifact_sha256,
            "reviewer": {
                "model": "gpt-5.6-sol",
                "reasoning_effort": "medium",
                "cyber_access_program": "daybreak_blue",
                "duration_ms": 100,
            },
            "agents": [
                {
                    "agent": name,
                    "duration_ms": 30,
                    "conclusion": "independent result",
                    "evidence_refs": ["evidence.json#/report/findings/0"],
                }
                for name in sorted(peer_review.AGENT_NAMES)
            ],
            "exploit": {
                "verdict": exploit,
                "reproduced": reproduced,
                "cia": ["confidentiality"] if exploit == "real" else [],
                "sink_observed": exploit == "real",
                "positive_controls": ["CANARY token"] if exploit == "real" else [],
                "negative_controls": negative_controls or [],
                "evidence_refs": ["evidence.json#/report/findings/0"],
            },
            "fix": {
                "status": fix,
                "diff_sha256": bundle.fix_diff_sha256 if fixed else None,
                "exploit_blocked": fixed,
                "legitimate_behavior_preserved": fixed,
                "tests": ["poc", "benign"] if fixed else [],
                "bypasses_tested": ["encoded traversal"] if fixed else [],
            },
            "recipe": {
                "action": "promote" if fixed else "none",
                "anonymous": fixed,
                "safe_to_publish": fixed,
                "stage_sha256": bundle.recipe_stage_sha256,
            },
            "dissent": [],
            "operational_errors": [],
            "decision": decision,
        }

    def test_bundle_is_content_bound_and_defines_three_agent_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary), fixed=True)
            evidence = json.loads(bundle.evidence.read_text())
            without_digest = dict(evidence)
            del without_digest["artifact_sha256"]
            self.assertEqual(bundle.artifact_sha256, peer_review._sha256(without_digest))
            self.assertEqual(
                evidence["report"]["findings"], [finding(fixed=True)]
            )
            self.assertEqual(evidence["fix_diff_sha256"], bundle.fix_diff_sha256)
            self.assertEqual(evidence["recipe_stage"]["recipe"]["id"], "anonymous")
            prompt = bundle.prompt.read_text()
            self.assertIn("Spawn exactly three generic subagents", prompt)
            self.assertIn("<BEGIN_UNTRUSTED_EVIDENCE_JSON>", prompt)
            self.assertIn('"finding_fingerprint": "finding-1"', prompt)
            for name in peer_review.AGENT_NAMES:
                self.assertIn(f"ROLE {name}", prompt)
            self.assertFalse(bundle.evidence.stat().st_mode & stat.S_IWUSR)

    def test_artifact_hash_ignores_the_run_specific_report_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = finding()
            bundles = []
            for index in range(2):
                subject = root / f"subject-{index}"
                subject.mkdir()
                bundles.append(
                    peer_review.prepare_review_bundle(
                        root / f"review-{index}",
                        subject=subject,
                        repository="owner/repo",
                        revision="abc123",
                        report={
                            "root": f"/volatile/run-{index}/checkout",
                            "findings": [selected],
                            "version": 1,
                        },
                        finding=selected,
                    )
                )
            evidence = json.loads(bundles[0].evidence.read_text())
        self.assertEqual(bundles[0].artifact_sha256, bundles[1].artifact_sha256)
        self.assertNotIn("root", evidence["report"])

    def test_command_pins_model_effort_daybreak_schema_and_subagents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary))
            command = peer_review.codex_command(bundle, peer_review.PeerReviewConfig())
        self.assertEqual(command[0], "codex")
        self.assertIn("gpt-5.6-sol", command)
        self.assertIn('model_reasoning_effort="medium"', command)
        self.assertIn("agents.max_concurrent_threads_per_session=3", command)
        self.assertIn("daybreak_blue", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertIn("shell_environment_policy.ignore_default_excludes=false", command)
        self.assertNotIn("--ephemeral", command)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertIn("--output-schema", command)
        self.assertIn("--output-last-message", command)

    def test_environment_keeps_codex_auth_but_drops_operational_secrets(self) -> None:
        cleaned = peer_review.sanitized_environment(
            {
                "PATH": "/bin",
                "HOME": "/home/reviewer",
                "CODEX_HOME": "/codex",
                "OPENAI_API_KEY": "review-auth",
                "SATORI_TOKEN": "no",
                "SATORI_PROFILE": "no",
                "GITHUB_TOKEN": "no",
                "GH_TOKEN": "no",
                "AWS_SECRET_ACCESS_KEY": "no",
                "DOCKER_HOST": "no",
                "ANTHROPIC_API_KEY": "no",
            }
        )
        self.assertEqual(cleaned["OPENAI_API_KEY"], "review-auth")
        self.assertEqual(cleaned["CODEX_HOME"], "/codex")
        self.assertNotIn("SATORI_TOKEN", cleaned)
        self.assertNotIn("GITHUB_TOKEN", cleaned)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", cleaned)
        self.assertNotIn("DOCKER_HOST", cleaned)

    def test_semantic_gate_accepts_fixed_and_unfixed_real_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.prepare(root / "unfixed")
            fixed_bundle = self.prepare(root / "fixed", fixed=True)
            unfixed = peer_review.validate_verdict(
                self.verdict(bundle), bundle, peer_review.PeerReviewConfig()
            )
            fixed = peer_review.validate_verdict(
                self.verdict(
                    fixed_bundle, decision="publish_fixed", fix="verified"
                ),
                fixed_bundle,
                peer_review.PeerReviewConfig(),
            )
        self.assertTrue(unfixed.publishable)
        self.assertFalse(unfixed.promotes_recipe)
        self.assertTrue(fixed.promotes_recipe)

    def test_verified_fix_hash_is_controller_authored_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary), fixed=True)
            value = self.verdict(bundle, decision="publish_fixed", fix="verified")
            value["fix"]["diff_sha256"] = "f" * 64
            normalized = peer_review._normalize_controller_fields(
                value,
                bundle=bundle,
                config=peer_review.PeerReviewConfig(),
                receipt={"agents": []},
                elapsed_s=1.25,
            )
            self.assertEqual(
                normalized["fix"]["diff_sha256"], bundle.fix_diff_sha256
            )
            peer_review.validate_verdict(
                normalized, bundle, peer_review.PeerReviewConfig()
            )
            normalized["fix"]["diff_sha256"] = "f" * 64
            with self.assertRaisesRegex(ValueError, "does not match evidence"):
                peer_review.validate_verdict(
                    normalized, bundle, peer_review.PeerReviewConfig()
                )
            no_diff = self.prepare(Path(temporary) / "without-diff")
            missing = self.verdict(no_diff, decision="publish_fixed", fix="verified")
            with self.assertRaisesRegex(ValueError, "does not match evidence"):
                peer_review.validate_verdict(
                    missing, no_diff, peer_review.PeerReviewConfig()
                )

    def test_real_exploit_requires_known_cia_and_a_positive_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary))
            unknown = self.verdict(bundle)
            unknown["exploit"]["cia"] = ["privacy"]
            with self.assertRaisesRegex(ValueError, "unknown impact"):
                peer_review.validate_verdict(
                    unknown, bundle, peer_review.PeerReviewConfig()
                )
            no_positive = self.verdict(bundle)
            no_positive["exploit"]["positive_controls"] = []
            with self.assertRaisesRegex(ValueError, "real exploit"):
                peer_review.validate_verdict(
                    no_positive, bundle, peer_review.PeerReviewConfig()
                )

    def test_false_positive_needs_two_independent_negative_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary))
            invalid = self.verdict(
                bundle,
                decision="delete_false_positive",
                exploit="false_positive",
                reproduced=False,
                fix="absent",
                negative_controls=["one"],
            )
            with self.assertRaisesRegex(ValueError, "two independent"):
                peer_review.validate_verdict(
                    invalid, bundle, peer_review.PeerReviewConfig()
                )
            duplicates = self.verdict(
                bundle,
                decision="delete_false_positive",
                exploit="false_positive",
                reproduced=False,
                fix="absent",
                negative_controls=["same", "same"],
            )
            with self.assertRaisesRegex(ValueError, "duplicates"):
                peer_review.validate_verdict(
                    duplicates, bundle, peer_review.PeerReviewConfig()
                )
            empty = self.verdict(
                bundle,
                decision="delete_false_positive",
                exploit="false_positive",
                reproduced=False,
                fix="absent",
                negative_controls=["one", " "],
            )
            with self.assertRaisesRegex(ValueError, "empty"):
                peer_review.validate_verdict(
                    empty, bundle, peer_review.PeerReviewConfig()
                )
            valid = dict(invalid)
            valid["exploit"] = dict(invalid["exploit"])
            valid["exploit"]["negative_controls"] = ["one", "two"]
            result = peer_review.validate_verdict(
                valid, bundle, peer_review.PeerReviewConfig()
            )
        self.assertEqual(result.decision, "delete_false_positive")

    def test_fake_codex_writes_a_valid_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.prepare(root)
            desired = self.verdict(bundle)
            desired["reviewer"] = {
                "model": "fabricated",
                "reasoning_effort": "fabricated",
                "cyber_access_program": "fabricated",
                "duration_ms": 0,
            }
            fake = root / "fake-codex"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json,os,sqlite3,sys,time\n"
                "if len(sys.argv)>1 and sys.argv[1]=='delete': time.sleep(.03); sys.exit(0)\n"
                f"value={json.dumps(desired)!r}\n"
                "args=sys.argv[1:]\n"
                "out=args[args.index('--output-last-message')+1]\n"
                "open(out,'w').write(value)\n"
                "home=os.environ['CODEX_HOME']; os.makedirs(home,exist_ok=True)\n"
                "root='00000000-0000-0000-0000-000000000001'\n"
                "roles=['exploit_replayer','exploit_skeptic','fix_adversary']\n"
                "state=sqlite3.connect(os.path.join(home,'state_1.sqlite'))\n"
                "state.execute('CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT, status TEXT)')\n"
                "state.execute('CREATE TABLE threads (id TEXT, agent_path TEXT, model TEXT, reasoning_effort TEXT)')\n"
                "history=sqlite3.connect(os.path.join(home,'thread_history_1.sqlite'))\n"
                "history.execute('CREATE TABLE thread_turns (thread_id TEXT, status TEXT, duration_ms INTEGER)')\n"
                "for i,role in enumerate(roles,2):\n"
                " child=f'00000000-0000-0000-0000-{i:012d}'\n"
                " state.execute('INSERT INTO thread_spawn_edges VALUES (?,?,?)',(root,child,'open'))\n"
                " state.execute('INSERT INTO threads VALUES (?,?,?,?)',(child,'/root/'+role,'gpt-5.6-sol','medium'))\n"
                " history.execute('INSERT INTO thread_turns VALUES (?,?,?)',(child,'completed',100+i))\n"
                "state.commit(); history.commit(); state.close(); history.close()\n"
                "sys.stdin.read()\n"
                "print(json.dumps({'type':'thread.started','thread_id':root}))\n"
                "print(json.dumps({'type':'turn.completed'}))\n"
            )
            fake.chmod(0o700)
            config = peer_review.PeerReviewConfig(codex_cli=str(fake), timeout_s=15)
            result = peer_review.run_peer_review(
                bundle,
                config,
                environment={
                    "PATH": os.environ["PATH"],
                    "CODEX_HOME": str(root / "codex-home"),
                },
            )
        self.assertEqual(result.returncode, 0)
        self.assertIsNotNone(result.verdict)
        self.assertEqual(result.verdict.decision, "publish_unfixed")
        self.assertEqual(result.verdict.raw["reviewer"]["model"], "gpt-5.6-sol")
        self.assertTrue(result.collaboration_receipt["verified"])
        self.assertEqual(
            result.verdict.raw["controller_receipt"], result.collaboration_receipt
        )
        self.assertEqual(len(result.collaboration_receipt["agents"]), 3)
        self.assertEqual(
            result.collaboration_receipt["artifact_sha256"], bundle.artifact_sha256
        )
        self.assertGreaterEqual(
            result.elapsed_s - result.verdict.raw["reviewer"]["duration_ms"] / 1000,
            0.08,
        )

    def test_collaboration_receipt_is_bound_to_the_exact_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = self.prepare(Path(temporary), fixed=True)
            receipt = {
                "schema_version": 1,
                "verified": True,
                "policy_version": peer_review.POLICY_VERSION,
                "artifact_sha256": bundle.artifact_sha256,
                "finding_fingerprint": bundle.fingerprint,
                "reviewed_commit": bundle.revision,
                "recipe_stage_sha256": bundle.recipe_stage_sha256,
                "root_thread_sha256": "a" * 64,
                "agents": [
                    {
                        "agent": name,
                        "model": "gpt-5.6-sol",
                        "reasoning_effort": "medium",
                        "duration_ms": 1,
                        "thread_sha256": f"{index:x}" * 64,
                        "completed": True,
                    }
                    for index, name in enumerate(sorted(peer_review.AGENT_NAMES), 1)
                ],
            }
            peer_review.validate_collaboration_receipt(
                receipt, peer_review.PeerReviewConfig(), bundle
            )
            for key in (
                "policy_version",
                "artifact_sha256",
                "finding_fingerprint",
                "reviewed_commit",
                "recipe_stage_sha256",
            ):
                mismatched = dict(receipt)
                mismatched[key] = "mismatch"
                with self.subTest(key=key), self.assertRaisesRegex(
                    ValueError, key
                ):
                    peer_review.validate_collaboration_receipt(
                        mismatched, peer_review.PeerReviewConfig(), bundle
                    )
            invalid_hash = dict(receipt)
            invalid_hash["root_thread_sha256"] = "z" * 64
            with self.assertRaisesRegex(ValueError, "root hash"):
                peer_review.validate_collaboration_receipt(
                    invalid_hash, peer_review.PeerReviewConfig(), bundle
                )

    def test_session_deletion_attempts_every_id_and_aggregates_failures(self) -> None:
        completed = subprocess.CompletedProcess([], 1, "", "first failed")
        timed_out = subprocess.TimeoutExpired(["codex", "delete"], 30)
        with mock.patch.object(
            peer_review.subprocess,
            "run",
            side_effect=[
                completed,
                timed_out,
                subprocess.CompletedProcess([], 0, "", ""),
            ],
        ) as run:
            error = peer_review._delete_codex_sessions(
                ("a", "b", "c"), peer_review.PeerReviewConfig(), {"PATH": "/bin"}
            )
        self.assertEqual(run.call_count, 3)
        self.assertIn("first failed", error)
        self.assertIn("timed out", error)

    def test_timeout_is_operational_not_a_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = self.prepare(root)
            fake = root / "slow-codex"
            fake.write_text("#!/bin/sh\nsleep 10\n")
            fake.chmod(0o700)
            config = peer_review.PeerReviewConfig(
                codex_cli=str(fake), timeout_s=1, terminate_grace_s=1
            )
            result = peer_review.run_peer_review(
                bundle, config, environment={"PATH": os.environ["PATH"]}
            )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)
        self.assertIsNone(result.verdict)
        self.assertEqual(result.error, "peer-review-timeout")


if __name__ == "__main__":
    unittest.main()
