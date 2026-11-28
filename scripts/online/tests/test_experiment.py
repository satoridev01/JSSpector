"""Deterministic experiment metrics and artifact rendering."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ONLINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ONLINE))

import experiment  # noqa: E402


class ExperimentTests(unittest.TestCase):
    def test_event_recorder_stage_writes_a_measurable_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            recorder = experiment.EventRecorder(
                path, experiment_id="epoch-1", policy_version="review-v1"
            )
            with recorder.stage("peer_review", repository="a/b"):
                pass
            loaded = experiment.read_jsonl(path)
        self.assertEqual(
            [item["type"] for item in loaded.items],
            ["stage_started", "stage_finished"],
        )
        self.assertEqual(loaded.items[0]["experiment_id"], "epoch-1")
        self.assertGreaterEqual(loaded.items[1]["duration_ms"], 0)

    def test_prefixed_events_invalid_lines_and_pairing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text(
                "noise\n"
                + experiment.EVENT_PREFIX
                + json.dumps(
                    {
                        "type": "stage_started",
                        "stage": "verification",
                        "repository": "a/b",
                        "monotonic_ms": 100,
                    }
                )
                + "\n"
                + experiment.EVENT_PREFIX
                + json.dumps(
                    {
                        "type": "stage_finished",
                        "stage": "verification",
                        "repository": "a/b",
                        "monotonic_ms": 3100,
                    }
                )
                + "\n"
            )
            loaded = experiment.read_jsonl(path)
        self.assertEqual(len(loaded.items), 2)
        self.assertEqual(loaded.invalid_lines, 1)
        summary = experiment.summarize(
            loaded.items, [], invalid_lines=loaded.invalid_lines
        )
        self.assertEqual(summary["latency"]["stages"]["verification"]["p50_ms"], 3000)
        self.assertEqual(summary["inputs"]["invalid_event_lines"], 1)

    def test_unfinished_stage_is_censored_not_failed(self) -> None:
        summary = experiment.summarize(
            [
                {
                    "type": "stage_started",
                    "stage": "fix",
                    "repository": "a/b",
                    "monotonic_ms": 100,
                },
                {"type": "run_interrupted"},
            ],
            [],
        )
        self.assertEqual(summary["censored"], {"fix": 1})
        self.assertEqual(summary["failures"], {})

    def test_lifecycle_starts_are_not_inferred_as_censored(self) -> None:
        summary = experiment.summarize(
            [
                {"type": "run_started", "monotonic_ms": 0},
                {"type": "discovery_started", "monotonic_ms": 10},
                {"type": "experiment_started", "monotonic_ms": 20},
                {"type": "discovery_completed", "monotonic_ms": 110},
                {"type": "run_interrupted", "monotonic_ms": 120},
            ],
            [],
        )
        self.assertEqual(summary["censored"], {})
        self.assertEqual(
            summary["latency"]["stages"]["discovery"]["p50_ms"], 100
        )

    def test_explicit_censor_and_timeout_are_separate(self) -> None:
        summary = experiment.summarize(
            [
                {
                    "type": "stage_censored",
                    "stage": "peer_review",
                    "duration_ms": 600000,
                },
                {
                    "type": "stage_timeout",
                    "stage": "verification",
                    "duration_ms": 900000,
                },
            ],
            [],
        )
        self.assertEqual(summary["censored"], {"peer_review": 1})
        self.assertEqual(summary["failures"], {"verification": 1})

    def test_quality_funnel_detects_false_publish_and_bad_fix(self) -> None:
        identities = [
            "owner/one@revision-1#finding-1",
            "owner/two@revision-2#finding-2",
            "owner/three@revision-3#finding-3",
        ]
        verdicts = [
            {
                "_case_id": identities[0],
                "decision": "publish_fixed",
                "exploit": {"verdict": "real"},
                "fix": {"status": "verified"},
                "reviewer": {"duration_ms": 300000},
                "agents": [
                    {"agent": "skeptic", "duration_ms": 100000},
                    {"agent": "fix", "duration_ms": 200000},
                ],
            },
            {
                "_case_id": identities[1],
                "decision": "publish_fixed",
                "exploit": {"verdict": "real"},
            },
            {
                "_case_id": identities[2],
                "decision": "delete_false_positive",
                "exploit": {"verdict": "false_positive"},
            },
        ]
        labels = {
            identities[0]: {"exploit": "real", "fix": "verified"},
            identities[1]: {"exploit": "false_positive", "fix": "rejected"},
            identities[2]: {"exploit": "false_positive"},
        }
        summary = experiment.summarize([], verdicts, labels=labels)
        self.assertEqual(summary["funnel"]["peer_reviewed_findings"], 3)
        self.assertEqual(summary["funnel"]["would_publish_fixed"], 2)
        self.assertEqual(summary["quality"]["false_published"], 1)
        self.assertEqual(summary["quality"]["bad_fix_attached"], 1)
        self.assertEqual(summary["quality"]["correct"], 2)
        self.assertEqual(summary["quality"]["accuracy"], 0.6667)
        self.assertEqual(summary["latency"]["agents"]["skeptic"]["p50_ms"], 100000)

    def test_blind_labels_join_after_review_without_modifying_verdicts(self) -> None:
        identity = "owner/repo@revision-1#finding-1"
        verdicts = [
            {
                "_case_id": identity,
                "finding_fingerprint": "finding-1",
                "decision": "publish_unfixed",
                "exploit": {"verdict": "real"},
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            labels_path = Path(temporary) / "labels.json"
            labels_path.write_text(
                json.dumps(
                    {
                        "findings": {
                            identity: {
                                "exploit": "false_positive",
                                "fix": "rejected",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            labels = experiment.read_labels(labels_path)
            summary = experiment.summarize([], verdicts, labels=labels)

        self.assertNotIn("expected", verdicts[0])
        self.assertEqual(summary["quality"]["labelled"], 1)
        self.assertEqual(summary["quality"]["false_published"], 1)

    def test_model_embedded_ground_truth_is_ignored(self) -> None:
        summary = experiment.summarize(
            [],
            [
                {
                    "decision": "publish_unfixed",
                    "exploit": {"verdict": "real"},
                    "expected": {"exploit": "real"},
                    "ground_truth": {"exploit": "real"},
                }
            ],
        )
        self.assertEqual(summary["quality"]["labelled"], 0)
        self.assertIsNone(summary["quality"]["accuracy"])

    def test_retry_fix_is_held_for_another_attempt(self) -> None:
        identity = "owner/repo@revision-1#finding-1"
        summary = experiment.summarize(
            [],
            [
                {
                    "_case_id": identity,
                    "decision": "retry_fix",
                    "exploit": {"verdict": "real"},
                }
            ],
            labels={identity: {"exploit": "real", "fix": "rejected"}},
        )
        self.assertEqual(summary["funnel"]["would_publish_unfixed"], 0)
        self.assertEqual(summary["funnel"]["would_retry_fix"], 1)
        self.assertEqual(summary["quality"]["real_held"], 1)
        self.assertEqual(summary["quality"].get("correct", 0), 0)

    def test_composite_evidence_identity_and_missing_verdict_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            events = run / "events.jsonl"
            events.write_text("", encoding="utf-8")
            first = run / "peer-reviews" / "first"
            second = run / "peer-reviews" / "second"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            first_identity = "owner/repo@abc123#finding-1"
            second_identity = "owner/repo@abc123#finding-2"
            for directory, fingerprint in (
                (first, "finding-1"),
                (second, "finding-2"),
            ):
                (directory / "evidence.json").write_text(
                    json.dumps(
                        {
                            "repository": "owner/repo",
                            "revision": "abc123",
                            "finding_fingerprint": fingerprint,
                        }
                    ),
                    encoding="utf-8",
                )
            verdict = first / "verdict.json"
            verdict.write_text(
                json.dumps(
                    {
                        "finding_fingerprint": "finding-1",
                        "decision": "publish_unfixed",
                        "exploit": {"verdict": "real"},
                    }
                ),
                encoding="utf-8",
            )
            labels_path = run / "labels.json"
            labels_path.write_text(
                json.dumps(
                    {
                        first_identity: {"exploit": "real"},
                        second_identity: {"exploit": "real"},
                    }
                ),
                encoding="utf-8",
            )
            loaded_verdicts, invalid = experiment.read_verdicts([verdict])
            summary = experiment.summarize_files(
                [events], [verdict], labels=experiment.read_labels(labels_path)
            )

        self.assertEqual(invalid, 0)
        self.assertEqual(loaded_verdicts[0]["_case_id"], first_identity)
        self.assertEqual(summary["inputs"]["evidence_cases"], 2)
        self.assertEqual(summary["quality"]["labelled"], 2)
        self.assertEqual(summary["quality"]["labelled_reviewed"], 1)
        self.assertEqual(summary["quality"]["labelled_missing_verdict"], 1)
        self.assertEqual(summary["quality"]["review_coverage"], 0.5)
        self.assertEqual(summary["quality"]["accuracy"], 0.5)

    def test_labels_require_composite_identity_and_known_enums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "labels.json"
            for value, message in (
                ({"fingerprint": {"exploit": "real"}}, "repository@revision"),
                (
                    {"owner/repo@rev#fp": {"exploit": "maybe"}},
                    "exploit must be one of",
                ),
                (
                    {
                        "owner/repo@rev#fp": {
                            "exploit": "real",
                            "fix": "maybe",
                        }
                    },
                    "fix must be one of",
                ),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, message):
                    experiment.read_labels(path)

    def test_resource_summary_and_disk_delta(self) -> None:
        summary = experiment.summarize(
            [
                {
                    "type": "operational_failure",
                    "message": "Docker garbage cleanup failed",
                },
                {"type": "storage_gc", "phase": "initial", "free_gib": 101, "failures": 0},
                {"type": "storage_gc", "phase": "final", "free_gib": 100, "failures": 2},
            ],
            [],
            resource_samples=[
                {"cpu_fraction": 0.2, "mem_fraction": 0.5, "disk_free_gib": 100},
                {"cpu_fraction": 0.8, "mem_fraction": 0.7, "disk_free_gib": 98.5},
            ],
        )
        self.assertEqual(summary["resources"]["cpu_percent"]["p50_percent"], 50)
        self.assertEqual(summary["resources"]["disk_delta_gib"], -1)
        self.assertEqual(summary["resources"]["cleanup_failures"], 3)

    def test_configuration_is_redacted_and_content_addressed(self) -> None:
        first = experiment.configuration_snapshot(
            {"model": "gpt", "SATORI_TOKEN": "secret", "nested": {"password": "x"}},
            experiment_id="e1",
            policy_version="p1",
        )
        second = experiment.configuration_snapshot(
            {
                "nested": {"password": "different"},
                "SATORI_TOKEN": "other",
                "model": "gpt",
            },
            experiment_id="e1",
            policy_version="p1",
        )
        self.assertEqual(first["configuration"]["SATORI_TOKEN"], "<redacted>")
        self.assertEqual(first["configuration"]["nested"]["password"], "<redacted>")
        self.assertEqual(first["configuration_sha256"], second["configuration_sha256"])
        changed_policy = experiment.configuration_snapshot(
            {"model": "gpt", "SATORI_TOKEN": "secret", "nested": {"password": "x"}},
            experiment_id="e1",
            policy_version="p2",
        )
        self.assertNotEqual(
            first["configuration_sha256"], changed_policy["configuration_sha256"]
        )

    def test_write_summary_produces_json_and_markdown(self) -> None:
        summary = experiment.summarize([], [])
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = experiment.write_summary(
                Path(temporary), summary
            )
            self.assertEqual(json.loads(json_path.read_text())["schema_version"], 1)
            markdown = markdown_path.read_text()
        self.assertIn("# JSSpector experiment summary", markdown)
        self.assertIn("Censored work", markdown)


if __name__ == "__main__":
    unittest.main()
