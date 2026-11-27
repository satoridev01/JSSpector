"""Host capacity: probing, the cost model, adjustable slots, the governor and calibration."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ONLINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ONLINE))

import controller  # noqa: E402
import resources  # noqa: E402


def host(**overrides: object) -> resources.Host:
    values: dict[str, object] = {
        "platform": "linux",
        "cpu_model": "Cortex-X925 + Cortex-A725",
        "logical_cpus": 20,
        "capacity_cpus": 16.92,
        "busy_cpus": 0.5,
        "mem_total_gib": 119.6,
        "mem_available_gib": 113.6,
        "docker": "native",
        "docker_cpus": 20,
        "disk_free_gib": 668.0,
    }
    values.update(overrides)
    return resources.Host(**values)  # type: ignore[arg-type]


REFERENCE = host(
    cpu_model="reference 10-core",
    logical_cpus=10,
    capacity_cpus=8.7,
    busy_cpus=1.0,
    mem_total_gib=16.0,
    mem_available_gib=15.0,
    docker_cpus=10,
    disk_free_gib=600.0,
)


def sample(
    t: float,
    *,
    cpu: float = 0.5,
    memory: float = 0.3,
    active: int = 4,
    waiting: int = 0,
    limit: int = 4,
    saturated: bool = False,
    mem_pressure: float | None = None,
) -> resources.Sample:
    return resources.Sample(
        t=t,
        cpu_busy=cpu * 20,
        cpu_fraction=cpu,
        mem_used_gib=memory * 100,
        mem_fraction=memory,
        cpu_pressure=None,
        mem_pressure=mem_pressure,
        active=active,
        waiting=waiting,
        limit=limit,
        static_active=0,
        saturated=saturated,
    )


class ProbeTests(unittest.TestCase):
    def test_big_little_capacity_and_cgroup_quota(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for cpu, capacity in enumerate([1024, 1024, 512, 512]):
                directory = root / f"devices/system/cpu/cpu{cpu}"
                directory.mkdir(parents=True)
                (directory / "cpu_capacity").write_text(f"{capacity}\n")
            cgroup = root / "cgroup"
            cgroup.mkdir()
            logical, capacity = resources.linux_cpus([0, 1, 2, 3], root, cgroup)
            self.assertEqual((logical, capacity), (4, 3.0))
            (cgroup / "cpu.max").write_text("200000 100000\n")
            logical, capacity = resources.linux_cpus([0, 1, 2, 3], root, cgroup)
            self.assertEqual((logical, capacity), (2, 1.5))

    def test_missing_capacity_files_mean_uniform_cores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            logical, capacity = resources.linux_cpus(
                [0, 1, 2], Path(temporary), Path(temporary)
            )
        self.assertEqual((logical, capacity), (3, 3.0))

    def test_memory_honors_a_cgroup_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary) / "proc"
            cgroup = Path(temporary) / "cgroup"
            proc.mkdir()
            cgroup.mkdir()
            (proc / "meminfo").write_text(
                "MemTotal:       16777216 kB\nMemFree:  1000 kB\nMemAvailable:   8388608 kB\n"
            )
            self.assertEqual(resources.linux_memory(proc, cgroup), (16.0, 8.0))
            (cgroup / "memory.max").write_text(str(4 * resources.GIB))
            (cgroup / "memory.current").write_text(str(1 * resources.GIB))
            self.assertEqual(resources.linux_memory(proc, cgroup), (4.0, 3.0))

    def test_cpu_busy_fraction_counts_iowait_as_idle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            (proc / "stat").write_text("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1\n")
            before = resources.cpu_times(proc)
            (proc / "stat").write_text("cpu  200 0 200 1300 300 0 0 0 0 0\n")
            after = resources.cpu_times(proc)
        self.assertEqual(before, (1000, 800))
        self.assertAlmostEqual(resources.busy_fraction(before, after) or 0.0, 0.2)

    def test_pressure_reads_avg10(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "memory"
            path.write_text(
                "some avg10=3.50 avg60=1.00 avg300=0.10 total=1\n"
                "full avg10=12.25 avg60=2.00 avg300=0.20 total=2\n"
            )
            self.assertEqual(resources.pressure(path, "some"), 3.5)
            self.assertEqual(resources.pressure(path, "full"), 12.25)
            self.assertIsNone(resources.pressure(Path(temporary) / "missing", "full"))

    def test_docker_vm_bounds_cpus_and_memory(self) -> None:
        info = {"OperatingSystem": "Docker Desktop", "NCPU": 4, "MemTotal": 8 * resources.GIB}
        with tempfile.TemporaryDirectory() as temporary:
            probed = resources.probe_host(Path(temporary), sample_s=0.01, docker=info)
        self.assertEqual(probed.docker, "vm")
        self.assertLessEqual(probed.logical_cpus, 4)
        self.assertEqual(probed.mem_total_gib, 8.0)
        self.assertLessEqual(probed.mem_available_gib, 8.0 - resources.VM_RESERVE_GIB)


class EstimateTests(unittest.TestCase):
    def test_reference_hardware_reproduces_the_hand_tuned_defaults(self) -> None:
        plan = resources.estimate(REFERENCE, resources.Costs())
        self.assertEqual(
            (plan.parallel_docker, plan.parallel_no_ai, plan.static_parallel, plan.max_checkouts),
            (4, 2, 12, 24),
        )
        self.assertEqual(plan.limited_by, "cpu")

    def test_gb10_is_cpu_bound_near_the_target(self) -> None:
        measured = host()
        costs = resources.Costs()
        plan = resources.estimate(measured, costs)
        self.assertEqual(plan.parallel_docker, 12)
        self.assertEqual(plan.parallel_no_ai, 10)
        self.assertEqual(plan.limited_by, "cpu")
        cpu, memory = plan.load(costs, measured)
        self.assertLessEqual(measured.busy_cpus + cpu, 0.8 * measured.logical_cpus)
        self.assertGreater(
            measured.busy_cpus + plan.load(costs, measured, plan.parallel_docker + 1)[0],
            0.8 * measured.logical_cpus,
        )
        self.assertLess(memory, plan.mem_budget_gib)
        self.assertGreater(plan.docker_ceiling, plan.parallel_docker)
        self.assertGreaterEqual(
            plan.max_checkouts, plan.static_parallel + 2 * plan.docker_ceiling
        )

    def test_memory_held_by_other_processes_shrinks_the_plan(self) -> None:
        # A model server holding most of a unified-memory machine.
        plan = resources.estimate(host(mem_available_gib=22.0), resources.Costs())
        self.assertEqual(plan.parallel_docker, plan.docker_floor)
        self.assertEqual(plan.limited_by, "minimum")
        self.assertLess(plan.mem_budget_gib, 0)

    def test_cpu_held_by_other_processes_shrinks_the_plan(self) -> None:
        idle = resources.estimate(host(), resources.Costs())
        busy = resources.estimate(host(busy_cpus=8.0), resources.Costs())
        self.assertLess(busy.parallel_docker, idle.parallel_docker)

    def test_explicit_counts_win_and_the_rest_stays_coherent(self) -> None:
        costs = resources.Costs()
        plan = resources.estimate(host(), costs, parallel_docker=8)
        self.assertEqual((plan.parallel_docker, plan.parallel_no_ai), (8, 6))
        plan = resources.estimate(host(), costs, parallel_no_ai=5)
        self.assertEqual((plan.parallel_docker, plan.parallel_no_ai), (7, 5))
        plan = resources.estimate(host(), costs, static_parallel=3, max_checkouts=100)
        self.assertEqual((plan.static_parallel, plan.max_checkouts), (3, 100))
        self.assertEqual(
            set(plan.explicit), {"static_parallel", "max_checkouts"}
        )

    def test_without_the_ai_lane_every_slot_is_deterministic(self) -> None:
        plan = resources.estimate(host(), resources.Costs(), ai_lane=False)
        self.assertEqual(plan.parallel_no_ai, plan.parallel_docker)
        self.assertEqual(plan.docker_floor, 1)

    def test_checkouts_are_capped_by_disk(self) -> None:
        self.assertEqual(resources.checkouts_for(12, 12, 1.0, 100), 24)
        self.assertEqual(resources.checkouts_for(12, 12, 1000.0, 100), 48)

    def test_render_explains_the_plan(self) -> None:
        costs = resources.Costs()
        plan = resources.estimate(host(), costs)
        text = resources.render_plan(host(), costs, plan, target=0.8, governed=True)
        for expected in ("target 80%", "limited by cpu", "governor", "docker 12", "full-core"):
            self.assertIn(expected, text)


class SlotTests(unittest.TestCase):
    def test_waiters_are_served_in_arrival_order(self) -> None:
        slots = resources.AdjustableSlots(1)
        order: list[int] = []
        slots.acquire()
        threads = []
        for index in range(4):
            thread = threading.Thread(
                target=lambda index=index: (slots.acquire(), order.append(index), slots.release())
            )
            thread.start()
            threads.append(thread)
            while slots.snapshot()[1] < index + 1:
                time.sleep(0.001)
        slots.release()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(order, [0, 1, 2, 3])

    def test_lowering_the_limit_waits_for_holders_and_raising_admits(self) -> None:
        slots = resources.AdjustableSlots(2)
        slots.acquire()
        slots.acquire()
        slots.set_limit(1)
        admitted = threading.Event()
        thread = threading.Thread(target=lambda: (slots.acquire(), admitted.set()))
        thread.start()
        slots.release()
        self.assertFalse(admitted.wait(0.2))  # one holder still at the new limit
        slots.set_limit(2)
        self.assertTrue(admitted.wait(2))
        thread.join(timeout=2)
        self.assertEqual(slots.snapshot(), (2, 0, 2))

    def test_wake_lets_every_waiter_through_for_shutdown(self) -> None:
        stop = threading.Event()
        slots = resources.AdjustableSlots(1, wake=stop)
        slots.acquire()
        results: list[bool] = []
        thread = threading.Thread(target=lambda: results.append(slots.acquire()))
        thread.start()
        time.sleep(0.05)
        stop.set()
        thread.join(timeout=3)
        self.assertEqual(results, [False])
        slots.release()
        slots.release()
        self.assertEqual(slots.snapshot()[0], 0)
        with self.assertRaises(ValueError):
            slots.release()


class GovernorTests(unittest.TestCase):
    def window(self, until: float, **kwargs: object) -> list[resources.Sample]:
        return [sample(float(t), **kwargs) for t in range(0, int(until) + 1, 5)]  # type: ignore[arg-type]

    def test_memory_over_the_band_cuts_a_quarter(self) -> None:
        state = resources.GovernorState(limit=12, floor=3, ceiling=18)
        limit, reason = resources.govern(
            state, self.window(30, memory=0.9), target=0.8, now=30
        )
        self.assertEqual(limit, 9)
        self.assertIn("memory", reason or "")

    def test_memory_pressure_cuts_even_below_the_band(self) -> None:
        state = resources.GovernorState(limit=8, floor=3, ceiling=18)
        limit, reason = resources.govern(
            state, self.window(30, memory=0.5, mem_pressure=25.0), target=0.8, now=30
        )
        self.assertEqual((limit, reason), (6, "memory pressure"))

    def test_sustained_cpu_over_the_band_sheds_one_slot(self) -> None:
        state = resources.GovernorState(limit=12, floor=3, ceiling=18)
        self.assertEqual(
            resources.govern(state, self.window(30, cpu=0.95), target=0.8, now=30)[0], 12
        )  # not enough history yet
        limit, reason = resources.govern(
            state, self.window(120, cpu=0.95), target=0.8, now=120
        )
        self.assertEqual(limit, 11)
        self.assertIn("cpu", reason or "")

    def test_headroom_adds_one_slot_only_when_work_is_waiting(self) -> None:
        state = resources.GovernorState(limit=12, floor=3, ceiling=18)
        idle = self.window(200, cpu=0.5, saturated=False)
        self.assertEqual(resources.govern(state, idle, target=0.8, now=200)[0], 12)
        busy = self.window(200, cpu=0.5, saturated=True, active=12, waiting=5)
        self.assertEqual(resources.govern(state, busy, target=0.8, now=200)[0], 13)
        state.last_increase = 150
        self.assertEqual(resources.govern(state, busy, target=0.8, now=200)[0], 12)

    def test_headroom_respects_the_links_ceiling(self) -> None:
        def busy_window(network: float) -> list[resources.Sample]:
            return [
                resources.Sample(
                    **{
                        **sample(float(t), cpu=0.5, saturated=True, active=12, waiting=8).__dict__,
                        "net_rx_mbps": network,
                    }
                )
                for t in range(0, 201, 5)
            ]

        state = resources.GovernorState(limit=12, floor=3, ceiling=18, network_ceiling=13.3)
        held, _reason = resources.govern(state, busy_window(12.8), target=0.8, now=200)
        self.assertEqual(held, 12)  # downloads at 96% of the link: adding builds only slows them
        raised, reason = resources.govern(state, busy_window(6.0), target=0.8, now=200)
        self.assertEqual(raised, 13)
        self.assertIn("network 6.0 MB/s", reason or "")
        unknown = resources.GovernorState(limit=12, floor=3, ceiling=18)
        self.assertEqual(resources.govern(unknown, busy_window(12.8), target=0.8, now=200)[0], 13)

    def test_inside_the_band_holds(self) -> None:
        state = resources.GovernorState(limit=12, floor=3, ceiling=18)
        steady = self.window(300, cpu=0.8, memory=0.6, saturated=True, waiting=3)
        self.assertEqual(resources.govern(state, steady, target=0.8, now=300), (12, None))

    def test_bounds_are_respected(self) -> None:
        low = resources.GovernorState(limit=3, floor=3, ceiling=18)
        self.assertEqual(
            resources.govern(low, self.window(300, cpu=0.99, memory=0.95), target=0.8, now=300)[0],
            3,
        )
        high = resources.GovernorState(limit=18, floor=3, ceiling=18)
        self.assertEqual(
            resources.govern(
                high, self.window(300, cpu=0.3, saturated=True, waiting=9), target=0.8, now=300
            )[0],
            18,
        )


class CalibrationTests(unittest.TestCase):
    def test_phases_follow_the_window_from_the_first_verification(self) -> None:
        calibration = resources.Calibration(low=6, high=12, window_s=1000)
        self.assertEqual(calibration.advance(sample(10, active=0)), (None, None))
        limit, message = calibration.advance(sample(20, active=1))
        self.assertEqual(limit, 6)
        self.assertIn("6 concurrent", message or "")
        self.assertEqual(calibration.advance(sample(300, active=6))[0], None)
        self.assertEqual(calibration.advance(sample(420, active=6))[0], 12)
        self.assertEqual(calibration.phase, "high")
        _limit, message = calibration.advance(sample(1020, active=12))
        self.assertEqual(calibration.phase, "done")
        self.assertIn("complete", message or "")

    def test_calibration_gives_up_when_nothing_starts(self) -> None:
        calibration = resources.Calibration(low=2, high=4, window_s=600)
        calibration.advance(sample(resources.CALIBRATION_IDLE_GRACE_S + 1, active=0))
        self.assertEqual(calibration.phase, "done")
        # Later samples (the pool draining) are ignored rather than failing.
        self.assertEqual(calibration.advance(sample(resources.CALIBRATION_IDLE_GRACE_S + 9)), (None, None))
        result = resources.analyze_calibration(
            [],
            calibration,
            records=[],
            host=host(),
            target=0.8,
            parallel_ai=2,
            static_parallel=12,
        )
        self.assertIn("no verification started", result["error"])

    def test_fit_recovers_the_per_verification_cost_and_sizes_the_host(self) -> None:
        measured = host(busy_cpus=0.5, mem_available_gib=113.6)
        calibration = resources.Calibration(low=6, high=12, window_s=1800)
        calibration.clock_start = 0.0
        calibration.switched_at = 720.0
        calibration.finished_at = 1800.0
        calibration.phase = "done"
        samples = []
        for t in range(0, 1800, 5):
            active = 6 if t < 720 else 12
            active += (t // 5) % 3 - 1  # natural variation around each level
            samples.append(
                resources.Sample(
                    t=float(t),
                    cpu_busy=1.5 + 0.8 * active,
                    cpu_fraction=(1.5 + 0.8 * active) / 20,
                    mem_used_gib=7.0 + 1.2 * active,
                    mem_fraction=(7.0 + 1.2 * active) / 119.6,
                    cpu_pressure=None,
                    mem_pressure=None,
                    active=active,
                    waiting=3,
                    limit=12,
                    static_active=2,
                    saturated=True,
                )
            )
        records = [
            resources.VerificationRecord(
                lane="no-ai",
                outcome="not-reproduced",
                started=index * 55.0,
                finished=index * 55.0 + 300,
                slot_s=300.0,
                phases={"startup": 120.0, "candidate": 170.0},
            )
            for index in range(30)
        ]
        result = resources.analyze_calibration(
            samples,
            calibration,
            records=records,
            host=measured,
            target=0.8,
            parallel_ai=2,
            static_parallel=12,
        )
        self.assertNotIn("error", result)
        self.assertAlmostEqual(result["fit"]["verify_cpu"], 0.8, places=3)
        self.assertAlmostEqual(result["fit"]["verify_mem_gib"], 1.2, places=3)
        self.assertAlmostEqual(result["fit"]["cpu_r2"], 1.0, places=3)
        # 0.8 × 20 − 0.5 busy = 15.5 CPU; overhead 1.0 (intercept 1.5 − 0.5 busy) leaves 14.5,
        # i.e. 18 verifications at 0.8 CPU each.
        # The fit says 18 at the target, but calibration only ran up to 12: start there and let the
        # governor climb (its ceiling covers the fit).
        self.assertEqual(result["recommended"]["parallel_docker"], 12)
        self.assertEqual(result["recommended"]["limited_by"], "calibrated start")
        self.assertEqual(result["costs"]["start_docker_slots"], 12.0)
        self.assertEqual(result["costs"]["max_docker_slots"], 64.0)
        self.assertEqual(result["checks"], [])
        self.assertGreater(result["high"]["verifications"], 0)
        self.assertEqual(result["high"]["bottleneck"]["verification"], 1.0)
        text = resources.render_calibration(result, target=0.8, profile=Path("/tmp/p.json"))
        self.assertIn("docker 12", text)
        self.assertIn("saved to /tmp/p.json", text)

    def test_flat_load_cannot_be_fitted(self) -> None:
        calibration = resources.Calibration(low=4, high=6, window_s=600)
        calibration.clock_start = 0.0
        samples = [sample(float(t), active=4) for t in range(0, 1200, 5)]
        result = resources.analyze_calibration(
            samples,
            calibration,
            records=[],
            host=host(),
            target=0.8,
            parallel_ai=2,
            static_parallel=12,
        )
        self.assertIn("not enough varied load", result["error"])
        self.assertIn("profile  unchanged", resources.render_calibration(result, target=0.8, profile=None))


def record(
    outcome: str,
    slot_s: float,
    *,
    lane: str = "no-ai",
    finished: float = 100.0,
    findings: int = 0,
    phases: dict[str, float] | None = None,
    skip_reason: str | None = None,
) -> resources.VerificationRecord:
    return resources.VerificationRecord(
        lane=lane,
        outcome=outcome,
        started=finished - slot_s,
        finished=finished,
        slot_s=slot_s,
        phases=phases or {},
        findings=findings,
        skip_reason=skip_reason,
    )


class ImprovementMetricTests(unittest.TestCase):
    def test_outcome_buckets(self) -> None:
        kind = resources.outcome_kind
        self.assertIsNone(
            kind(cancelled=True, failed=False, failure_reason=None, findings=0, driven="")
        )
        self.assertEqual(
            kind(cancelled=False, failed=True, failure_reason="verify-startup-timeout",
                 findings=0, driven=""),
            "timeout",
        )
        self.assertEqual(
            kind(cancelled=False, failed=True, failure_reason="verify-failed", findings=0,
                 driven=""),
            "error",
        )
        self.assertEqual(
            kind(cancelled=False, failed=False, failure_reason=None, findings=2, driven=""),
            "verified",
        )
        self.assertEqual(
            kind(cancelled=False, failed=False, failure_reason=None, findings=0,
                 driven="skipped"),
            "skipped",
        )
        self.assertEqual(
            kind(cancelled=False, failed=False, failure_reason=None, findings=0,
                 driven="not-reproduced"),
            "not-reproduced",
        )

    def test_bottleneck_names_the_limiting_stage(self) -> None:
        def at(**kwargs: object) -> str:
            values: dict[str, object] = {"active": 3, "waiting": 0, "limit": 6}
            values.update(kwargs)
            return resources.bottleneck(sample(0, **values), 12)  # type: ignore[arg-type]

        self.assertEqual(at(saturated=True), "verification")
        busy = resources.Sample(**{**sample(0).__dict__, "static_active": 12})
        self.assertEqual(resources.bottleneck(busy, 12), "static")
        full = resources.Sample(
            **{**sample(0).__dict__, "checkouts": 40, "checkout_capacity": 40}
        )
        self.assertEqual(resources.bottleneck(full, 12), "checkouts")
        self.assertEqual(at(), "discovery")

    def test_summary_splits_docker_time_phases_lanes_and_bottleneck(self) -> None:
        records = [
            record("verified", 600, findings=2, phases={"startup": 200, "candidate": 350}),
            record("not-reproduced", 300, phases={"startup": 100, "candidate": 180}),
            record("skipped", 60, skip_reason="the app did not start: missing DATABASE_URL"),
            record("skipped", 40, skip_reason="the app did not start: missing DATABASE_URL"),
            record("timeout", 900, lane="ai", phases={"startup": 180, "candidate": 700}),
            record("error", 100, finished=10_000),  # outside the window below
        ]
        samples = [
            resources.Sample(**{**sample(float(t)).__dict__, "saturated": t < 60})
            for t in range(0, 100, 5)
        ]
        summary = resources.performance_summary(
            records, samples, static_parallel=12, start=0, end=1000
        )
        self.assertEqual(summary["verifications"], 5)
        self.assertEqual(summary["issues"], 2)
        self.assertEqual(summary["docker_time"]["timeout"], round(900 / 1900, 3))
        self.assertEqual(summary["docker_time"]["error"], 0.0)
        self.assertEqual(summary["slot_minutes_per_issue"], round(1900 / 60 / 2, 1))
        self.assertEqual(summary["phases"]["startup"], round(480 / 1900, 3))
        self.assertEqual(
            summary["top_skip_reasons"][0],
            ["the app did not start: missing DATABASE_URL", 2],
        )
        self.assertEqual(summary["bottleneck"]["verification"], 0.6)
        self.assertEqual(summary["lanes"]["no-ai"]["issues"], 2)
        self.assertEqual(summary["lanes"]["ai"]["issues_per_slot_hour"], 0.0)
        self.assertEqual(summary["lanes"]["no-ai"]["slot_minutes_per_issue"], 8.3)
        lines = resources.performance_lines(summary, summary)
        self.assertEqual(len(lines), 4)
        self.assertIn("timeout 47%", lines[0])
        self.assertIn("1 issue per 16 Docker-min", lines[0])
        self.assertIn("build/start 25%", lines[1])
        self.assertIn("top skip: the app did not start", lines[1])
        self.assertIn("verification 60%", lines[2])
        self.assertIn("deterministic 2 issues in 4 runs, 1 per 8 Docker-min", lines[3])
        self.assertIn("Opus no issue in 1 runs (15 Docker-min)", lines[3])

    def test_empty_summary_reads_as_collecting(self) -> None:
        empty = resources.performance_summary([], [], static_parallel=12)
        lines = resources.performance_lines(empty, empty)
        self.assertIn("collecting", lines[0])
        self.assertIn("collecting", lines[2])
        self.assertIn("collecting", lines[3])

    def test_checkout_budget_grows_while_holders_run(self) -> None:
        budget = resources.CountedSemaphore(1)
        self.assertTrue(budget.acquire(timeout=0.1))
        self.assertFalse(budget.acquire(timeout=0.01))
        budget.grow_to(3)
        budget.grow_to(2)  # never shrinks
        self.assertTrue(budget.acquire(timeout=0.1))
        self.assertTrue(budget.acquire(timeout=0.1))
        self.assertEqual((budget.held, budget.capacity), (3, 3))
        for _ in range(3):
            budget.release()
        with self.assertRaises(ValueError):
            budget.release()

    def test_counted_semaphore_reports_held_permits(self) -> None:
        budget = resources.CountedSemaphore(2)
        self.assertTrue(budget.acquire(timeout=0.1))
        with budget:
            self.assertEqual((budget.held, budget.capacity), (2, 2))
            self.assertFalse(budget.acquire(timeout=0.01))
        budget.release()
        self.assertEqual(budget.held, 0)

    def test_verifier_phases_are_timed(self) -> None:
        state = controller.VerificationBudgetState(
            started=0.0,
            startup_s=180,
            candidate_soft_s=180,
            candidate_hard_s=300,
            normal_s=900,
            extended_s=1800,
            fix_s=600,
        )
        state.observe({"event": "candidate_started"}, 5.0)
        state.observe({"event": "app_ready"}, 65.0)
        state.observe({"event": "request_activity"}, 70.0)
        state.observe({"event": "candidate_finished"}, 125.0)
        phases = state.close(130.0)
        self.assertEqual(
            phases, {"repository": 10.0, "startup": 60.0, "candidate": 60.0}
        )

    def test_unverified_verifications_are_split_by_whether_a_candidate_ran(self) -> None:
        candidates = ({"fingerprint": "a"}, {"fingerprint": "b"})
        skipped = {
            "findings": [
                {"fingerprint": "a", "exploitation": {"outcome": "skipped", "reason": "no app"}},
                {"fingerprint": "b", "exploitation": {"outcome": "skipped", "reason": "no route"}},
                {"fingerprint": "z", "exploitation": {"outcome": "not-reproduced"}},
            ]
        }
        self.assertEqual(controller.unverified_kind(skipped, candidates), ("skipped", "no app"))
        driven = {
            "findings": [
                {"fingerprint": "a", "exploitation": {"outcome": "skipped", "reason": "x"}},
                {"fingerprint": "b", "exploitation": {"outcome": "not-reproduced", "tried": 4}},
            ]
        }
        self.assertEqual(
            controller.unverified_kind(driven, candidates), ("not-reproduced", None)
        )

    def test_drivable_candidates_are_selected_first(self) -> None:
        routed = {"source": {"kind": "http"}, "entry": "POST /login"}
        unrouted = {"source": {"kind": "http"}}
        browser = {"source": {"kind": "dom"}}
        stored = {"source": {"kind": "stored"}, "stored_by": {"entry": "POST /profile"}}
        orphan = {"source": {"kind": "stored"}, "stored_by": {"expr": "x"}}
        self.assertTrue(controller.drivable(routed))
        self.assertFalse(controller.drivable(unrouted))
        self.assertTrue(controller.drivable(browser))
        self.assertTrue(controller.drivable(stored))
        self.assertFalse(controller.drivable(orphan))
        self.assertTrue(controller.drivable({"source": {"kind": "socket"}}))

    def test_calibration_checks_static_bound_and_contention(self) -> None:
        def level(verifications: int, timeouts: int, **bottleneck: float) -> dict:
            shares = {name: 0.0 for name in resources.BOTTLENECKS}
            shares.update(bottleneck)
            return {
                "verifications": verifications,
                "samples": 100,
                "outcomes": {"timeout": timeouts},
                "bottleneck": shares,
            }

        checks = resources.calibration_checks(
            level(20, 1, verification=0.9), level(30, 1, verification=0.8), high_slots=12
        )
        self.assertEqual(checks.notes, [])
        self.assertEqual(
            (checks.static_per_slot, checks.start_docker_slots, checks.max_docker_slots),
            (resources.STATIC_PER_SLOT, 12.0, 64.0),
        )

        checks = resources.calibration_checks(
            level(20, 0, verification=0.9),
            level(30, 0, verification=0.3, static=0.6, discovery=0.1),
            high_slots=12,
        )
        self.assertEqual(checks.static_per_slot, resources.STATIC_BOUND_PER_SLOT)
        self.assertEqual(checks.max_docker_slots, 64.0)
        self.assertIn("static 60%", checks.notes[0])

        # The first calibration on the GB10: 0/46 then 7/127 is a rise, but not a significant one.
        checks = resources.calibration_checks(
            level(46, 0, verification=0.88), level(127, 7, verification=1.0), high_slots=12
        )
        self.assertEqual(checks.max_docker_slots, 64.0)
        self.assertIn("p=0.11", checks.notes[0])
        self.assertIn("not significant", checks.notes[0])

        checks = resources.calibration_checks(
            level(60, 1, verification=0.9), level(120, 20, verification=0.9), high_slots=12
        )
        self.assertEqual((checks.max_docker_slots, checks.start_docker_slots), (12.0, 12.0))
        self.assertIn("contention", checks.notes[0])

    def test_flat_downloads_while_slots_grow_flag_the_network(self) -> None:
        def level(verifications: int, network: float) -> dict:
            return {
                "verifications": verifications,
                "samples": 100,
                "outcomes": {"timeout": 0},
                "bottleneck": {"verification": 1.0},
                "net_rx_mean": network,
            }

        checks = resources.calibration_checks(
            {**level(40, 12.0)}, {**level(80, 13.5), "net_rx_p95": 14.2}, high_slots=18, low_slots=9
        )
        self.assertEqual(checks.max_docker_slots, 64.0)
        self.assertEqual(checks.start_docker_slots, 9.0)
        self.assertEqual(checks.network_ceiling_mbps, 14.2)
        self.assertIn("levels off near 14.2 MB/s", checks.notes[0])
        checks = resources.calibration_checks(
            level(40, 6.0), level(80, 11.0), high_slots=18, low_slots=9
        )
        self.assertEqual((checks.notes, checks.start_docker_slots), ([], 18.0))

    def test_network_rate_counts_only_physical_interfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            (proc / "net").mkdir(parents=True)
            sys_root = root / "sys"
            for name in ("eth0", "docker0", "veth1"):
                (sys_root / "class/net" / name).mkdir(parents=True)
            (sys_root / "class/net/eth0/device").mkdir()
            dev = proc / "net/dev"
            header = "Inter-|Receive\n face |bytes packets\n"

            def write(eth: int, docker: int) -> None:
                dev.write_text(
                    header
                    + f"  eth0: {eth} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                    + f"docker0: {docker} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                    + f"    lo: 999999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
                )

            write(1_000_000, 5_000_000)
            (proc / "stat").write_text("cpu  1 0 1 8 0 0 0 0\n")
            (proc / "meminfo").write_text("MemTotal: 1048576 kB\nMemAvailable: 524288 kB\n")
            reader = resources.UsageReader(host(), proc=proc, sys_root=sys_root)
            write(11_000_000, 50_000_000)
            reader._net_time -= 2.0  # two seconds ago
            rate = reader.network()
        assert rate is not None
        self.assertAlmostEqual(rate, 5.0, places=1)

    def test_throughput_that_does_not_scale_caps_at_the_low_level(self) -> None:
        def level(rate: float, network: float, verification_share: float) -> dict:
            return {
                "verifications": 60,
                "verifications_per_hour": rate,
                "samples": 100,
                "outcomes": {"timeout": 2},
                "bottleneck": {
                    "verification": verification_share,
                    "static": 1 - verification_share,
                },
                "net_rx_mean": network,
            }

        # Docker limited the 9-slot level, 18 slots added nothing and the link was full: start at 9
        # (a soft start, not a cap) and keep static workers as they are.
        checks = resources.calibration_checks(
            level(300, 13.3, 0.9), level(310, 13.3, 0.3), high_slots=18, low_slots=9
        )
        self.assertEqual((checks.start_docker_slots, checks.max_docker_slots), (9.0, 64.0))
        self.assertEqual(checks.static_per_slot, resources.STATIC_PER_SLOT)
        joined = " | ".join(checks.notes)
        self.assertIn("levels off near 13.3 MB/s", joined)
        self.assertIn("while Docker was the limit: passes start at 9", joined)
        self.assertIn("share the saturated link", joined)

        # The GB10's second calibration: the 9-slot level was clone-bound (Docker 26%), so the
        # flat throughput says nothing about slots and must not lower the start by itself.
        checks = resources.calibration_checks(
            {**level(379, 0.0, 0.26), "net_rx_mean": None},
            {**level(392, 0.0, 0.01), "net_rx_mean": None},
            high_slots=18,
            low_slots=9,
        )
        self.assertEqual(checks.start_docker_slots, 18.0)
        self.assertIn("says nothing about slots", " | ".join(checks.notes))

        # Calibration 1 (no network data): 232 -> 425/h when doubling the slots pays.
        checks = resources.calibration_checks(
            {**level(232, 0.0, 0.88), "net_rx_mean": None},
            {**level(425, 0.0, 1.0), "net_rx_mean": None},
            high_slots=12,
            low_slots=6,
        )
        self.assertEqual((checks.start_docker_slots, checks.max_docker_slots), (12.0, 64.0))

    def test_fisher_exact_tail(self) -> None:
        self.assertAlmostEqual(resources.fisher_greater(0, 46, 7, 127), 0.1098, places=4)
        self.assertEqual(resources.fisher_greater(0, 10, 0, 10), 1.0)
        self.assertLess(resources.fisher_greater(1, 60, 20, 120), 0.01)
        self.assertGreater(resources.fisher_greater(5, 10, 1, 10), 0.9)

    def test_a_calibrated_start_leaves_the_governor_room_to_climb(self) -> None:
        costs = resources.Costs(start_docker_slots=9)
        plan = resources.estimate(host(), costs)
        self.assertEqual(plan.parallel_docker, 9)
        self.assertEqual(plan.limited_by, "calibrated start")
        self.assertGreaterEqual(plan.docker_ceiling, 12)
        self.assertLessEqual(plan.docker_ceiling, 18)
        explicit = resources.estimate(host(), costs, parallel_docker=12)
        self.assertEqual(explicit.parallel_docker, 12)

    def test_calibrated_static_scaling_and_cap_shape_the_plan(self) -> None:
        costs = resources.Costs(static_per_slot=1.5, max_docker_slots=8)
        plan = resources.estimate(host(), costs)
        self.assertEqual(plan.parallel_docker, 8)
        self.assertEqual(plan.limited_by, "calibrated cap")
        self.assertEqual(plan.static_parallel, 12)
        self.assertLessEqual(plan.docker_ceiling, 8)
        # Wider static stages cost CPU too, so the slots shrink slightly as the workers grow.
        wide = resources.estimate(host(), resources.Costs(static_per_slot=1.5))
        self.assertEqual(wide.static_parallel, -(-wide.parallel_docker * 3 // 2))
        self.assertGreater(wide.static_parallel, plan.static_parallel)


class ProfileTests(unittest.TestCase):
    def test_profile_round_trip_applies_only_to_the_same_hardware(self) -> None:
        result = {
            "costs": {
                "verify_cpu": 0.7,
                "verify_mem_gib": 0.9,
                "verify_peak_mem_gib": 4.5,
                "static_cpu": 0.0,
                "static_mem_gib": 0.0,
                "overhead_cpu": 1.2,
                "overhead_mem_gib": 1.0,
            },
            "recommended": {"parallel_docker": 15},
            "levels": {"low": 6, "high": 12},
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "jsspector" / "online-profile.json"
            resources.save_profile(
                path, resources.calibration_profile(result, host=host(), target=0.8)
            )
            costs, note = resources.load_profile(path, host(busy_cpus=3.0))
            self.assertIsNone(note)
            assert costs is not None
            self.assertEqual(costs.verify_cpu, 0.7)
            self.assertTrue(costs.source.startswith("calibrated on this host"))
            other, note = resources.load_profile(path, REFERENCE)
            self.assertIsNone(other)
            self.assertIn("different hardware", note or "")
            path.write_text("{not json")
            broken, note = resources.load_profile(path, host())
            self.assertIsNone(broken)
            self.assertIn("unreadable", note or "")
        self.assertEqual(resources.load_profile(Path("/nonexistent/x.json"), host()), (None, None))


class ControllerCapacityTests(unittest.TestCase):
    def setUp(self) -> None:
        probe = mock.patch.object(controller.resources, "probe_host", return_value=host())
        probe.start()
        self.addCleanup(probe.stop)
        profile = mock.patch.dict(
            os.environ,
            {"JSSPECTOR_ONLINE_PROFILE": str(Path(tempfile.gettempdir()) / "jss-no-profile.json")},
        )
        profile.start()
        self.addCleanup(profile.stop)

    def test_auto_sizing_resolves_counts_and_governs(self) -> None:
        args = controller.parse_args([])
        capacity = controller.plan_capacity(args, Path(tempfile.gettempdir()))
        self.assertEqual((args.parallel_docker, args.parallel_no_ai, args.parallel_ai), (12, 10, 2))
        self.assertTrue(capacity.governed)
        self.assertIsNone(capacity.calibration)

    def test_explicit_lane_counts_disable_the_governor(self) -> None:
        args = controller.parse_args(["--parallel-docker", "6"])
        capacity = controller.plan_capacity(args, Path(tempfile.gettempdir()))
        self.assertEqual((args.parallel_docker, args.parallel_no_ai), (6, 4))
        self.assertFalse(capacity.governed)
        args = controller.parse_args(["--no-governor"])
        self.assertFalse(controller.plan_capacity(args, Path(tempfile.gettempdir())).governed)

    def test_calibration_is_local_fix_free_deterministic_and_two_level(self) -> None:
        args = controller.parse_args(
            ["--calibrate", "--satori-sync", "--fix-attempts", "1", "--learn-fixes"]
        )
        self.assertFalse(args.satori_sync)
        self.assertEqual(args.fix_attempts, 0)
        self.assertFalse(args.learn_fixes)
        self.assertFalse(args.ai_lane)
        self.assertEqual(controller.choose_lane(1, args), "no-ai")
        capacity = controller.plan_capacity(args, Path(tempfile.gettempdir()))
        assert capacity.calibration is not None
        # Half the CPU-bound estimate, then the estimate itself; every slot is deterministic.
        self.assertEqual((capacity.calibration.low, capacity.calibration.high), (6, 12))
        self.assertEqual(args.parallel_docker, 12)
        self.assertEqual(args.parallel_no_ai, 12)
        self.assertFalse(capacity.governed)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            controller.parse_args(["--calibrate", "--estimate"])

    def test_estimate_prints_and_exits_before_any_side_effect(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(controller, "capture_docker_inventory") as docker,
            mock.patch.object(controller, "acquire_run_lock") as lock,
            contextlib.redirect_stdout(output),
        ):
            exit_code = controller.main(
                ["--scanner", controller.__file__, "--estimate", "--satori-sync"]
            )
        self.assertEqual(exit_code, 0)
        docker.assert_not_called()
        lock.assert_not_called()
        self.assertIn("docker 12 (deterministic 10 + Opus 2)", output.getvalue())

    def test_backlog_in_a_pool_queue_counts_as_demand(self) -> None:
        # Seven deterministic threads, all inside the gate, more repositories queued behind them in
        # the pool: Docker is the limit, even though nobody waits at the gate itself.
        plan = resources.estimate(host(), resources.Costs(), parallel_docker=9)
        docker = resources.AdjustableSlots(9)
        gate = resources.AdjustableSlots(7)
        for _ in range(7):
            gate.acquire()
            docker.acquire()
        reader = mock.Mock()
        reader.read.return_value = (8.0, 20.0, None, None)
        reader.network.return_value = None
        backlog = {"value": 0}
        monitor = resources.Monitor(
            host=host(),
            plan=plan,
            target=0.8,
            docker_slots=docker,
            no_ai_gate=gate,
            ai_workers=2,
            governed=False,
            calibration=None,
            static_active=lambda: 12,
            emit=lambda *_args, **_fields: None,
            log=lambda _message: None,
            on_calibrated=lambda _message: None,
            reader=reader,
            checkouts=lambda: (39, 39),
            backlog=lambda: backlog["value"],
        )
        idle = monitor.tick()
        self.assertFalse(idle.saturated)
        self.assertEqual(resources.bottleneck(idle, 12), "checkouts")
        backlog["value"] = 18
        busy = monitor.tick()
        self.assertTrue(busy.saturated)
        self.assertEqual(busy.waiting, 18)
        self.assertEqual(resources.bottleneck(busy, 12), "verification")

    def make_monitor(self, docker: int, **kwargs: object) -> tuple[resources.Monitor, mock.Mock]:
        plan = resources.estimate(host(), resources.Costs(), parallel_docker=docker)
        reader = mock.Mock()
        reader.read.return_value = (8.0, 20.0, None, None)
        reader.network.return_value = None
        values: dict[str, object] = {
            "host": host(),
            "plan": plan,
            "target": 0.8,
            "docker_slots": resources.AdjustableSlots(docker),
            "no_ai_gate": resources.AdjustableSlots(docker - 2),
            "ai_workers": 2,
            "governed": True,
            "calibration": None,
            "static_active": lambda: 0,
            "emit": lambda *_args, **_fields: None,
            "log": lambda _message: None,
            "on_calibrated": lambda _message: None,
            "reader": reader,
        }
        values.update(kwargs)
        return resources.Monitor(**values), reader  # type: ignore[arg-type]

    def test_operator_control_file_sets_and_releases_the_slots(self) -> None:
        grown: list[int] = []
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary) / "control.json"
            monitor, _reader = self.make_monitor(
                9, control_path=control, ensure_checkouts=grown.append
            )
            self.assertIsNone(monitor.read_control())  # no file yet
            control.write_text('{"docker_slots": 12}')
            message = monitor.read_control()
            self.assertIn("9 → 12", message or "")
            self.assertEqual(
                (monitor.docker_slots.limit, monitor.no_ai_gate.limit), (12, 10)
            )
            self.assertEqual(grown, [12])
            self.assertTrue(monitor.manual)
            self.assertFalse(monitor.governed)
            self.assertIsNone(monitor.read_control())  # applied once per change
            control.write_text('{"docker_slots": 1}')
            os.utime(control, ns=(1, 2_000_000_000))
            monitor.read_control()
            self.assertEqual(monitor.docker_slots.limit, 3)  # at least one deterministic slot
            control.write_text('{"docker_slots": "auto"}')
            os.utime(control, ns=(1, 3_000_000_000))
            self.assertIn("governor resumed", monitor.read_control() or "")
            self.assertTrue(monitor.governed)
            self.assertFalse(monitor.manual)
            control.write_text("not json")
            os.utime(control, ns=(1, 4_000_000_000))
            self.assertIn("unreadable", monitor.read_control() or "")

    def test_fixed_passes_and_calibrations_reject_the_wrong_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary) / "control.json"
            control.write_text('{"docker_slots": "auto"}')
            fixed, _reader = self.make_monitor(9, governed=False, control_path=control)
            self.assertIn("fixed worker counts", fixed.read_control() or "")
            calibrating, _reader = self.make_monitor(
                9,
                governed=False,
                control_path=control,
                calibration=resources.Calibration(low=4, high=9, window_s=600),
            )
            self.assertIn("calibrating", calibrating.read_control() or "")

    def test_the_memory_guard_still_lowers_a_manual_setting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary) / "control.json"
            control.write_text('{"docker_slots": 12}')
            monitor, reader = self.make_monitor(9, control_path=control)
            reader.read.return_value = (4.0, 30.0, None, None)  # quiet CPU
            with mock.patch.object(monitor, "now", side_effect=[0.0, 5.0, 10.0]):
                monitor.tick()
                self.assertEqual(monitor.docker_slots.limit, 12)
                monitor.tick()  # CPU headroom does not raise a manual setting
                self.assertEqual(monitor.docker_slots.limit, 12)
                reader.read.return_value = (4.0, 110.0, None, 30.0)  # memory stalls
                monitor.tick()
            self.assertEqual(monitor.docker_slots.limit, 9)
            self.assertTrue(monitor.manual)

    def test_monitor_governs_both_gates_and_records_samples(self) -> None:
        plan = resources.estimate(host(), resources.Costs())
        docker = resources.AdjustableSlots(plan.parallel_docker)
        gate = resources.AdjustableSlots(plan.parallel_no_ai)
        events: list[tuple[str, dict[str, object]]] = []
        reader = mock.Mock()
        reader.read.return_value = (19.5, 30.0, None, None)  # 97% CPU
        reader.network.return_value = 12.345
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary) / "resources.jsonl"
            monitor = resources.Monitor(
                host=host(),
                plan=plan,
                target=0.8,
                docker_slots=docker,
                no_ai_gate=gate,
                ai_workers=2,
                governed=True,
                calibration=None,
                static_active=lambda: 0,
                emit=lambda kind, **fields: events.append((kind, fields)),
                log=lambda _message: None,
                on_calibrated=lambda _message: None,
                record_path=record,
                reader=reader,
            )
            with mock.patch.object(monitor, "now", side_effect=[float(t) for t in range(0, 200, 5)]):
                for _ in range(14):
                    monitor.tick()
            lines = record.read_text().splitlines()
        self.assertEqual(len(lines), 14)
        self.assertEqual(json.loads(lines[-1])["cpu_fraction"], 0.975)
        self.assertEqual(json.loads(lines[-1])["net_rx_mbps"], 12.35)
        self.assertEqual(docker.limit, plan.parallel_docker - 1)
        self.assertEqual(gate.limit, plan.parallel_docker - 1 - 2)
        self.assertTrue(
            any("governor: docker slots" in str(fields.get("message", "")) for _, fields in events)
        )


if __name__ == "__main__":
    unittest.main()
