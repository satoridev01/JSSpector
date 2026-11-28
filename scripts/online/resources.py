"""Host capacity for `jsspector online`: probe, estimate, govern and calibrate.

The controller sizes its worker pools from what this host has free when a pass starts, keeps the
whole machine near a utilization target while the pass runs, and can measure what one Docker
verification costs here (`--calibrate`) so later passes size themselves from evidence instead of
the built-in model. Like the rest of the controller this module is stdlib-only.

Units: CPU is counted in logical CPUs as the kernel schedules them and memory in GiB. Built-in and
calibrated costs are stored per *full-capacity* core and scaled up on hosts whose cores are not all
equal (Arm big.LITTLE, Apple performance/efficiency cores): one verification needs more core-time
when part of it lands on a slower core.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Callable


GIB = 1024**3
DEFAULT_TARGET = 0.80
PROFILE_VERSION = 1
MAX_DOCKER_SLOTS = 64
# Static scans take milliseconds to seconds; a static worker mostly waits on `git clone`. Twelve was
# the hand-tuned default and remains the floor; very wide verification pools get a few more.
MIN_STATIC = 12
MAX_STATIC = 32
STATIC_PER_SLOT = 0.75
MIN_CHECKOUTS = 24
# Checkouts that may wait per verification slot, so a slot freed by a fast verification never
# starves while the static stage clones the next repository.
QUEUE_PER_SLOT = 3
# Fraction of free disk that retained checkouts may claim in the worst case (every checkout at
# --max-repo-size-mb).
CHECKOUT_DISK_SHARE = 0.10
APPLE_EFFICIENCY_WEIGHT = 0.35
VM_RESERVE_GIB = 1.0
SAMPLE_INTERVAL_S = 5.0
RESOURCE_LOG_INTERVAL_S = 60.0

# Governor thresholds around the target. The band is deliberately wide: one verification is a
# build burst followed by mostly idle probing, so a narrow band would oscillate.
CPU_HIGH_MARGIN = 0.08
CPU_LOW_MARGIN = 0.10
MEMORY_HIGH_MARGIN = 0.07
MEMORY_LOW_MARGIN = 0.10
MEMORY_PRESSURE_STOP = 10.0  # PSI "full avg10" percent: tasks stalled on memory
CPU_WINDOW_S = 120.0
INCREASE_COOLDOWN_S = 150.0  # a new verification needs this long to reach its build burst
CPU_DECREASE_COOLDOWN_S = 60.0
MEMORY_DECREASE_COOLDOWN_S = 30.0

# Calibration: two load levels, the first at half the estimate, measured after a warm-up that keeps
# first-time base-image pulls out of the fit.
CALIBRATION_LOW_SHARE = 0.4
CALIBRATION_WARMUP_S = 180.0
CALIBRATION_IDLE_GRACE_S = 20 * 60.0
MIN_FIT_SAMPLES = 30
MIN_FIT_SPREAD = 2
MIN_VERIFY_CPU = 0.2
MIN_VERIFY_MEMORY_GIB = 0.25
MIN_OVERHEAD_CPU = 0.5
MIN_OVERHEAD_MEMORY_GIB = 0.5
# Calibration checks: the high level must have been limited by Docker for more slots to help, and
# timeouts must not be significantly more frequent there (contention). Repositories differ a lot (an
# Electron app may need longer than the startup budget on an idle host), so a handful of extra
# timeouts is not evidence on its own: the rise must pass a one-sided Fisher exact test.
VERIFICATION_BOUND_SHARE = 0.5
CONTENTION_P_VALUE = 0.05
MIN_CONTENTION_TIMEOUTS = 3
MIN_LEVEL_VERIFICATIONS = 5
STATIC_BOUND_PER_SLOT = 1.5
# Downloads (clones, npm installs inside image builds, base-image pulls) share one link that the
# CPU and memory model cannot see. If received bytes barely grow while the slots grow by half or
# more, the link is the shared limit.
NETWORK_FLAT_RATIO = 1.25
# More slots must buy throughput: at least this share of the proportional gain in verifications per
# hour (doubling the slots must add 25%), or the low level was already the useful maximum.
THROUGHPUT_SCALING_SHARE = 0.25
# The governor adds a slot only while downloads stay below this share of the link's measured ceiling.
NETWORK_HEADROOM = 0.9

# Improvement metrics: only what changes a decision.
OUTCOMES = ("verified", "not-reproduced", "skipped", "timeout", "error")
OUTCOME_LABELS = {
    "verified": "issue",
    "not-reproduced": "no repro",
    "skipped": "skipped",
    "timeout": "timeout",
    "error": "error",
}
PHASES = ("startup", "candidate", "fix", "other")
PHASE_LABELS = {"startup": "build/start", "candidate": "probing", "fix": "fix", "other": "other"}
BOTTLENECKS = ("verification", "checkouts", "static", "discovery")
RECENT_WINDOW_S = 15 * 60.0
PERFORMANCE_EMIT_INTERVAL_S = 30.0
PERFORMANCE_LOG_INTERVAL_S = 600.0


# --- Host probe -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Host:
    """What this machine offers to one online pass right now."""

    platform: str
    cpu_model: str
    logical_cpus: int
    capacity_cpus: float
    busy_cpus: float
    mem_total_gib: float
    mem_available_gib: float
    docker: str  # "native", "vm" (Docker Desktop and friends) or "unavailable"
    docker_cpus: int
    disk_free_gib: float

    @property
    def core_weight(self) -> float:
        """Logical core-seconds one full-capacity core-second costs here (1.0 on uniform hosts)."""
        if self.capacity_cpus <= 0:
            return 1.0
        return max(1.0, self.logical_cpus / self.capacity_cpus)

    @property
    def mem_used_gib(self) -> float:
        return max(0.0, self.mem_total_gib - self.mem_available_gib)

    def fingerprint(self) -> dict[str, Any]:
        """Stable identity of the hardware a calibration applies to."""
        return {
            "platform": self.platform,
            "cpu_model": self.cpu_model,
            "logical_cpus": self.logical_cpus,
            "mem_total_gib": round(self.mem_total_gib),
            "docker": self.docker,
        }


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _run(command: list[str], timeout: float = 20) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def cpu_times(proc: Path = Path("/proc")) -> tuple[int, int] | None:
    """Aggregate (total, idle) jiffies from /proc/stat; iowait counts as idle."""
    text = _read(proc / "stat")
    if not text:
        return None
    fields = text.splitlines()[0].split()
    if not fields or fields[0] != "cpu":
        return None
    try:
        values = [int(value) for value in fields[1:9]]
    except ValueError:
        return None
    if len(values) < 5:
        return None
    return sum(values), values[3] + values[4]


def busy_fraction(before: tuple[int, int] | None, after: tuple[int, int] | None) -> float | None:
    if before is None or after is None:
        return None
    total = after[0] - before[0]
    idle = after[1] - before[1]
    if total <= 0:
        return None
    return min(1.0, max(0.0, 1.0 - idle / total))


def linux_memory(
    proc: Path = Path("/proc"), cgroup: Path = Path("/sys/fs/cgroup")
) -> tuple[float, float]:
    """(total, available) GiB, bounded by a cgroup v2 memory limit when one applies."""
    info: dict[str, int] = {}
    for line in (_read(proc / "meminfo") or "").splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            info[key] = int(parts[0]) * 1024
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    limit = (_read(cgroup / "memory.max") or "").strip()
    current = (_read(cgroup / "memory.current") or "").strip()
    if limit.isdigit() and current.isdigit():
        total = min(total, int(limit)) if total else int(limit)
        available = min(available, max(0, int(limit) - int(current)))
    return total / GIB, available / GIB


def linux_cpus(
    allowed: list[int] | None = None,
    sys_root: Path = Path("/sys"),
    cgroup: Path = Path("/sys/fs/cgroup"),
) -> tuple[int, float]:
    """(logical CPUs usable, capacity-weighted CPUs) honoring affinity and a cgroup quota."""
    if allowed is None:
        allowed = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
        if not allowed:
            allowed = list(range(os.cpu_count() or 1))
    capacities = []
    for cpu in allowed:
        raw = (_read(sys_root / f"devices/system/cpu/cpu{cpu}/cpu_capacity") or "").strip()
        capacities.append(int(raw) if raw.isdigit() and int(raw) > 0 else 1024)
    top = max(capacities)
    logical = len(allowed)
    capacity = sum(value / top for value in capacities)
    quota, _, period = (_read(cgroup / "cpu.max") or "").strip().partition(" ")
    if quota.isdigit() and period.isdigit() and int(period) > 0:
        limit = int(quota) / int(period)
        if limit < logical:
            capacity *= limit / logical
            logical = max(1, math.floor(limit))
    return logical, capacity


def linux_cpu_model() -> str:
    names: list[str] = []
    for line in (_run(["lscpu"]) or "").splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "Model name" and value.strip() and value.strip() not in names:
            names.append(value.strip())
    if not names:
        for line in (_read(Path("/proc/cpuinfo")) or "").splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "model name" and value.strip() not in names:
                names.append(value.strip())
    return " + ".join(names) or os.uname().machine


def _sysctl(name: str) -> str | None:
    value = _run(["sysctl", "-n", name])
    return value.strip() if value else None


def darwin_memory_available_gib() -> float | None:
    text = _run(["vm_stat"])
    if not text:
        return None
    page = re.search(r"page size of (\d+) bytes", text)
    size = int(page.group(1)) if page else 4096
    pages = 0
    for label in ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"):
        match = re.search(rf"{label}:\s+(\d+)", text)
        if match:
            pages += int(match.group(1))
    return pages * size / GIB


def docker_info() -> dict[str, Any] | None:
    output = _run(["docker", "info", "--format", "{{json .}}"], timeout=30)
    if not output:
        return None
    try:
        info = json.loads(output)
    except json.JSONDecodeError:
        return None
    return info if isinstance(info, dict) else None


def _existing(path: Path) -> Path:
    path = path.expanduser().absolute()
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def probe_host(
    out: Path, *, sample_s: float = 1.0, docker: dict[str, Any] | None | bool = True
) -> Host:
    """Measure CPUs, memory and disk that one pass may use, as seen by Docker.

    Docker Desktop (and every other macOS engine) runs containers in a VM: containers then share the
    VM's CPUs and memory, not the host's, so both are bounded by what `docker info` reports.
    """
    info = docker_info() if docker is True else (docker or None)
    if sys.platform == "darwin":
        logical = os.cpu_count() or 1
        performance = int(_sysctl("hw.perflevel0.logicalcpu") or 0)
        efficiency = int(_sysctl("hw.perflevel1.logicalcpu") or 0)
        capacity = (
            performance + efficiency * APPLE_EFFICIENCY_WEIGHT
            if performance
            else float(logical)
        )
        busy = min(float(logical), os.getloadavg()[0])
        mem_total = int(_sysctl("hw.memsize") or 0) / GIB
        mem_available = darwin_memory_available_gib() or mem_total * 0.5
        cpu_model = _sysctl("machdep.cpu.brand_string") or "Apple"
    else:
        logical, capacity = linux_cpus()
        before = cpu_times()
        time.sleep(sample_s)
        fraction = busy_fraction(before, cpu_times())
        busy = (fraction or 0.0) * logical
        mem_total, mem_available = linux_memory()
        cpu_model = linux_cpu_model()

    engine = "unavailable"
    docker_cpus = logical
    if info:
        operating_system = str(info.get("OperatingSystem", ""))
        engine = (
            "vm"
            if sys.platform == "darwin" or "Docker Desktop" in operating_system
            else "native"
        )
        docker_cpus = int(info.get("NCPU") or logical)
        docker_mem = int(info.get("MemTotal") or 0) / GIB
        if engine == "vm":
            # Containers see the VM; the host only matters when it is even tighter.
            if docker_cpus < logical:
                capacity *= docker_cpus / logical
                busy *= docker_cpus / logical
                logical = docker_cpus
            if docker_mem:
                mem_available = min(mem_available, max(0.0, docker_mem - VM_RESERVE_GIB))
                mem_total = docker_mem
    return Host(
        platform=sys.platform,
        cpu_model=cpu_model,
        logical_cpus=logical,
        capacity_cpus=round(capacity, 2),
        busy_cpus=round(busy, 2),
        mem_total_gib=round(mem_total, 1),
        mem_available_gib=round(mem_available, 1),
        docker=engine,
        docker_cpus=docker_cpus,
        disk_free_gib=round(shutil.disk_usage(_existing(out)).free / GIB, 1),
    )


# --- Cost model and plan --------------------------------------------------------------------


@dataclass(frozen=True)
class Costs:
    """Average load of one unit of online work, per full-capacity core.

    The built-in values come from measuring a full strict verification (Express + MongoDB, six
    candidates, about five minutes) on an Arm GB10 host, with margin: ~0.75 logical CPUs and
    ~0.75 GiB. The peak bounds a verification by the sandbox's own container caps (app 1 GiB,
    database/cache sidecars, browser 2 GiB) plus an image build.
    """

    verify_cpu: float = 0.9
    verify_mem_gib: float = 1.5
    verify_peak_mem_gib: float = 4.5
    static_cpu: float = 0.1
    static_mem_gib: float = 0.15
    overhead_cpu: float = 1.0
    overhead_mem_gib: float = 2.0
    # Static workers per Docker slot (at least MIN_STATIC); a calibration that found the static
    # stage limiting raises it.
    static_per_slot: float = STATIC_PER_SLOT
    # Hard cap: most Docker slots worth running here. Only a calibration that saw timeouts grow
    # significantly with load (contention) sets it; the governor never goes above it.
    max_docker_slots: float = MAX_DOCKER_SLOTS
    # Where a pass starts: the highest level a calibration saw pay off. The governor may climb from
    # here while the host keeps headroom and verifications queue.
    start_docker_slots: float = MAX_DOCKER_SLOTS
    # MB/s the downloads levelled off at during calibration (0 when unknown); the governor stops
    # adding slots near it.
    network_ceiling_mbps: float = 0.0
    source: str = "built-in"


@dataclass(frozen=True)
class Plan:
    """Resolved worker counts for one pass and the budget they came from."""

    static_parallel: int
    max_checkouts: int
    parallel_no_ai: int
    parallel_ai: int
    parallel_docker: int
    docker_floor: int
    docker_ceiling: int
    cpu_budget: float
    mem_budget_gib: float
    verify_cpu: float
    verify_mem_gib: float
    limited_by: str
    explicit: tuple[str, ...] = ()

    def load(self, costs: Costs, host: Host, docker: int | None = None) -> tuple[float, float]:
        """Estimated (CPU, GiB) this plan adds at `docker` concurrent verifications."""
        slots = self.parallel_docker if docker is None else docker
        weight = host.core_weight
        cpu = (
            costs.overhead_cpu * weight
            + slots * costs.verify_cpu * weight
            + self.static_parallel * costs.static_cpu * weight
        )
        memory = (
            costs.overhead_mem_gib
            + slots * costs.verify_mem_gib
            + self.static_parallel * costs.static_mem_gib
        )
        return cpu, memory


def static_for(docker: int, per_slot: float = STATIC_PER_SLOT) -> int:
    return min(MAX_STATIC, max(MIN_STATIC, math.ceil(docker * per_slot)))


def checkouts_for(
    static: int, docker_ceiling: int, disk_free_gib: float, max_repo_size_mb: int
) -> int:
    wanted = max(MIN_CHECKOUTS, static + QUEUE_PER_SLOT * docker_ceiling)
    disk_cap = math.floor(
        disk_free_gib * CHECKOUT_DISK_SHARE * 1024 / max(1, max_repo_size_mb)
    )
    return max(1, min(wanted, max(static + docker_ceiling, disk_cap)))


def estimate(
    host: Host,
    costs: Costs,
    *,
    target: float = DEFAULT_TARGET,
    parallel_ai: int = 2,
    ai_lane: bool = True,
    static_parallel: int | None = None,
    max_checkouts: int | None = None,
    parallel_no_ai: int | None = None,
    parallel_docker: int | None = None,
    max_repo_size_mb: int = 100,
) -> Plan:
    """Size the pass so the whole host stays near `target` CPU and memory use.

    The budget is the target share of the machine minus what other processes already use, so a
    running model server or build automatically shrinks the plan. Explicit counts always win; the
    rest are derived from them so the lanes, Docker slots and checkouts stay coherent.
    """
    weight = host.core_weight
    verify_cpu = costs.verify_cpu * weight
    static_cpu = costs.static_cpu * weight
    overhead_cpu = costs.overhead_cpu * weight
    cpu_budget = target * host.logical_cpus - host.busy_cpus
    mem_budget = target * host.mem_total_gib - host.mem_used_gib
    requested_ai_workers = parallel_ai if ai_lane else 0
    # One verification is the only irreducible floor.  Treat the Opus count as a preferred lane
    # width, not reserved Docker capacity: forcing two AI slots plus one deterministic slot made a
    # busy host exceed the utilization target before the governor could react.
    floor = 1

    max_docker = max(1, min(MAX_DOCKER_SLOTS, int(costs.max_docker_slots)))

    def fits(docker: int) -> tuple[bool, bool]:
        static = static_parallel or static_for(docker, costs.static_per_slot)
        cpu = overhead_cpu + docker * verify_cpu + static * static_cpu
        memory = (
            costs.overhead_mem_gib
            + docker * costs.verify_mem_gib
            + static * costs.static_mem_gib
        )
        return cpu <= cpu_budget, memory <= mem_budget

    docker = 0
    for candidate in range(max_docker, 0, -1):
        cpu_ok, memory_ok = fits(candidate)
        if cpu_ok and memory_ok:
            docker = candidate
            break
    if docker == max_docker:
        limited_by = "ceiling" if max_docker == MAX_DOCKER_SLOTS else "calibrated cap"
    elif docker == 0:
        limited_by = "minimum"
    else:
        cpu_ok, memory_ok = fits(docker + 1)
        limited_by = "cpu" if not cpu_ok else "memory"
    fitted = docker
    start = int(costs.start_docker_slots)
    if start < docker:
        docker = start
        limited_by = "calibrated start"
    if docker < floor:
        docker = floor
        limited_by = "minimum"

    explicit: list[str] = []
    if parallel_docker is not None:
        docker = parallel_docker
        explicit.append("parallel_docker")
    elif parallel_no_ai is not None:
        docker = parallel_no_ai + requested_ai_workers
    ai_workers = min(requested_ai_workers, max(0, docker - 1))
    if parallel_no_ai is not None:
        explicit.append("parallel_no_ai")
        no_ai = parallel_no_ai
    else:
        no_ai = max(1, docker - ai_workers)
    if static_parallel is not None:
        explicit.append("static_parallel")
    static = static_parallel or static_for(docker, costs.static_per_slot)

    usable_memory = mem_budget - costs.overhead_mem_gib - static * costs.static_mem_gib
    memory_ceiling = math.floor(usable_memory / costs.verify_peak_mem_gib)
    # The governor may climb past a calibrated start up to what CPU and memory fit (at most twice
    # the start), never past the hard cap or what memory allows at the per-verification peak.
    ceiling = max(docker, min(max_docker, max(2 * docker, fitted), memory_ceiling))
    if max_checkouts is not None:
        explicit.append("max_checkouts")
        checkouts = max_checkouts
    else:
        checkouts = checkouts_for(static, ceiling, host.disk_free_gib, max_repo_size_mb)
    return Plan(
        static_parallel=static,
        max_checkouts=checkouts,
        parallel_no_ai=no_ai,
        parallel_ai=ai_workers,
        parallel_docker=docker,
        docker_floor=floor,
        docker_ceiling=ceiling,
        cpu_budget=round(cpu_budget, 2),
        mem_budget_gib=round(mem_budget, 1),
        verify_cpu=round(verify_cpu, 2),
        verify_mem_gib=round(costs.verify_mem_gib, 2),
        limited_by=limited_by,
        explicit=tuple(explicit),
    )


def render_plan(
    host: Host,
    costs: Costs,
    plan: Plan,
    *,
    target: float,
    governed: bool,
    ai_lane: bool = True,
) -> str:
    """Human-readable capacity report printed by `jsspector online --estimate`."""
    cpu_load, memory_load = plan.load(costs, host)
    engine = {
        "native": "native engine",
        "vm": f"VM with {host.docker_cpus} CPUs and {host.mem_total_gib:.1f} GiB",
        "unavailable": "not reachable (estimate uses the host)",
    }[host.docker]
    uniform = abs(host.capacity_cpus - host.logical_cpus) < 0.05
    capacity = (
        ""
        if uniform
        else f" (≈{host.capacity_cpus:g} at full-core capacity: cores are not all equal)"
    )
    lanes = (
        f"deterministic {plan.parallel_no_ai} + Opus {plan.parallel_ai}"
        if ai_lane
        else f"deterministic {plan.parallel_no_ai}, Opus ranking off"
    )
    cost_note = (
        "built-in; `jsspector online --calibrate` measures this host"
        if costs.source == "built-in"
        else costs.source
    )
    lines = [
        f"jsspector online capacity — target {target:.0%} of this host",
        f"  host     {host.cpu_model}",
        f"  CPU      {host.logical_cpus} logical{capacity}, {host.busy_cpus:g} busy now",
        f"  memory   {host.mem_total_gib:.1f} GiB, {host.mem_available_gib:.1f} GiB available",
        f"  docker   {engine}",
        f"  disk     {host.disk_free_gib:.0f} GiB free",
        f"  cost     {plan.verify_cpu:g} CPU and {plan.verify_mem_gib:g} GiB per concurrent "
        f"verification ({cost_note})",
        f"  budget   {plan.cpu_budget:g} CPU and {plan.mem_budget_gib:g} GiB "
        f"(target minus other processes)",
        f"  plan     docker {plan.parallel_docker} ({lanes}), static {plan.static_parallel}, "
        f"checkouts {plan.max_checkouts} — limited by {plan.limited_by}",
        f"  load     ≈{cpu_load:.1f} CPU ({(host.busy_cpus + cpu_load) / host.logical_cpus:.0%} of "
        f"the host with current load) and ≈{memory_load:.1f} GiB",
    ]
    if governed:
        projected = (host.busy_cpus + cpu_load) / host.logical_cpus
        if projected > target and plan.parallel_docker == plan.docker_floor:
            lines.append(
                f"  governor starts at its {plan.docker_floor}-slot minimum; current external "
                f"load leaves too little budget to reach {target:.0%} until that load falls"
            )
        else:
            lines.append(
                f"  governor keeps the host near {target:.0%} with {plan.docker_floor}–"
                f"{plan.docker_ceiling} docker slots while the pass runs"
            )
    else:
        lines.append("  governor off: worker counts stay fixed")
    if plan.explicit:
        lines.append(f"  explicit {', '.join(plan.explicit)} (kept as given)")
    lines.append(
        "  default  before auto-sizing: docker 4 (deterministic 2 + Opus 2), static 12, "
        "checkouts 24"
    )
    return "\n".join(lines)


# --- Host profile ---------------------------------------------------------------------------


def default_profile_path() -> Path:
    override = os.environ.get("JSSPECTOR_ONLINE_PROFILE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "jsspector" / "online-profile.json"


def load_profile(path: Path, host: Host) -> tuple[Costs | None, str | None]:
    """Calibrated costs when the profile was measured on this hardware, else why not."""
    if not path.is_file():
        return None, None
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return None, f"ignoring unreadable host profile {path}: {error}"
    if profile.get("version") != PROFILE_VERSION:
        return None, f"ignoring host profile {path}: unsupported version"
    if profile.get("host") != host.fingerprint():
        return None, (
            f"ignoring host profile {path}: it was calibrated on different hardware "
            "(run `jsspector online --calibrate` here)"
        )
    raw = profile.get("costs")
    if not isinstance(raw, dict):
        return None, f"ignoring host profile {path}: no costs"
    known = {name for name in Costs.__dataclass_fields__ if name != "source"}
    try:
        values = {name: float(raw[name]) for name in known if name in raw}
    except (TypeError, ValueError):
        return None, f"ignoring host profile {path}: invalid costs"
    stamp = str(profile.get("calibrated_at", "unknown time"))[:16].replace("T", " ")
    return replace(Costs(), **values, source=f"calibrated on this host {stamp} UTC"), None


def save_profile(path: Path, profile: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


# --- Adjustable concurrency -----------------------------------------------------------------


class AdjustableSlots:
    """A first-come, first-served counting semaphore whose limit can change at any time.

    Lowering the limit never interrupts a holder; it only delays later acquisitions until enough
    holders have released. Setting `wake` (the controller's shutdown event) lets every waiter
    through at once so a cancelled pass drains promptly; acquire() then returns False and the slot
    must still be released.
    """

    def __init__(self, limit: int, *, wake: threading.Event | None = None) -> None:
        if limit < 1:
            raise ValueError("slot limit must be positive")
        self._limit = limit
        self._active = 0
        self._queue: deque[object] = deque()
        self._condition = threading.Condition()
        self._wake = wake

    def acquire(self) -> bool:
        token = object()
        with self._condition:
            self._queue.append(token)
            try:
                while True:
                    if self._wake is not None and self._wake.is_set():
                        self._queue.remove(token)
                        self._active += 1
                        self._condition.notify_all()
                        return False
                    if self._queue[0] is token and self._active < self._limit:
                        self._queue.popleft()
                        self._active += 1
                        self._condition.notify_all()
                        return True
                    self._condition.wait(0.5)
            except BaseException:
                if token in self._queue:
                    self._queue.remove(token)
                    self._condition.notify_all()
                raise

    def release(self) -> None:
        with self._condition:
            if self._active <= 0:
                raise ValueError("slot released more often than acquired")
            self._active -= 1
            self._condition.notify_all()

    def set_limit(self, limit: int) -> None:
        with self._condition:
            self._limit = max(1, limit)
            self._condition.notify_all()

    @property
    def limit(self) -> int:
        with self._condition:
            return self._limit

    def snapshot(self) -> tuple[int, int, int]:
        """(active holders, queued waiters, limit)."""
        with self._condition:
            return self._active, len(self._queue), self._limit

    def __enter__(self) -> AdjustableSlots:
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


# --- Live usage -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Sample:
    """One whole-host observation while a pass runs."""

    t: float
    cpu_busy: float
    cpu_fraction: float
    mem_used_gib: float
    mem_fraction: float
    cpu_pressure: float | None
    mem_pressure: float | None
    active: int
    waiting: int
    limit: int
    static_active: int
    saturated: bool = False
    checkouts: int = 0
    checkout_capacity: int = 0
    net_rx_mbps: float | None = None


class CountedSemaphore(threading.Semaphore):
    """A semaphore that reports how many permits are held and can grow while holders run."""

    def __init__(self, value: int) -> None:
        super().__init__(value)
        self.capacity = value
        self._held = 0
        self._count_lock = threading.Lock()

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        acquired = super().acquire(blocking, timeout)
        if acquired:
            with self._count_lock:
                self._held += 1
        return acquired

    def release(self, n: int = 1) -> None:
        with self._count_lock:
            if self._held < n:
                raise ValueError("permit released more often than acquired")
            self._held -= n
        super().release(n)

    def grow_to(self, total: int) -> None:
        """Raise the number of permits to `total` (never lowers it)."""
        with self._count_lock:
            extra = total - self.capacity
            if extra <= 0:
                return
            self.capacity = total
        super().release(extra)

    # threading.Semaphore aliases __enter__ to its own acquire, which would bypass the count.
    def __enter__(self) -> bool:
        return self.acquire()

    @property
    def held(self) -> int:
        with self._count_lock:
            return self._held


def pressure(path: Path, kind: str) -> float | None:
    """PSI avg10 percentage for `some` or `full` stalls, when the kernel exposes it."""
    text = _read(path)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith(kind + " "):
            match = re.search(r"avg10=([\d.]+)", line)
            if match:
                return float(match.group(1))
    return None


def _parse_size_gib(text: str) -> float:
    match = re.match(r"\s*([\d.]+)\s*([KMGT]?i?B)", text)
    if not match:
        return 0.0
    scale = {
        "B": 1,
        "KB": 1e3,
        "KiB": 1024,
        "MB": 1e6,
        "MiB": 1024**2,
        "GB": 1e9,
        "GiB": GIB,
        "TB": 1e12,
        "TiB": 1024**4,
    }.get(match.group(2), 1)
    return float(match.group(1)) * scale / GIB


class UsageReader:
    """Whole-host CPU and memory use between calls (Linux /proc, or macOS + the Docker VM)."""

    def __init__(
        self, host: Host, proc: Path = Path("/proc"), sys_root: Path = Path("/sys")
    ) -> None:
        self.host = host
        self.proc = proc
        self.sys_root = sys_root
        self._last = cpu_times(proc) if host.platform != "darwin" else None
        self._net_last = self._received_bytes()
        self._net_time = time.monotonic()

    def _received_bytes(self) -> int | None:
        """Bytes received so far on physical interfaces (bridges, veths and lo have no device)."""
        if self.host.platform == "darwin":
            return None
        total = 0
        found = False
        for line in (_read(self.proc / "net/dev") or "").splitlines()[2:]:
            name, _, data = line.partition(":")
            fields = data.split()
            if not fields or not (self.sys_root / "class/net" / name.strip() / "device").exists():
                continue
            try:
                total += int(fields[0])
            except ValueError:
                continue
            found = True
        return total if found else None

    def network(self) -> float | None:
        """MB/s received on physical interfaces since the previous call."""
        current = self._received_bytes()
        now = time.monotonic()
        last, last_time = self._net_last, self._net_time
        self._net_last, self._net_time = current, now
        if current is None or last is None or now <= last_time:
            return None
        return max(0.0, (current - last) / (now - last_time) / 1e6)

    def read(self) -> tuple[float, float, float | None, float | None]:
        """(busy logical CPUs, used GiB, CPU pressure, memory pressure)."""
        logical = self.host.logical_cpus
        if self.host.platform == "darwin":
            busy = min(float(logical), os.getloadavg()[0])
            used = self._vm_memory_used()
            return busy, used, None, None
        current = cpu_times(self.proc)
        fraction = busy_fraction(self._last, current)
        self._last = current
        total, available = linux_memory(self.proc)
        if self.host.docker == "vm":
            total = self.host.mem_total_gib
        return (
            (fraction or 0.0) * logical,
            max(0.0, total - available),
            pressure(self.proc / "pressure/cpu", "some"),
            pressure(self.proc / "pressure/memory", "full"),
        )

    def _vm_memory_used(self) -> float:
        output = _run(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"], timeout=15
        )
        used = sum(
            _parse_size_gib(line.split("/")[0]) for line in (output or "").splitlines()
        )
        return used + VM_RESERVE_GIB


@dataclass
class GovernorState:
    limit: int
    floor: int
    ceiling: int
    last_increase: float = -math.inf
    last_decrease: float = -math.inf
    network_ceiling: float = 0.0


def govern(
    state: GovernorState, window: list[Sample], *, target: float, now: float
) -> tuple[int, str | None]:
    """Next Docker slot limit and why, from recent whole-host samples.

    Memory is guarded first and cut by a quarter, because exhausting it kills containers; CPU above
    the band sheds one slot; one slot is added only when CPU and memory have headroom, downloads are
    below the link's calibrated ceiling, every slot is busy and work is waiting, and the previous
    change has had time to show in the samples.
    """
    if not window:
        return state.limit, None
    latest = window[-1]
    recent = [sample for sample in window if sample.t >= now - CPU_WINDOW_S]
    cpu = sum(sample.cpu_fraction for sample in recent) / len(recent)
    memory = latest.mem_fraction
    history = now - window[0].t
    memory_stalled = (latest.mem_pressure or 0.0) >= MEMORY_PRESSURE_STOP
    if (
        (memory >= target + MEMORY_HIGH_MARGIN or memory_stalled)
        and state.limit > state.floor
        and now - state.last_decrease >= MEMORY_DECREASE_COOLDOWN_S
    ):
        reason = "memory pressure" if memory_stalled else f"memory {memory:.0%}"
        return max(state.floor, state.limit - max(1, state.limit // 4)), reason
    if (
        cpu >= target + CPU_HIGH_MARGIN
        and state.limit > state.floor
        and history >= CPU_DECREASE_COOLDOWN_S
        and now - state.last_decrease >= CPU_DECREASE_COOLDOWN_S
    ):
        return state.limit - 1, f"cpu {cpu:.0%}"
    network = [sample.net_rx_mbps for sample in recent if sample.net_rx_mbps is not None]
    network_mean = sum(network) / len(network) if network else 0.0
    network_ok = not state.network_ceiling or network_mean < NETWORK_HEADROOM * state.network_ceiling
    if (
        cpu <= target - CPU_LOW_MARGIN
        and memory <= target - MEMORY_LOW_MARGIN
        and network_ok
        and latest.saturated
        and state.limit < state.ceiling
        and history >= CPU_WINDOW_S
        and now - max(state.last_increase, state.last_decrease) >= INCREASE_COOLDOWN_S
    ):
        return state.limit + 1, (
            f"headroom: cpu {cpu:.0%}, memory {memory:.0%}"
            + (f", network {network_mean:.1f} MB/s" if network else "")
        )
    return state.limit, None


# --- Improvement metrics --------------------------------------------------------------------
#
# Issues per hour is verifications per hour times issues per verification. Three measurements say
# which factor to work on and how: where Docker slot time goes (by outcome, and build/start versus
# probing), which stage limits the pass, and what each lane yields per slot-hour.


@dataclass(frozen=True)
class VerificationRecord:
    """One finished repository verification, timed on the monitor's clock."""

    lane: str
    outcome: str  # one of OUTCOMES
    started: float
    finished: float
    slot_s: float
    phases: dict[str, float] = field(default_factory=dict)
    findings: int = 0
    skip_reason: str | None = None


def outcome_kind(
    *,
    cancelled: bool,
    failed: bool,
    failure_reason: str | None,
    findings: int,
    driven: str,
) -> str | None:
    """Improvement bucket for one verification, or None when it was cancelled."""
    if cancelled:
        return None
    if failed:
        return "timeout" if (failure_reason or "").endswith("timeout") else "error"
    if findings:
        return "verified"
    return "skipped" if driven == "skipped" else "not-reproduced"


def bottleneck(sample: Sample, static_parallel: int) -> str:
    """The stage that limited the pass at one sample.

    Docker is the limit when a verification gate is full with work waiting. Otherwise, a full
    checkout budget means queued repositories (typically a slower lane) block cloning; busy static
    workers mean cloning/scanning cannot feed Docker; anything else is waiting on discovery.
    """
    if sample.saturated:
        return "verification"
    if sample.checkout_capacity and sample.checkouts >= sample.checkout_capacity:
        return "checkouts"
    if sample.static_active >= static_parallel:
        return "static"
    return "discovery"


class Performance:
    """Thread-safe log of finished verifications."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[VerificationRecord] = []

    def record(self, record: VerificationRecord) -> None:
        with self._lock:
            self._records.append(record)

    def snapshot(self) -> list[VerificationRecord]:
        with self._lock:
            return list(self._records)


def _short_reason(reason: str) -> str:
    text = re.sub(r"\s+", " ", reason).strip()
    text = re.sub(r"[0-9a-f]{12,}", "…", text)
    return text[:60] + ("…" if len(text) > 60 else "")


def performance_summary(
    records: list[VerificationRecord],
    samples: list[Sample],
    *,
    static_parallel: int,
    start: float | None = None,
    end: float | None = None,
) -> dict[str, Any]:
    """The three improvement measurements over [start, end) of the monitor clock."""
    low = -math.inf if start is None else start
    high = math.inf if end is None else end
    chosen = [record for record in records if low <= record.finished < high]
    window = [sample for sample in samples if low <= sample.t <= high]
    slot_total = sum(record.slot_s for record in chosen)
    issues = sum(record.findings for record in chosen)

    def share(value: float, total: float) -> float:
        return round(value / total, 3) if total > 0 else 0.0

    docker_time = {
        outcome: share(
            sum(record.slot_s for record in chosen if record.outcome == outcome), slot_total
        )
        for outcome in OUTCOMES
    }
    phase_totals = {phase: 0.0 for phase in PHASES}
    for record in chosen:
        known = 0.0
        for phase in ("startup", "candidate", "fix"):
            value = record.phases.get(phase, 0.0)
            phase_totals[phase] += value
            known += value
        phase_totals["other"] += max(0.0, record.slot_s - known)
    phase_sum = sum(phase_totals.values())
    skips = Counter(
        _short_reason(record.skip_reason)
        for record in chosen
        if record.outcome == "skipped" and record.skip_reason
    )
    counts = Counter(bottleneck(sample, static_parallel) for sample in window)
    lanes: dict[str, dict[str, Any]] = {}
    for lane in sorted({record.lane for record in chosen}):
        lane_records = [record for record in chosen if record.lane == lane]
        slot_hours = sum(record.slot_s for record in lane_records) / 3600
        lane_issues = sum(record.findings for record in lane_records)
        lanes[lane] = {
            "verifications": len(lane_records),
            "issues": lane_issues,
            "slot_hours": round(slot_hours, 3),
            "issues_per_slot_hour": round(lane_issues / slot_hours, 2) if slot_hours else None,
            "slot_minutes_per_issue": (
                round(slot_hours * 60 / lane_issues, 1) if lane_issues else None
            ),
        }
    span_s = None
    if window:
        span_s = window[-1].t - window[0].t
    elif start is not None and end is not None and math.isfinite(end):
        span_s = end - start
    slot_times = sorted(record.slot_s for record in chosen)
    pressures = [sample.cpu_pressure for sample in window if sample.cpu_pressure is not None]
    network = sorted(sample.net_rx_mbps for sample in window if sample.net_rx_mbps is not None)
    return {
        "verifications": len(chosen),
        "outcomes": {
            outcome: sum(1 for record in chosen if record.outcome == outcome)
            for outcome in OUTCOMES
        },
        "issues": issues,
        "cpu_mean": (
            round(sum(sample.cpu_fraction for sample in window) / len(window), 3)
            if window
            else None
        ),
        "cpu_pressure_mean": round(sum(pressures) / len(pressures), 1) if pressures else None,
        "net_rx_mean": round(sum(network) / len(network), 1) if network else None,
        "net_rx_p95": round(network[int(0.95 * (len(network) - 1))], 1) if network else None,
        "slot_hours": round(slot_total / 3600, 3),
        "verifications_per_hour": (
            round(len(chosen) * 3600 / span_s, 1) if span_s and span_s > 0 else None
        ),
        "median_slot_s": round(median(slot_times)) if slot_times else None,
        "slot_minutes_per_issue": round(slot_total / 60 / issues, 1) if issues else None,
        "docker_time": docker_time,
        "phases": {phase: share(value, phase_sum) for phase, value in phase_totals.items()},
        "top_skip_reasons": [[reason, count] for reason, count in skips.most_common(5)],
        "bottleneck": {name: share(counts[name], len(window)) for name in BOTTLENECKS},
        "samples": len(window),
        "lanes": lanes,
    }


def _percentages(values: dict[str, float], labels: dict[str, str] | None = None) -> str:
    return " · ".join(
        f"{(labels or {}).get(name, name)} {value:.0%}" for name, value in values.items()
    )


LANE_LABELS = {"no-ai": "deterministic", "ai": "Opus"}


def lane_yield(lane: str, stats: dict[str, Any]) -> str:
    """`deterministic 3 issues in 40 runs, 1 per 17 Docker-min`: whole counts, no rates."""
    label = LANE_LABELS.get(lane, lane)
    runs = stats["verifications"]
    issues = stats["issues"]
    minutes = stats["slot_hours"] * 60
    if not issues:
        return f"{label} no issue in {runs} runs ({minutes:.0f} Docker-min)"
    return (
        f"{label} {issues} issue{'s' if issues != 1 else ''} in {runs} runs, "
        f"1 per {minutes / issues:.0f} Docker-min"
    )


def performance_lines(
    overall: dict[str, Any], recent: dict[str, Any], *, window: str = "last 15 min"
) -> list[str]:
    """Compact panel text: Docker time and lanes for the whole pass, bottleneck for `window`."""
    if not overall["verifications"]:
        docker = "Docker time  collecting… (no verification finished yet)"
        phases = "  of which   –"
    else:
        per_issue = overall["slot_minutes_per_issue"]
        docker = (
            f"Docker time  {_percentages(overall['docker_time'], OUTCOME_LABELS)}  ·  "
            + (
                f"1 issue per {per_issue:.0f} Docker-min"
                if per_issue is not None
                else "no issue yet"
            )
        )
        top = overall["top_skip_reasons"]
        phases = f"  of which   {_percentages(overall['phases'], PHASE_LABELS)}" + (
            f"  ·  top skip: {top[0][0]} ×{top[0][1]}" if top else ""
        )
    network = recent.get("net_rx_mean")
    bottleneck_line = (
        f"Bottleneck   {_percentages(recent['bottleneck'])}"
        + (f"  ·  network {network:g} MB/s" if network is not None else "")
        + f"  ({window})"
        if recent["samples"]
        else "Bottleneck   collecting…"
    )
    lane_parts = [lane_yield(lane, stats) for lane, stats in overall["lanes"].items()]
    lanes = "Lanes        " + (" · ".join(lane_parts) if lane_parts else "collecting…")
    return [docker, phases, bottleneck_line, lanes]


# --- Calibration ----------------------------------------------------------------------------


@dataclass
class Calibration:
    """Two fixed load levels whose samples reveal what one verification costs on this host."""

    low: int
    high: int
    window_s: float
    phase: str = "waiting"
    clock_start: float | None = None
    switched_at: float | None = None
    finished_at: float | None = None

    def advance(self, sample: Sample) -> tuple[int | None, str | None]:
        """(new slot limit, phase message) after observing one sample."""
        if self.phase == "done":
            return None, None
        if self.phase == "waiting":
            if sample.active >= 1:
                self.phase = "low"
                self.clock_start = sample.t
                return self.low, (
                    f"calibration: measuring {self.low} concurrent verifications"
                )
            if sample.t >= CALIBRATION_IDLE_GRACE_S:
                self.phase = "done"
                self.finished_at = sample.t
                return None, "calibration: no verification started; stopping"
            return None, None
        assert self.clock_start is not None
        elapsed = sample.t - self.clock_start
        if self.phase == "low" and elapsed >= self.window_s * CALIBRATION_LOW_SHARE:
            self.phase = "high"
            self.switched_at = sample.t
            return self.high, (
                f"calibration: measuring {self.high} concurrent verifications"
            )
        if self.phase == "high" and elapsed >= self.window_s:
            self.phase = "done"
            self.finished_at = sample.t
            return None, "calibration window complete; stopping safely"
        return None, None


def fit_line(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    """Least-squares (intercept, slope, r²)."""
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx == 0:
        return mean_y, 0.0, 0.0
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    syy = sum((y - mean_y) ** 2 for y in ys)
    residual = sum(
        (y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys, strict=True)
    )
    r2 = 1.0 - residual / syy if syy else 0.0
    return intercept, slope, r2


def _level(
    records: list[VerificationRecord],
    samples: list[Sample],
    *,
    static_parallel: int,
    start: float | None,
    end: float | None,
) -> dict[str, Any]:
    if start is None or end is None or end <= start:
        return {"minutes": 0.0, "verifications": 0}
    return {
        "minutes": round((end - start) / 60, 1),
        **performance_summary(
            records, samples, static_parallel=static_parallel, start=start, end=end
        ),
    }


def fisher_greater(low_hits: int, low_n: int, high_hits: int, high_n: int) -> float:
    """One-sided Fisher exact p-value that the high group's hit rate exceeds the low group's."""
    hits = low_hits + high_hits
    total = low_n + high_n
    if hits == 0 or total == 0:
        return 1.0
    denominator = math.comb(total, hits)
    tail = sum(
        math.comb(high_n, k) * math.comb(low_n, hits - k)
        for k in range(high_hits, min(hits, high_n) + 1)
        if hits - k <= low_n
    )
    return min(1.0, tail / denominator)


@dataclass(frozen=True)
class Checks:
    """What the two calibration levels say beyond the CPU and memory fit."""

    notes: list[str]
    static_per_slot: float
    start_docker_slots: float
    max_docker_slots: float
    network_ceiling_mbps: float


def calibration_checks(
    low: dict[str, Any], high: dict[str, Any], *, high_slots: int, low_slots: int | None = None
) -> Checks:
    """Start level, hard cap, static scaling and link ceiling from the two levels' metrics.

    A pass starts at most at the highest level calibration ran (the governor explores beyond it);
    the low level when the link was saturated or when more slots did not raise throughput while
    Docker was the limit. Only significant contention sets a hard cap.

    The CPU and memory fit says what the host could run; these checks say whether running it pays.
    More slots must raise verifications per hour; Docker must have been what limited the high level;
    downloads must not have hit the link's ceiling (then wider static stages only split the same
    link); and timeouts must not be significantly more frequent at the high level (contention).
    """
    notes: list[str] = []
    static_per_slot = STATIC_PER_SLOT
    max_docker = float(MAX_DOCKER_SLOTS)
    start = float(high_slots)
    network_ceiling = 0.0

    low_network = low.get("net_rx_mean")
    high_network = high.get("net_rx_mean")
    network_saturated = bool(
        low_slots
        and high_slots >= 1.5 * low_slots
        and low_network
        and high_network is not None
        and high_network < low_network * NETWORK_FLAT_RATIO
    )
    if network_saturated:
        network_ceiling = float(high.get("net_rx_p95") or high_network)
        start = float(low_slots or high_slots)
        notes.append(
            f"downloads stayed near {high_network:g} MB/s at {high_slots} slots "
            f"({low_network:g} MB/s at {low_slots}): the link levels off near "
            f"{network_ceiling:g} MB/s; passes start at {int(start)} slots and the governor adds "
            "slots only below it"
        )

    low_rate = low.get("verifications_per_hour")
    high_rate = high.get("verifications_per_hour")
    low_bound = low.get("bottleneck", {}).get("verification", 0.0) >= VERIFICATION_BOUND_SHARE
    if low_slots and high_slots > low_slots and low_rate and high_rate is not None:
        wanted = 1 + THROUGHPUT_SCALING_SHARE * (high_slots / low_slots - 1)
        if high_rate < low_rate * wanted and low_bound:
            start = min(start, float(low_slots))
            notes.append(
                f"throughput went from {low_rate:g} to {high_rate:g} verifications/h as the "
                f"slots went from {low_slots} to {high_slots} while Docker was the limit: passes "
                f"start at {low_slots}"
            )
        elif high_rate < low_rate * wanted:
            notes.append(
                f"throughput went from {low_rate:g} to {high_rate:g} verifications/h, but Docker "
                f"limited the {low_slots}-slot level only "
                f"{low.get('bottleneck', {}).get('verification', 0.0):.0%} of the time, so this "
                "says nothing about slots"
            )

    shares = high.get("bottleneck", {})
    if high.get("samples") and shares.get("verification", 0.0) < VERIFICATION_BOUND_SHARE:
        limiter = max(
            (name for name in BOTTLENECKS if name != "verification"),
            key=lambda name: shares.get(name, 0.0),
        )
        notes.append(
            f"at {high_slots} slots Docker was the limit only "
            f"{shares.get('verification', 0.0):.0%} of the time and {limiter} "
            f"{shares.get(limiter, 0.0):.0%}: more slots alone will not raise throughput"
        )
        if limiter == "static" and not network_saturated:
            static_per_slot = STATIC_BOUND_PER_SLOT
            notes.append(
                f"later passes run {STATIC_BOUND_PER_SLOT:g} static workers per Docker slot"
            )
        elif limiter == "static":
            notes.append("static workers stay as they are: their clones share the saturated link")
        elif limiter == "discovery":
            notes.append("discovery starves the pipeline: add GITHUB_TOKENS or widen --since")
        else:
            notes.append(
                "queued repositories hold every checkout: raise --max-checkouts or rebalance lanes"
            )

    low_n = low.get("verifications", 0)
    high_n = high.get("verifications", 0)
    if low_n >= MIN_LEVEL_VERIFICATIONS and high_n >= MIN_LEVEL_VERIFICATIONS:
        low_timeouts = low.get("outcomes", {}).get("timeout", 0)
        high_timeouts = high.get("outcomes", {}).get("timeout", 0)
        if high_timeouts / high_n > low_timeouts / low_n:
            p_value = fisher_greater(low_timeouts, low_n, high_timeouts, high_n)
            rise = (
                f"timeouts rose from {low_timeouts}/{low_n} to {high_timeouts}/{high_n} "
                f"verifications at {high_slots} slots (p={p_value:.2f})"
            )
            if high_timeouts >= MIN_CONTENTION_TIMEOUTS and p_value < CONTENTION_P_VALUE:
                max_docker = min(max_docker, float(high_slots))
                start = min(start, max_docker)
                notes.append(f"{rise}: contention, capped at {int(max_docker)}")
            else:
                notes.append(
                    f"{rise}, not significant: not capped; watch the timeout share of Docker "
                    "time in real passes"
                )
    return Checks(
        notes=notes,
        static_per_slot=static_per_slot,
        start_docker_slots=start,
        max_docker_slots=max_docker,
        network_ceiling_mbps=round(network_ceiling, 1),
    )


def analyze_calibration(
    samples: list[Sample],
    calibration: Calibration,
    *,
    records: list[VerificationRecord],
    host: Host,
    target: float,
    parallel_ai: int,
    static_parallel: int,
    max_repo_size_mb: int = 100,
) -> dict[str, Any]:
    """Fit per-verification CPU and memory, check the levels' metrics, and size this host."""
    start = calibration.clock_start
    result: dict[str, Any] = {
        "levels": {"low": calibration.low, "high": calibration.high},
        "window_minutes": round(calibration.window_s / 60, 1),
        "low": _level(
            records,
            samples,
            static_parallel=static_parallel,
            start=start,
            end=calibration.switched_at,
        ),
        "high": _level(
            records,
            samples,
            static_parallel=static_parallel,
            start=calibration.switched_at,
            end=calibration.finished_at,
        ),
    }
    if start is None:
        result["error"] = "no verification started, so nothing could be measured"
        return result
    # Samples after the window are the shutdown draining the pool, not steady load.
    end = calibration.finished_at if calibration.finished_at is not None else math.inf
    usable = [
        sample
        for sample in samples
        if start + CALIBRATION_WARMUP_S <= sample.t <= end and sample.active >= 1
    ]
    result["samples"] = len(usable)
    levels = sorted({sample.active for sample in usable})
    if len(usable) < MIN_FIT_SAMPLES or not levels or levels[-1] - levels[0] < MIN_FIT_SPREAD:
        result["error"] = (
            f"not enough varied load to fit ({len(usable)} samples, active "
            f"{levels[0] if levels else 0}–{levels[-1] if levels else 0}); run longer, widen "
            "--since, or check that discovery finds repositories with candidates"
        )
        return result
    xs = [float(sample.active) for sample in usable]
    cpu_intercept, cpu_slope, cpu_r2 = fit_line(xs, [sample.cpu_busy for sample in usable])
    mem_intercept, mem_slope, mem_r2 = fit_line(xs, [sample.mem_used_gib for sample in usable])
    verify_cpu = max(MIN_VERIFY_CPU, cpu_slope)
    verify_mem = max(MIN_VERIFY_MEMORY_GIB, mem_slope)
    weight = host.core_weight
    costs = Costs(
        verify_cpu=round(verify_cpu / weight, 3),
        verify_mem_gib=round(verify_mem, 3),
        verify_peak_mem_gib=max(Costs().verify_peak_mem_gib, round(verify_mem * 2, 3)),
        static_cpu=0.0,
        static_mem_gib=0.0,
        overhead_cpu=round(max(MIN_OVERHEAD_CPU, cpu_intercept - host.busy_cpus) / weight, 3),
        overhead_mem_gib=round(
            max(MIN_OVERHEAD_MEMORY_GIB, mem_intercept - host.mem_used_gib), 3
        ),
        source="calibrated",
    )
    checks = calibration_checks(
        result["low"], result["high"], high_slots=calibration.high, low_slots=calibration.low
    )
    costs = replace(
        costs,
        static_per_slot=checks.static_per_slot,
        start_docker_slots=checks.start_docker_slots,
        max_docker_slots=checks.max_docker_slots,
        network_ceiling_mbps=checks.network_ceiling_mbps,
    )
    plan = estimate(
        host,
        costs,
        target=target,
        parallel_ai=parallel_ai,
        max_repo_size_mb=max_repo_size_mb,
    )
    busy = [sample.cpu_fraction for sample in usable]
    result.update(
        {
            "fit": {
                "verify_cpu": round(cpu_slope, 3),
                "cpu_intercept": round(cpu_intercept, 2),
                "cpu_r2": round(cpu_r2, 3),
                "verify_mem_gib": round(mem_slope, 3),
                "mem_intercept_gib": round(mem_intercept, 2),
                "mem_r2": round(mem_r2, 3),
                "active_levels": levels,
            },
            "observed": {
                "cpu_mean": round(sum(busy) / len(busy), 3),
                "cpu_p95": round(sorted(busy)[int(0.95 * (len(busy) - 1))], 3),
                "mem_max": round(max(sample.mem_fraction for sample in usable), 3),
                "cpu_pressure_max": max(
                    (sample.cpu_pressure or 0.0 for sample in usable), default=0.0
                ),
                "mem_pressure_max": max(
                    (sample.mem_pressure or 0.0 for sample in usable), default=0.0
                ),
            },
            "checks": checks.notes,
            "costs": {
                name: value for name, value in asdict(costs).items() if name != "source"
            },
            "recommended": {
                "parallel_docker": plan.parallel_docker,
                "parallel_no_ai": plan.parallel_no_ai,
                "parallel_ai": plan.parallel_ai,
                "static_parallel": plan.static_parallel,
                "max_checkouts": plan.max_checkouts,
                "limited_by": plan.limited_by,
            },
        }
    )
    return result


def render_calibration(result: dict[str, Any], *, target: float, profile: Path | None) -> str:
    lines = [f"jsspector online calibration — target {target:.0%}"]
    for name in ("low", "high"):
        stats = result.get(name, {})
        level = result["levels"][name]
        if not stats.get("minutes"):
            lines.append(f"  {name:<5} {level} slots: not reached")
            continue
        rate = stats.get("verifications_per_hour")
        median_slot = stats.get("median_slot_s")
        per_issue = stats.get("slot_minutes_per_issue")
        lines.append(
            f"  {name:<5} {level} slots for {stats['minutes']:g} min: "
            f"{stats['verifications']} verifications"
            + (f" ({rate:.0f}/h)" if rate is not None else "")
            + f", median {median_slot if median_slot is not None else '—'}s, "
            f"{stats['issues']} issues"
            + (f" (1 per {per_issue:.0f} Docker-min)" if per_issue is not None else "")
        )
        if stats.get("verifications"):
            lines.append(
                f"        Docker time {_percentages(stats['docker_time'], OUTCOME_LABELS)}"
            )
        if stats.get("samples"):
            pressure_mean = stats.get("cpu_pressure_mean")
            network = stats.get("net_rx_mean")
            lines.append(
                f"        bottleneck  {_percentages(stats['bottleneck'])}  ·  cpu "
                f"{(stats.get('cpu_mean') or 0):.0%}"
                + (f" (pressure {pressure_mean:g}%)" if pressure_mean is not None else "")
                + (f"  ·  network {network:g} MB/s" if network is not None else "")
            )
    if "error" in result:
        lines.append(f"  result   {result['error']}")
        lines.append("  profile  unchanged")
        return "\n".join(lines)
    fit = result["fit"]
    observed = result["observed"]
    recommended = result["recommended"]
    for check in result.get("checks", []):
        lines.append(f"  check    {check}")
    lines += [
        f"  measured {fit['verify_cpu']:g} CPU and {fit['verify_mem_gib']:g} GiB per concurrent "
        f"verification (r² {fit['cpu_r2']:g} / {fit['mem_r2']:g}, {result['samples']} samples, "
        f"active {fit['active_levels'][0]}–{fit['active_levels'][-1]})",
        f"  observed CPU mean {observed['cpu_mean']:.0%}, p95 {observed['cpu_p95']:.0%}; memory "
        f"max {observed['mem_max']:.0%}",
        f"  plan     docker {recommended['parallel_docker']} (deterministic "
        f"{recommended['parallel_no_ai']} + Opus {recommended['parallel_ai']}), static "
        f"{recommended['static_parallel']}, checkouts {recommended['max_checkouts']} — limited "
        f"by {recommended['limited_by']}",
        f"  profile  {'saved to ' + str(profile) if profile else 'not saved'}",
    ]
    return "\n".join(lines)


def calibration_profile(
    result: dict[str, Any], *, host: Host, target: float
) -> dict[str, Any]:
    return {
        "version": PROFILE_VERSION,
        "host": host.fingerprint(),
        "calibrated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "target": target,
        "costs": result["costs"],
        "recommended": result["recommended"],
        "measurement": {
            key: result[key]
            for key in ("levels", "window_minutes", "low", "high", "samples", "fit", "observed")
            if key in result
        },
    }


# --- Monitor --------------------------------------------------------------------------------


class Monitor(threading.Thread):
    """Samples the host while a pass runs, and either governs or calibrates the Docker slots."""

    def __init__(
        self,
        *,
        host: Host,
        plan: Plan,
        target: float,
        docker_slots: AdjustableSlots,
        no_ai_gate: AdjustableSlots,
        ai_workers: int,
        governed: bool,
        calibration: Calibration | None,
        static_active: Callable[[], int],
        emit: Callable[..., None],
        log: Callable[[str], None],
        on_calibrated: Callable[[str], None],
        record_path: Path | None = None,
        reader: UsageReader | None = None,
        interval_s: float = SAMPLE_INTERVAL_S,
        network_ceiling: float = 0.0,
        performance: Performance | None = None,
        checkouts: Callable[[], tuple[int, int]] | None = None,
        backlog: Callable[[], int] | None = None,
        control_path: Path | None = None,
        ensure_checkouts: Callable[[int], None] | None = None,
    ) -> None:
        super().__init__(name="jsspector-online-capacity", daemon=True)
        self.host = host
        self.plan = plan
        self.target = target
        self.docker_slots = docker_slots
        self.no_ai_gate = no_ai_gate
        self.ai_workers = ai_workers
        self.governed = governed
        self.calibration = calibration
        self.static_active = static_active
        self.emit = emit
        self.log = log
        self.on_calibrated = on_calibrated
        self.record_path = record_path
        self.reader = reader or UsageReader(host)
        self.interval_s = interval_s
        self.performance = performance or Performance()
        self.checkouts = checkouts
        self.backlog = backlog
        self.control_path = control_path
        self.ensure_checkouts = ensure_checkouts
        self.manual = False
        self._governable = governed
        self._control_stamp: int | None = None
        self.samples: list[Sample] = []
        self.started = time.monotonic()
        self._stop_event = threading.Event()
        self._window: deque[Sample] = deque(maxlen=int(CPU_WINDOW_S * 3 / interval_s) + 1)
        self.network_ceiling = network_ceiling
        self._state = GovernorState(
            limit=docker_slots.limit,
            floor=plan.docker_floor,
            ceiling=plan.docker_ceiling,
            network_ceiling=network_ceiling,
        )
        self._last_log = -math.inf
        self._last_performance = -math.inf
        self._last_performance_log = -math.inf

    def now(self) -> float:
        return time.monotonic() - self.started

    def stop(self) -> None:
        self._stop_event.set()

    def record(self, record: VerificationRecord) -> None:
        """Remember one finished verification (times from now())."""
        self.performance.record(record)

    def summaries(self, now: float | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
        """(whole pass, last 15 minutes) improvement metrics."""
        now = self.now() if now is None else now
        records = self.performance.snapshot()
        samples = list(self.samples)
        static_parallel = self.plan.static_parallel
        overall = performance_summary(records, samples, static_parallel=static_parallel)
        recent = performance_summary(
            records,
            samples,
            static_parallel=static_parallel,
            start=now - RECENT_WINDOW_S,
        )
        return overall, recent

    def set_limit(self, limit: int) -> None:
        self.docker_slots.set_limit(limit)
        self.no_ai_gate.set_limit(max(1, limit - self.ai_workers))

    def read_control(self) -> str | None:
        """Apply the operator's latest `control.json`, once per change; the message to report.

        `{"docker_slots": 12}` fixes the slots (the governor pauses; only its memory guard may
        still lower them) and `{"docker_slots": "auto"}` hands them back to the governor.
        """
        if self.control_path is None:
            return None
        try:
            stamp = self.control_path.stat().st_mtime_ns
        except OSError:
            return None
        if stamp == self._control_stamp:
            return None
        self._control_stamp = stamp
        try:
            command = json.loads(self.control_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "control: ignored an unreadable control.json"
        value = command.get("docker_slots") if isinstance(command, dict) else None
        if self.calibration is not None:
            return "control: ignored while calibrating (the calibration sets the slots)"
        current = self.docker_slots.limit
        if value == "auto":
            if not self._governable:
                return "control: this pass has fixed worker counts, so there is no governor to resume"
            self.manual = False
            self.governed = True
            self._state = GovernorState(
                limit=current,
                floor=self.plan.docker_floor,
                ceiling=max(self.plan.docker_ceiling, current),
                network_ceiling=self.network_ceiling,
            )
            return f"control: governor resumed at {current} docker slots"
        if isinstance(value, int) and not isinstance(value, bool):
            limit = max(self.ai_workers + 1, min(MAX_DOCKER_SLOTS, value))
            self.manual = True
            self.governed = False
            self.set_limit(limit)
            self._state.limit = limit
            if self.ensure_checkouts is not None:
                self.ensure_checkouts(limit)
            return f"control: docker slots {current} → {limit} (manual; the governor is paused)"
        return "control: ignored an unknown command in control.json"

    def run(self) -> None:
        while not self._stop_event.wait(self.interval_s):
            try:
                self.tick()
            except Exception as error:  # a broken probe must never take the pass down
                self.log(f"CAPACITY_MONITOR_ERROR {error}")

    def tick(self) -> Sample:
        busy, used, cpu_pressure, mem_pressure = self.reader.read()
        active, waiting, limit = self.docker_slots.snapshot()
        gate_active, gate_waiting, gate_limit = self.no_ai_gate.snapshot()
        # Work waits at a gate, or, when a lane's pool has exactly as many threads as slots, in the
        # pool's own queue; both are demand the slots could not take. The Opus lane rarely fills
        # its share of the shared cap (it ranks first, and receives fewer repositories), so the
        # deterministic gate counts as full on its own.
        queued = waiting + gate_waiting + max(0, self.backlog() if self.backlog else 0)
        saturated = queued > 0 and (gate_active >= gate_limit or active >= limit)
        checkouts, checkout_capacity = self.checkouts() if self.checkouts else (0, 0)
        network = self.reader.network() if hasattr(self.reader, "network") else None
        sample = Sample(
            t=round(self.now(), 1),
            cpu_busy=round(busy, 2),
            cpu_fraction=round(busy / self.host.logical_cpus, 4),
            mem_used_gib=round(used, 2),
            mem_fraction=round(used / self.host.mem_total_gib, 4) if self.host.mem_total_gib else 0.0,
            cpu_pressure=cpu_pressure,
            mem_pressure=mem_pressure,
            active=active,
            waiting=queued,
            limit=limit,
            static_active=self.static_active(),
            saturated=saturated,
            checkouts=checkouts,
            checkout_capacity=checkout_capacity,
            net_rx_mbps=round(network, 2) if isinstance(network, (int, float)) else None,
        )
        self.samples.append(sample)
        self._window.append(sample)
        if self.record_path is not None:
            with self.record_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(asdict(sample), sort_keys=True) + "\n")
        message = self.read_control()
        if message:
            self.log(f"CONTROL {message}")
        if self.calibration is not None:
            new_limit, message = self.calibration.advance(sample)
            if new_limit is not None:
                self.set_limit(new_limit)
            if self.calibration.phase == "done" and message:
                self.log(f"CALIBRATION {message}")
                self.on_calibrated(message)
            elif message:
                self.log(f"CALIBRATION {message}")
        elif self.governed or self.manual:
            new_limit, reason = govern(
                self._state, list(self._window), target=self.target, now=sample.t
            )
            # A manual setting stays as set, except that the memory guard may still shed slots:
            # running out of memory kills containers mid-verification.
            if self.manual and not (
                new_limit < self._state.limit and (reason or "").startswith("memory")
            ):
                new_limit = self._state.limit
            if new_limit != self._state.limit:
                direction = "up" if new_limit > self._state.limit else "down"
                message = (
                    f"governor: docker slots {self._state.limit} → {new_limit} ({reason})"
                )
                self.log(
                    f"GOVERNOR slots={self._state.limit}->{new_limit} direction={direction} "
                    f"reason={reason!r} cpu={sample.cpu_fraction:.0%} "
                    f"memory={sample.mem_fraction:.0%} active={sample.active} "
                    f"waiting={sample.waiting}"
                )
                if new_limit > self._state.limit:
                    self._state.last_increase = sample.t
                else:
                    self._state.last_decrease = sample.t
                self._state.limit = new_limit
                self.set_limit(new_limit)
        self.emit(
            "resources",
            cpu=round(sample.cpu_fraction, 3),
            memory=round(sample.mem_fraction, 3),
            active=sample.active,
            waiting=sample.waiting,
            slots=self.docker_slots.limit,
            **({"message": message} if message else {}),
        )
        if sample.t - self._last_performance >= PERFORMANCE_EMIT_INTERVAL_S:
            self._last_performance = sample.t
            overall, recent = self.summaries(sample.t)
            lines = performance_lines(overall, recent)
            self.emit("performance", lines=lines)
            if sample.t - self._last_performance_log >= PERFORMANCE_LOG_INTERVAL_S:
                self._last_performance_log = sample.t
                for line in lines:
                    self.log(f"PERFORMANCE {line}")
        if sample.t - self._last_log >= RESOURCE_LOG_INTERVAL_S:
            self._last_log = sample.t
            self.log(
                f"RESOURCES cpu={sample.cpu_fraction:.0%} memory={sample.mem_fraction:.0%} "
                f"docker={sample.active}/{self.docker_slots.limit} waiting={sample.waiting} "
                f"static={sample.static_active}"
                + (
                    f" cpu_psi={sample.cpu_pressure:g}"
                    if sample.cpu_pressure is not None
                    else ""
                )
                + (
                    f" mem_psi={sample.mem_pressure:g}"
                    if sample.mem_pressure is not None
                    else ""
                )
                + (
                    f" net_rx={sample.net_rx_mbps:g}MB/s"
                    if sample.net_rx_mbps is not None
                    else ""
                )
            )
        return sample
