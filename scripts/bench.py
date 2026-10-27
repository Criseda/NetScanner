#!/usr/bin/env python3
"""Compare two ns builds on the Docker lab's benchmark targets.

Does what AGENTS.md asks of a performance change: old and new
ReleaseFast binaries run interleaved in one random order (not one
side's batch after the other's, so network drift does not land on one
side), 10+ runs each, with medians and p90. Per run it also records CPU
time and whether the scan found every port the target listens on, and
per profile it says whether a difference stands out from the noise: a
Mann-Whitney rank test plus a bootstrap confidence interval on the
ratio of the medians. A 3-run comparison has shown a 15% difference
that vanished at 30 runs.

Run it from the lab's scanner container, with the targets up:

    docker compose -f docker/compose.yaml --profile bench up -d --build
    docker compose -f docker/compose.yaml exec scanner \\
        python3 scripts/bench.py --old /tmp/old/bin/ns --new zig-out/bin/ns

See docker/README.md for building the old side. Linux only: Windows
and macOS still need real hosts. Standard library only.
"""

import argparse
import csv
import json
import math
import os
import random
import subprocess
import sys
import time
from pathlib import Path

# Benchmark targets, as docker/compose.yaml places them (profile "bench").
TARGETS = {
    "clean": "192.168.90.200",
    "lossy": "192.168.90.201",
    "filtering": "192.168.90.202",
    "first-syn-lost": "192.168.90.203",
    "far": "192.168.90.204",
}

LAB_ENV = Path(__file__).resolve().parent.parent / "docker" / "lab.env"


def open_ports_from_lab_env(path):
    """The ground truth: OPEN_PORTS from docker/lab.env."""
    for line in path.read_text().splitlines():
        key, _, value = line.strip().partition("=")
        if key == "OPEN_PORTS":
            return {int(p) for p in value.split(",") if p.strip()}
    sys.exit(f"bench: no OPEN_PORTS in {path}")


def ports_in_range(ports, spec):
    """The ports of `ports` that a scan of `spec` ("a-b" or "a") covers."""
    low, _, high = spec.partition("-")
    low, high = int(low), int(high or low)
    return {p for p in ports if low <= p <= high}


def run_once(binary, ip, port_spec):
    """One `ns -p` scan: wall seconds, CPU seconds, open ports, error."""
    started = time.perf_counter()
    proc = subprocess.Popen(
        [binary, "-p", ip, port_spec, "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    output = proc.stdout.read()
    proc.stdout.close()
    # wait4 rather than wait: it also hands back the child's rusage.
    _, status, usage = os.wait4(proc.pid, 0)
    wall = time.perf_counter() - started
    proc.returncode = os.waitstatus_to_exitcode(status)

    found, error = set(), None
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "port":
            found.add(event["port"])
        elif event.get("type") == "error":
            error = event.get("message", "error")
    if proc.returncode != 0 and error is None:
        error = f"exit code {proc.returncode}"
    return wall, usage.ru_utime + usage.ru_stime, found, error


def quantile(values, q):
    """Linear-interpolated quantile, as numpy's default."""
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low = math.floor(pos)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


def median(values):
    return quantile(values, 0.5)


def mann_whitney_p(a, b):
    """Two-sided p-value of the Mann-Whitney U test, by the normal
    approximation with tie correction (sound from about 8 runs a side).
    """
    n1, n2 = len(a), len(b)
    pooled = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    n = n1 + n2
    ranks = [0.0] * n
    tie_term = 0.0
    i = 0
    while i < n:
        j = i
        while j + 1 < n and pooled[j + 1][0] == pooled[i][0]:
            j += 1
        for k in range(i, j + 1):
            ranks[k] = (i + j) / 2 + 1
        tied = j - i + 1
        tie_term += tied**3 - tied
        i = j + 1
    rank_sum_a = sum(r for r, (_, side) in zip(ranks, pooled) if side == 0)
    u = rank_sum_a - n1 * (n1 + 1) / 2
    mean = n1 * n2 / 2
    variance = n1 * n2 / 12 * ((n + 1) - tie_term / (n * (n - 1)))
    if variance <= 0:
        return 1.0
    z = (abs(u - mean) - 0.5) / math.sqrt(variance)
    return math.erfc(max(z, 0) / math.sqrt(2))


def bootstrap_ratio_ci(old, new, rng, rounds=10000, level=0.95):
    """Percentile bootstrap interval for median(new) / median(old)."""
    ratios = []
    for _ in range(rounds):
        old_median = median(rng.choices(old, k=len(old)))
        new_median = median(rng.choices(new, k=len(new)))
        if old_median > 0:
            ratios.append(new_median / old_median)
    tail = (1 - level) / 2
    return quantile(ratios, tail), quantile(ratios, 1 - tail)


def verdict(p_value, ci, alpha):
    """Faster or slower only when both tests agree it is not noise."""
    low, high = ci
    if p_value < alpha and high < 1:
        return "new faster"
    if p_value < alpha and low > 1:
        return "new slower"
    return "within noise"


def summarize(profile, runs, expected, alpha, rng):
    lines = [f"== {profile} ({TARGETS[profile]}), {len(expected)} open ports expected"]
    walls = {}
    for side in ("old", "new"):
        mine = [r for r in runs if r["side"] == side]
        wall = [r["wall"] for r in mine]
        cpu = [r["cpu"] for r in mine]
        walls[side] = wall
        complete = sum(1 for r in mine if not r["missing"] and not r["error"])
        missed = {}
        for r in mine:
            for port in r["missing"]:
                missed[port] = missed.get(port, 0) + 1
        errors = sum(1 for r in mine if r["error"])
        lines.append(
            f"  {side}: wall {median(wall):.3f}s (p90 {quantile(wall, 0.9):.3f}s), "
            f"cpu {median(cpu):.3f}s (p90 {quantile(cpu, 0.9):.3f}s), "
            f"all ports found in {complete}/{len(mine)} runs"
        )
        if missed:
            listing = ", ".join(f"{p} x{n}" for p, n in sorted(missed.items()))
            lines.append(f"       missed: {listing}")
        if errors:
            lines.append(f"       {errors} runs failed")
    p_value = mann_whitney_p(walls["old"], walls["new"])
    ci = bootstrap_ratio_ci(walls["old"], walls["new"], rng)
    ratio = median(walls["new"]) / median(walls["old"])
    lines.append(
        f"  new/old median wall {ratio:.3f}, 95% CI [{ci[0]:.3f}, {ci[1]:.3f}], "
        f"Mann-Whitney p={p_value:.3g}: {verdict(p_value, ci, alpha)}"
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--old", required=True, help="old ns binary (ReleaseFast)")
    parser.add_argument("--new", required=True, help="new ns binary (ReleaseFast)")
    parser.add_argument(
        "--profiles",
        default="clean,lossy,first-syn-lost",
        help="comma-separated, from: " + ", ".join(TARGETS) + " (default: %(default)s)",
    )
    parser.add_argument("--runs", type=int, default=10, help="runs per side and profile (default: %(default)s)")
    parser.add_argument(
        "--ports",
        default="1-65535",
        help="port range each scan covers (default: %(default)s; filtering and far are slow over all of it)",
    )
    parser.add_argument(
        "--pause",
        type=float,
        default=2.0,
        help="seconds between runs; keep it above FIRST_SYN_WINDOW (default: %(default)s)",
    )
    parser.add_argument("--alpha", type=float, default=0.05, help="significance level (default: %(default)s)")
    parser.add_argument("--seed", type=int, help="seed for the run order and the bootstrap")
    parser.add_argument("--csv", help="also write every run to this CSV file")
    args = parser.parse_args()

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    unknown = [p for p in profiles if p not in TARGETS]
    if unknown:
        parser.error(f"unknown profiles: {', '.join(unknown)}")
    if args.runs < 2:
        parser.error("--runs must be at least 2")
    for binary in (args.old, args.new):
        if not os.access(binary, os.X_OK):
            parser.error(f"not an executable: {binary}")

    seed = args.seed if args.seed is not None else random.randrange(2**32)
    rng = random.Random(seed)
    expected = ports_in_range(open_ports_from_lab_env(LAB_ENV), args.ports)
    binaries = {"old": args.old, "new": args.new}
    print(f"bench: seed {seed}, {args.runs} runs a side, ports {args.ports}", file=sys.stderr)

    all_runs, reports = [], []
    for profile in profiles:
        ip = TARGETS[profile]
        order = ["old", "new"] * args.runs
        rng.shuffle(order)
        runs = []
        for i, side in enumerate(order, 1):
            if i > 1:
                time.sleep(args.pause)
            wall, cpu, found, error = run_once(binaries[side], ip, args.ports)
            missing = sorted(expected - found)
            runs.append(
                {"profile": profile, "side": side, "wall": wall, "cpu": cpu, "missing": missing, "error": error}
            )
            status = error or (f"missed {missing}" if missing else "all found")
            print(f"[{profile} {i}/{len(order)}] {side} {wall:.3f}s cpu {cpu:.3f}s, {status}", file=sys.stderr)
        all_runs += runs
        reports.append(summarize(profile, runs, expected, args.alpha, rng))

    print()
    print("\n\n".join(reports))

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["profile", "side", "wall_s", "cpu_s", "missing", "error"])
            for r in all_runs:
                writer.writerow(
                    [r["profile"], r["side"], f"{r['wall']:.6f}", f"{r['cpu']:.6f}",
                     " ".join(map(str, r["missing"])), r["error"] or ""]
                )


if __name__ == "__main__":
    main()
