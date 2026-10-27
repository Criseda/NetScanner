# Working in this repo (notes for humans and agents)

No-root operation is the selling point: any change requiring
privileges does not belong here.

## Commands

- `zig build` — build the `ns` binary (`zig-out/bin/`).
- `zig build test --summary all` — run the full test suite. Must be
  green before any PR.
- `zig build release -Doptimize=ReleaseFast` — all five release
  binaries. CI also builds and tests on Linux, macOS and Windows.
  Build releases on a Mac: macOS binaries must be codesigned (see
  `installExe` in `build.zig`) or macOS hides the ARP table.

## Releasing

Bump `.version` in `build.zig.zon` (`ns --version` reads it) and the
version badges in `README.md` and `docs/README.md`, and turn
`## Unreleased` in `CHANGELOG.md` into the version's section.
Benchmark against the previous release on Linux, macOS and Windows,
and record the differences in the CHANGELOG.

## Changelog per change

This repo keeps a changelog **per change**: every user-facing change
(new flag, changed output, fixed behavior, performance shift) gets an
entry under `## Unreleased` in `CHANGELOG.md` in the same commit or
PR. Create the section if it is missing.

## Tests

- Tests live in `tests/` (`main_test.zig` pulls the rest in).
- Network tests bind loopback listeners they own; they hunt a free
  port and `SkipZigTest` when none is nearby instead of failing.
- **Never write to stdout from a test.** Test binaries running under
  `zig build test` speak the build protocol over stdout
  (`compiler/test_runner.zig`, `--listen=-`); stray writes corrupt
  the stream and hang the runner with no output. `std.debug.print`
  (stderr) is fine. Scans take `stream_results = false` exactly so
  tests can run quietly; the streaming output is verified manually.
- Cloud agents and other sandboxes may fail the suite because of
  their unusual network setup, not because of `ns` (one put its own
  interface on TEST-NET-1, which tests treat as unassigned). Do not
  skip or loosen a test to make such a sandbox pass; say in the PR
  which tests failed and why, and let CI or an ordinary machine
  decide. See "Failures in sandboxes and cloud agents" in
  `docs/README.md`.

## Performance changes

- A speedup ships only if it measures faster and finds the same or
  more hosts and open ports. Compare ReleaseFast builds, old and new
  interleaved in random order (not hyperfine: it runs one side's batch
  after the other's, so network drift lands on one side), 10+ runs
  each, medians and p90. On Linux, `scripts/bench.py` does this
  against the Docker lab's lossy, filtering and far targets (see
  `docker/README.md`).
- Your network is one data point. Prefer signals the scan observes
  (answers, round trips, kernel state) over constants fitted to one
  router. Say in the PR which networks and OSes were measured and
  which weren't, and reason through the rest: tiny ranges, far hosts,
  hosts that drop or rate-limit probes. A change that helps one case
  and adds a wait to another does not ship.
- A gain has to be worth its code.

## Style

- Human-readable first, compact never at clarity's expense. Doc
  comments explain *why*, not just *what*.
- `zig fmt` the files you touch. Note: `zig fmt --check` fails
  repo-wide on untouched files (CRLF line endings predate it); do
  not reformat the world to chase that.
- Match the existing branch-per-change, PR-to-`main` workflow.
