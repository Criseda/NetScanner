# Working in this repo (notes for humans and agents)

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

## Changelog per change

This repo keeps a changelog **per change**: every user-facing change
(new flag, changed output, fixed behavior, performance shift) gets an
entry under `## Unreleased` in `CHANGELOG.md` in the same commit or
PR. Create the section if it is missing. No-root operation is the
selling point: any change requiring privileges does not belong here.

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

## Performance changes

- **Measure, then decide.** A speedup ships only if it measures
  faster: `-Doptimize=ReleaseFast`, old and new interleaved in random
  order (hyperfine runs one command's batch after the other's, so
  network drift lands on one side), at least 10 runs each, median and
  p90, and % change = (old - new) / old on the medians. Hosts and
  open ports found must be the same or more.
- **Don't tune to the test network.** One router, LAN or ISP is one
  data point, not the target: fitting to it is overfitting, as with
  an ML model. Prefer signals the scan observes itself (answers, round
  trips, kernel state) over constants fitted to one device. Each PR
  says which networks and OSes it was measured on, and which not.
- **Think through the scans you can't measure.** Tiny ranges (`/30`),
  far hosts, hosts that drop or rate-limit probes, every OS. A change
  that helps one case but adds a wait to another does not ship.
- **Keep it small.** A gain has to be worth its code. When an idea
  needs a lot of machinery for a little time, leave it out and say
  why in its issue.
- **Releases** are benchmarked against the previous release on Linux,
  macOS and Windows, and the CHANGELOG records the differences.

## Style

- Human-readable first, compact never at clarity's expense. Doc
  comments explain *why*, not just *what*.
- `zig fmt` the files you touch. Note: `zig fmt --check` fails
  repo-wide on untouched files (CRLF line endings predate it); do
  not reformat the world to chase that.
- Match the existing branch-per-change, PR-to-`main` workflow.
