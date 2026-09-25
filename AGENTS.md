# Working in this repo (notes for humans and agents)

## Commands

- `zig build` — build the `ns` binary (`zig-out/bin/`).
- `zig build test --summary all` — run the full test suite. Must be
  green before any PR.
- `zig build release -Doptimize=ReleaseFast` — all five release
  binaries. CI also builds and tests on Linux, macOS and Windows.
  Build releases on a Mac: macOS binaries must be codesigned (see
  `installAndSign` in `build.zig`) or macOS hides the ARP table.

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
  (stderr) is fine. `scanPorts` has `ScanOptions.progress` exactly so
  tests can run quietly; the streaming output is verified manually.

## Style

- Human-readable first, compact never at clarity's expense. Doc
  comments explain *why*, not just *what*.
- `zig fmt` the files you touch. Note: `zig fmt --check` fails
  repo-wide on untouched files (CRLF line endings predate it); do
  not reformat the world to chase that.
- Match the existing branch-per-change, PR-to-`main` workflow.
