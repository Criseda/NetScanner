#!/usr/bin/env python3
"""
generate_ports.py - Packs the IANA TCP port registry, merged with the
curated overlay in port_overlay.txt, into a compact binary lookup table
(ports.bin) for NetScanner.

Two sources, kept apart on purpose:
- IANA (official): the service name and description registered for each
  TCP port. Public domain (CC0), updated as ports are assigned.
- port_overlay.txt (curated): friendly labels ("RDP" for ms-wbt-server),
  categories, and common de-facto uses of ports IANA leaves unassigned or
  assigns to something else. The overlay never invents an IANA name; the
  `iana` field of a port is always the registry's own.

Format layout (little-endian):
- Header (24 bytes, same layout as oui.bin):
    magic: [4]u8 = "NSPT"
    version: u32 = 1
    entry_count: u32
    table_offset: u32
    strings_offset: u32
    strings_len: u32
- Table: entry_count * 20 bytes, sorted by port, one record per port
    port: u16
    reserved: u16 (0)
    label: u32        curated display name
    iana: u32         IANA service name
    description: u32  curated description, else IANA's
    category: u32     curated category
  Each u32 is a byte offset into the string pool.
- Strings: strings_len bytes of length-prefixed UTF-8 (u8 length, then
  the bytes), deduplicated. Offset 0 is the empty string, meaning "none".

Re-running with the same inputs produces identical bytes. When an older
ports.bin exists, the script prints what changed, for the PR description.
"""

import csv
import io
import os
import re
import struct
import sys
import urllib.request

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"

MAGIC = b"NSPT"
VERSION = 1
HEADER_FORMAT = "<4sIIIII"
RECORD_FORMAT = "<HHIIII"

# Coarse groups for frontends (icons, filters, "open in browser").
# Keep in sync with the category list in docs/README.md.
CATEGORIES = {
    "web", "remote", "file", "mail", "dns", "database", "directory", "media",
    "printing", "messaging", "voip", "network", "vpn", "proxy", "home",
}

# The text table in `ns -p` reserves this many columns for the label.
MAX_LABEL_LEN = 20

# IANA appends this to descriptions of renamed entries; it says nothing
# about the service itself.
WELL_FORMED_NOTE = re.compile(r'\s*IANA assigned this well-formed service name as a replacement for "[^"]*"\.?')


def clean_text(text: str) -> str:
    """Collapse whitespace (some descriptions span lines) and drop noise."""
    text = WELL_FORMED_NOTE.sub("", text)
    text = text.replace("\uFFFD", "")  # U+FFFD, from bytes that were not UTF-8
    return " ".join(text.split())


def parse_iana(content: str):
    """Return {port: [(service_name, description), ...]} for TCP.

    IANA lists a port's primary name first, so callers use the first
    entry unless the overlay picks another. Ranges ("6000-6063") expand to
    every port in them.
    """
    ports = {}
    newest = ""
    for row in csv.DictReader(io.StringIO(content)):
        newest = max(newest, row.get("Modification Date") or "", row.get("Registration Date") or "")
        name = (row.get("Service Name") or "").strip()
        number = (row.get("Port Number") or "").strip()
        if row.get("Transport Protocol") != "tcp" or not name or not number:
            continue
        first, _, last = number.partition("-")
        start, end = int(first), int(last or first)
        description = clean_text(row.get("Description") or "")
        for port in range(start, end + 1):
            if 1 <= port <= 65535:
                ports.setdefault(port, []).append((name, description))
    return ports, newest


def parse_overlay(path: str, iana):
    """Return {port: (label, category, iana_name, description)}.

    Lines are `port | label | category | iana | description`, `#` starts a
    comment. Any field but port may be blank. Aborts on malformed lines,
    so a typo fails the build step instead of shipping.
    """
    overlay = {}
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue

            def fail(msg: str):
                sys.exit(f"{path}:{lineno}: {msg}")

            fields = [x.strip() for x in line.split("|")]
            if len(fields) != 5:
                fail(f"expected 5 '|'-separated fields, got {len(fields)}")
            port_str, label, category, iana_name, description = fields
            if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
                fail(f"invalid port '{port_str}'")
            port = int(port_str)
            if port in overlay:
                fail(f"duplicate port {port}")
            if len(label) > MAX_LABEL_LEN:
                fail(f"label '{label}' is longer than {MAX_LABEL_LEN} characters")
            if category and category not in CATEGORIES:
                fail(f"unknown category '{category}' (known: {', '.join(sorted(CATEGORIES))})")
            names = [n for n, _ in iana.get(port, [])]
            if iana_name and iana_name not in names:
                fail(f"'{iana_name}' is not an IANA TCP name for port {port} (IANA has: {', '.join(names) or 'none'})")
            if not label and not names:
                fail(f"port {port} is not IANA-assigned, so it needs a label")
            overlay[port] = (label, category, iana_name, description)
    return overlay


def merge(iana, overlay):
    """One (label, iana_name, description, category) tuple per port."""
    merged = {}
    for port in sorted(set(iana) | set(overlay)):
        label, category, pick, curated_description = overlay.get(port, ("", "", "", ""))
        entries = iana.get(port, [])
        iana_name, iana_description = next(
            (e for e in entries if e[0] == pick), entries[0] if entries else ("", "")
        )
        merged[port] = (label, iana_name, curated_description or iana_description, category)
    return merged


def encode(text: str) -> bytes:
    """UTF-8, cut to the 255-byte limit of a length prefix without splitting a character."""
    data = text.encode("utf-8")
    if len(data) > 255:
        data = data[:255].decode("utf-8", errors="ignore").encode("utf-8")
    return data


def pack(merged) -> bytes:
    pool = bytearray(b"\x00")  # offset 0: the empty string
    offsets = {b"": 0}

    def intern(text: str) -> int:
        data = encode(text)
        if data not in offsets:
            offsets[data] = len(pool)
            pool.append(len(data))
            pool.extend(data)
        return offsets[data]

    table = bytearray()
    for port, fields in merged.items():
        table.extend(struct.pack(RECORD_FORMAT, port, 0, *(intern(f) for f in fields)))

    header_size = struct.calcsize(HEADER_FORMAT)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        len(merged),
        header_size,
        header_size + len(table),
        len(pool),
    )
    return bytes(header + table + pool)


def unpack(data: bytes):
    """Decode a ports.bin back into {port: fields}, or None if it is not one."""
    header_size = struct.calcsize(HEADER_FORMAT)
    if len(data) < header_size:
        return None
    magic, version, count, table_offset, strings_offset, strings_len = struct.unpack_from(HEADER_FORMAT, data)
    if magic != MAGIC or version != VERSION:
        return None
    pool = data[strings_offset:strings_offset + strings_len]

    def string(offset: int) -> str:
        return pool[offset + 1:offset + 1 + pool[offset]].decode("utf-8")

    record_size = struct.calcsize(RECORD_FORMAT)
    result = {}
    for i in range(count):
        port, _, *offsets = struct.unpack_from(RECORD_FORMAT, data, table_offset + i * record_size)
        result[port] = tuple(string(o) for o in offsets)
    return result


def describe(port, fields) -> str:
    label, iana_name, _, category = fields
    return f"{port} {label or iana_name}" + (f" [{category}]" if category else "")


def report_changes(old, new):
    """Print added, removed and changed ports, capped so a big refresh stays readable."""
    added = [p for p in new if p not in old]
    removed = [p for p in old if p not in new]
    changed = [p for p in new if p in old and new[p] != old[p]]
    print(f"Changes: {len(added)} added, {len(removed)} removed, {len(changed)} changed")
    limit = 25
    for title, ports, source in (("added", added, new), ("removed", removed, old)):
        for port in ports[:limit]:
            print(f"  {title}: {describe(port, source[port])}")
        if len(ports) > limit:
            print(f"  ... and {len(ports) - limit} more {title}")
    for port in changed[:limit]:
        print(f"  changed: {describe(port, old[port])} -> {describe(port, new[port])}")
    if len(changed) > limit:
        print(f"  ... and {len(changed) - limit} more changed")


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    default_out = os.path.join(repo_root, "src", "core", "data", "ports.bin")
    overlay_path = os.path.join(script_dir, "port_overlay.txt")

    in_path = sys.argv[1] if len(sys.argv) > 1 else None
    out_path = sys.argv[2] if len(sys.argv) > 2 else default_out

    if in_path and os.path.exists(in_path):
        print(f"Reading IANA registry from local file: {in_path}")
        with open(in_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            content = f.read()
    else:
        print(f"Downloading IANA port registry from {IANA_CSV_URL}...")
        req = urllib.request.Request(IANA_CSV_URL, headers={"User-Agent": "NetScanner-Ports-Generator/1.0"})
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read().decode("utf-8", errors="replace")
        except Exception as err:
            print(f"error: failed to download the IANA registry: {err}", file=sys.stderr)
            print("Provide a path to a local copy of the registry CSV to run offline:", file=sys.stderr)
            print(f"    python {os.path.basename(__file__)} <path/to/service-names-port-numbers.csv> [out.bin]", file=sys.stderr)
            sys.exit(1)

    iana, newest = parse_iana(content)
    overlay = parse_overlay(overlay_path, iana)
    merged = merge(iana, overlay)
    data = pack(merged)

    old = None
    if os.path.exists(out_path):
        with open(out_path, "rb") as f:
            old = unpack(f.read())

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)

    curated_only = sum(1 for p in overlay if p not in iana)
    print(f"Packed {len(merged)} TCP ports into {out_path} ({len(data) / 1024:.1f} KB)")
    print(f"IANA: {len(iana)} ports, newest entry {newest or 'unknown'}")
    print(f"Overlay: {len(overlay)} ports ({curated_only} not assigned by IANA)")
    if old is not None:
        report_changes(old, merged)


if __name__ == "__main__":
    main()
