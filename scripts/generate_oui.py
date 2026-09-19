#!/usr/bin/env python3
"""
generate_oui.py - Pre-packs Wireshark / IEEE OUI databases into a compact,
memory-mappable binary lookup table (oui.bin) for NetScanner.

Format layout (little-endian):
- Header (24 bytes):
    magic: [4]u8 = "NSOU"
    version: u32 = 1
    entry_count: u32
    table_offset: u32
    strings_offset: u32
    strings_len: u32
- Table: entry_count * 8 bytes
    prefix: [3]u8
    name_len: u8
    name_offset: u32 (byte offset into string pool)
- Strings: strings_len bytes
    Deduplicated UTF-8 vendor string bytes
"""

import sys
import os
import re
import struct
import urllib.request

WIRESHARK_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"

def parse_and_pack(in_content: str, out_path: str):
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+(\S+)(?:\s+(.*))?$")
    temp_entries = []

    for line in in_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = pattern.match(line)
        if not m:
            continue
        mac_str, short_name, long_name = m.groups()
        vendor = (long_name.strip() if long_name else short_name).strip()
        octets = [int(x, 16) for x in re.split(r"[:-]", mac_str)]
        prefix = bytes(octets)
        temp_entries.append((prefix, vendor))

    # Sort strictly by prefix
    temp_entries.sort(key=lambda x: x[0])

    # Deduplicate prefixes (keep earlier entry)
    unique_entries = []
    seen_prefixes = set()
    for prefix, vendor in temp_entries:
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)
        unique_entries.append((prefix, vendor))

    string_pool = bytearray()
    vendor_offsets = {}
    packed_entries = bytearray()

    for prefix, vendor in unique_entries:
        v_bytes = vendor.encode("utf-8")
        if len(v_bytes) > 255:
            v_bytes = v_bytes[:255].decode("utf-8", errors="ignore").encode("utf-8")
        if v_bytes not in vendor_offsets:
            vendor_offsets[v_bytes] = len(string_pool)
            string_pool.extend(v_bytes)
        offset = vendor_offsets[v_bytes]
        entry_bytes = struct.pack("<3sBI", prefix, len(v_bytes), offset)
        packed_entries.extend(entry_bytes)

    header_format = "<4sIIIII"
    magic = b"NSOU"
    version = 1
    entry_count = len(unique_entries)
    header_size = struct.calcsize(header_format)
    table_offset = header_size
    strings_offset = table_offset + len(packed_entries)
    strings_len = len(string_pool)

    header = struct.pack(
        header_format,
        magic,
        version,
        entry_count,
        table_offset,
        strings_offset,
        strings_len,
    )

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(header)
        f.write(packed_entries)
        f.write(string_pool)

    total_size = len(header) + len(packed_entries) + len(string_pool)
    print(f"Successfully packed {entry_count} OUIs into {out_path}")
    print(f"Header: {len(header)} B, Table: {len(packed_entries)} B, Strings: {len(string_pool)} B")
    print(f"Total size: {total_size} B ({total_size / 1024:.1f} KB)")


def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_out = os.path.join(repo_root, "src", "core", "data", "oui.bin")

    in_path = sys.argv[1] if len(sys.argv) > 1 else None
    out_path = sys.argv[2] if len(sys.argv) > 2 else default_out

    if in_path and os.path.exists(in_path):
        print(f"Reading OUI database from local file: {in_path}")
        with open(in_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    else:
        print(f"Downloading latest Wireshark manuf from {WIRESHARK_MANUF_URL}...")
        req = urllib.request.Request(
            WIRESHARK_MANUF_URL,
            headers={"User-Agent": "NetScanner-OUI-Generator/1.0"}
        )
        try:
            with urllib.request.urlopen(req) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
        except Exception as err:
            print(f"error: failed to download Wireshark manuf database: {err}", file=sys.stderr)
            print("Provide a path to a local Wireshark manuf or IEEE text file to run offline:", file=sys.stderr)
            print(f"    python {os.path.basename(__file__)} <path/to/manuf> [out.bin]", file=sys.stderr)
            sys.exit(1)

    parse_and_pack(content, out_path)


if __name__ == "__main__":
    main()
