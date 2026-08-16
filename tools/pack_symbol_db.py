#!/usr/bin/env python3
"""Pack maintained aliases and an optional local unique map into the runtime symbol DB."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Optional

MAGIC = b"C6SB"
VERSION = 1


def parse_int(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s)


def msvc_friendly_name(mangled: str) -> Optional[str]:
    """Best-effort MSVC scope decode for non-template symbols.

    ?Func@Class@Ns@@...  -> Ns::Class::Func
    ??0Class@Ns@@...     -> Ns::Class::Class
    """
    if not mangled.startswith("?") or "@@" not in mangled:
        return None
    # Templates / special encodings are too ambiguous for a stable friendly key.
    if "?$" in mangled or "??_" in mangled:
        return None

    head, _rest = mangled.split("@@", 1)
    parts = head.split("@")
    if not parts:
        return None

    raw = parts[0]
    scopes = parts[1:]
    if any(s.startswith("?") for s in scopes):
        return None

    name: Optional[str] = None
    if raw.startswith("??0"):
        name = raw[3:]  # ctor
    elif raw.startswith("??1"):
        name = "~" + raw[3:]  # dtor — rarely looked up by plugins
    elif raw.startswith("?"):
        name = raw[1:]
    else:
        return None

    if not name or name.startswith("?") or "$" in name:
        return None

    scopes_rev = list(reversed(scopes))
    if not scopes_rev:
        return name
    return "::".join(scopes_rev + [name])


def ida_sub_name(rva: int, image_base: int) -> str:
    return f"sub_{image_base + rva:X}"


def build_entries(
    unique_path: Path,
    aliases_path: Path,
) -> tuple[dict[str, int], int]:
    """Return name->rva map and expected SizeOfImage."""
    aliases_doc = json.loads(aliases_path.read_text(encoding="utf-8"))
    expected = parse_int(aliases_doc.get("expected_size_of_image", "0xC61000"))
    image_base = parse_int(aliases_doc.get("image_base", "0x180000000"))

    # mangled -> rva from optional generated unique table. A source checkout
    # can still build a smaller, alias-only DB without reverse-engineering
    # artifacts under tools/out/.
    mangled_rva: dict[str, int] = {}
    if unique_path.is_file():
        with unique_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                m = o.get("mangled")
                r = o.get("new_rva")
                if not isinstance(m, str) or not isinstance(r, int):
                    continue
                mangled_rva[m] = r
    else:
        print(f"Note: {unique_path} not found; packing explicit aliases only")

    # Collect candidates; track collisions for friendly / sub names.
    name_to_rva: dict[str, int] = {}
    collision: set[str] = set()

    def consider(name: str, rva: int) -> None:
        if not name:
            return
        prev = name_to_rva.get(name)
        if prev is None:
            name_to_rva[name] = rva
        elif prev != rva:
            collision.add(name)

    for mangled, rva in mangled_rva.items():
        consider(mangled, rva)
        friendly = msvc_friendly_name(mangled)
        if friendly:
            consider(friendly, rva)
        # Optional IDA-style; only keep if unique later
        consider(ida_sub_name(rva, image_base), rva)

    # Drop colliding auto names (keep mangled — mangled keys never collide with each other)
    for name in collision:
        if name.startswith("?") or name.startswith("??"):
            continue
        name_to_rva.pop(name, None)

    # Re-add all mangled (authoritative)
    for mangled, rva in mangled_rva.items():
        name_to_rva[mangled] = rva

    # Explicit aliases always win
    for name, raw in (aliases_doc.get("aliases") or {}).items():
        if name.startswith("_"):
            continue
        name_to_rva[name] = parse_int(raw)

    return name_to_rva, expected


def pack(entries: dict[str, int], expected_size: int, out_path: Path) -> None:
    # Stable sort for binary search
    items = sorted(entries.items(), key=lambda kv: kv[0].encode("utf-8"))

    heap = bytearray()
    packed_entries = []
    for name, rva in items:
        off = len(heap)
        heap.extend(name.encode("utf-8"))
        heap.append(0)
        packed_entries.append((off, rva & 0xFFFFFFFF))

    header = struct.pack(
        "<4sIIIIII",
        MAGIC,
        VERSION,
        expected_size & 0xFFFFFFFF,
        len(packed_entries),
        28,  # heap_offset = sizeof header
        len(heap),
        28 + len(heap),  # entries_offset
    )
    assert len(header) == 28

    out = bytearray()
    out.extend(header)
    out.extend(heap)
    for off, rva in packed_entries:
        out.extend(struct.pack("<II", off, rva))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--unique",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "map_new_rva_unique.jsonl",
    )
    ap.add_argument(
        "--aliases",
        type=Path,
        default=Path(__file__).resolve().parent / "symbol_aliases.json",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "out" / "Civ6DllLoader.symbols.bin",
    )
    ap.add_argument("--check", action="store_true", help="Print sample lookups after pack")
    args = ap.parse_args()

    entries, expected = build_entries(args.unique, args.aliases)
    pack(entries, expected, args.out)

    size = args.out.stat().st_size
    print(
        f"Wrote {args.out} entries={len(entries)} bytes={size} "
        f"expected_SizeOfImage=0x{expected:X}"
    )

    if args.check:
        aliases = json.loads(args.aliases.read_text(encoding="utf-8")).get("aliases", {})
        # verify via re-read
        data = args.out.read_bytes()
        magic, ver, exp, count, heap_off, heap_size, ent_off = struct.unpack_from(
            "<4sIIIIII", data, 0
        )
        assert magic == MAGIC and ver == VERSION
        heap = data[heap_off : heap_off + heap_size]

        def lookup(name: str) -> Optional[int]:
            # linear for check
            for i in range(count):
                off, rva = struct.unpack_from("<II", data, ent_off + i * 8)
                end = heap.index(0, off)
                n = heap[off:end].decode("utf-8")
                if n == name:
                    return rva
            return None

        for name, raw in aliases.items():
            if name.startswith("_"):
                continue
            want = parse_int(raw)
            got = lookup(name)
            ok = "OK" if got == want else "FAIL"
            print(f"  [{ok}] {name} want=0x{want:X} got={hex(got) if got is not None else None}")

        # demangle sample
        sample = "?AttemptNewQuests@Manager@Quests@GameCore@@AEAAXW4PlayerTypes@3@0@Z"
        print("  friendly", msvc_friendly_name(sample), "rva", hex(lookup(sample) or 0))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
