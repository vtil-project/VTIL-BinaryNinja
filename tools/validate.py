#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

VTIL_IMPLEMENTED_LLIL = {
    "mov", "movsx", "str", "ldd", "ifs", "neg", "add", "sub", "mul", "imul",
    "mulhi", "imulhi", "div", "idiv", "rem", "irem",
    "popcnt", "bsf", "bsr",
    "not", "shr", "shl", "xor", "or", "and", "ror", "rol",
    "tg", "tge", "te", "tne", "tle", "tl", "tug", "tuge", "tule", "tul",
    "js", "jmp", "vexit", "vxcall",
    "nop", "sfence", "lfence", "vemit", "vpinr", "vpinw", "vpinrm", "vpinwm",
}

VTIL_PENDING_LLIL = set()


def parse_vtil_core_instruction_names(instruction_set_hpp: Path) -> list[str]:
    text = instruction_set_hpp.read_text(encoding="utf-8", errors="ignore")
    names = re.findall(r'inline\s+const\s+instruction_desc\s+\w+\s*=\s*\{\s*"([a-z0-9_]+)"', text)
    return sorted(set(names))


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python tools/validate.py /path/to/VTIL-Core")
        return 1

    core_root = Path(sys.argv[1]).expanduser().resolve()
    instruction_set_hpp = core_root / "VTIL-Architecture" / "arch" / "instruction_set.hpp"
    if not instruction_set_hpp.is_file():
        print(f"error: could not find {instruction_set_hpp}")
        return 2

    core_instructions = set(parse_vtil_core_instruction_names(instruction_set_hpp))
    plugin_known = VTIL_IMPLEMENTED_LLIL | VTIL_PENDING_LLIL

    missing_from_plugin = sorted(core_instructions - plugin_known)
    extra_in_plugin = sorted(plugin_known - core_instructions)

    print(f"VTIL-Core instructions: {len(core_instructions)}")
    print(f"Implemented LLIL:       {len(VTIL_IMPLEMENTED_LLIL)}")
    print(f"Pending LLIL:          {len(VTIL_PENDING_LLIL)}")
    print(f"Total plugin known:    {len(plugin_known)}")

    if missing_from_plugin:
        print("\nMissing from plugin coverage table:")
        for ins in missing_from_plugin:
            print(f"  - {ins}")

    if extra_in_plugin:
        print("\nPresent in plugin table but not in VTIL-Core list:")
        for ins in extra_in_plugin:
            print(f"  - {ins}")

    if not missing_from_plugin and not extra_in_plugin:
        print("\nCoverage table is in sync with VTIL-Core instruction list.")
        return 0

    return 3


if __name__ == "__main__":
    raise SystemExit(main())
