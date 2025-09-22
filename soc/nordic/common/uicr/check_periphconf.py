"""
Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from textwrap import indent
from typing import Any

from intelhex import IntelHex

try:
    ZEPHYR_BASE = Path(os.environ["ZEPHYR_BASE"]).resolve()
except KeyError:
    sys.exit("Set the environment variable 'ZEPHYR_BASE' to point to the zephyr root directory")

# Add packages that are located in zephyr itself to the python path so we can import them below
sys.path.insert(0, str(ZEPHYR_BASE / "scripts/dts/python-devicetree/src"))
sys.path.insert(0, str(ZEPHYR_BASE / "soc/nordic/common/uicr"))

from periphconf.validate import (
    parse_periphconf,
    validate_periphconf,
    render_periphconf_table,
    render_validation_status,
    ValidationStatus,
)


def main() -> None:
    # TODO: put some more thought into the CLI here.
    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=("TODO"),
    )
    parser.add_argument(
        "--in-periphconf-hex",
        type=argparse.FileType("r", encoding="utf-8"),
        required=True,
    )
    parser.add_argument(
        "--in-periphconf-registers-json",
        type=argparse.FileType("r", encoding="utf-8"),
        required=True,
    )
    parser.add_argument("--only-errors", action="store_true", default=False)
    parser.add_argument("--print", action="store_true", default=False, help="If set TODO")
    parser.add_argument(
        "--style",
        choices=["regs", "raw"],
        default="regs",
    )
    args = parser.parse_args()

    ihex = IntelHex()
    ihex.loadhex(args.in_periphconf_hex)

    if len(ihex.segments()) > 1:
        sys.exit("Expected a PERIPHCONF HEX file containing a single contiguous data segment")

    register_info = json.load(args.in_periphconf_registers_json)

    raw = ihex.tobinstr()
    entries = parse_periphconf(register_info, raw)
    validate_status, validated_entries = validate_periphconf(entries)
    if args.only_errors:
        if not validate_status.is_error():
            # We are running in --only-errors mode and have no errors.
            # Therefore we are done.
            return
        entries_to_print = [e for e in validated_entries if e.status.is_error()]
    else:
        entries_to_print = validated_entries

    table_str = render_periphconf_table(entries_to_print, style=args.style)
    status_str = render_validation_status(validate_status)

    if table_str:
        print()
        if validate_status.is_error():
            print("Found errors in the PERIPHCONF table:", end="\n\n")
        print(indent(table_str, "  "))

    if status_str:
        print()
        print("Error description:", end="\n\n")
        print(indent(status_str, "  "))

    if validate_status.is_fatal_error():
        sys.exit(
            f"PERIPHCONF at {args.in_periphconf_hex.name} has errors "
            "that will prevent the device from booting correctly.\n"
        )


if __name__ == "__main__":
    main()
