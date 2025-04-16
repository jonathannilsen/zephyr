"""
Copyright (c) 2024 Nordic Semiconductor ASA
SPDX-License-Identifier: Apache-2.0
"""

import argparse
import re
import sys
from textwrap import dedent

from elftools.elf.elffile import ELFFile, Section
from intelhex import IntelHex

# TODO: debug logging


class ScriptError(RuntimeError):
    ...


def main() -> None:
    parser = argparse.ArgumentParser(description="TODO", allow_abbrev=False)
    parser.add_argument("--input-elf", dest="input_elfs", required=True,
                         action="append", type=argparse.FileType("rb"))
    parser.add_argument("--conf-section", required=True)
    parser.add_argument("--output-macro-prefix", default="")
    parser.add_argument("--output-header", required=True, type=argparse.FileType("w", encoding="utf-8"))
    parser.add_argument("--output-merged-hex", default=None, type=argparse.FileType("w", encoding="utf-8"))
    parser.add_argument("--output-merged-hex-address", default=None, type=lambda s: int(s, 0))
    args = parser.parse_args()

    try:
        if args.output_merged_hex is None:
            if len(args.input_elfs) > 1:
                raise ScriptError("--output-merged-hex is required with multiple input ELFs")
        else:
            if args.output_merged_hex_address is None:
                raise ScriptError("--output-merged-hex-address is required with --output-merged-hex")

        conf_parts = []

        for in_file in args.input_elfs:
            elf = ELFFile(in_file)
            conf_section = elf.get_section_by_name(args.conf_section)
            if conf_section is None:
                raise ScriptError(f"Failed to find section {args.conf_section} in {in_file.name}")
            if not isinstance(conf_section, Section):
                raise ScriptError(f"Section {args.conf_section} in {in_file.name} has unexpected section type {type(conf_section)}")

            conf_part_address = conf_section["sh_addr"]
            conf_part_data = conf_section.data()
            conf_parts.append((conf_part_address, conf_part_data))

        if args.output_merged_hex:
            combined_conf_data = bytearray(*(data for _, data in conf_parts))
            conf_address = args.output_merged_hex_address
            conf_size = len(combined_conf_data)
            ihex = IntelHex(combined_conf_data)
            ihex.start_addr = conf_address
            ihex.write_hex_file(args.output_merged_hex)
        else:
            conf_address, combined_conf_data = conf_parts[0]
            conf_size = len(combined_conf_data)

        filename_we = re.sub(r'[\W]','_', args.output_header.name).upper()
        prefix = args.output_macro_prefix
        args.output_header.write(
            dedent(f"""\
                #ifndef {filename_we}_H
                #define {filename_we}_H

                #define {prefix}ADDRESS 0x{conf_address:08x}UL
                #define {prefix}SIZE 0x{conf_size:08x}UL

                #endif /* {filename_we}_H */
                """
            )
        )

    except ScriptError as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

