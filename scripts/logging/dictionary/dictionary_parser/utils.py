#!/usr/bin/env python3
#
# Copyright (c) 2021 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
Utilities for Dictionary-based Logging Parser
"""

import binascii


ENCODING = "iso-8859-1"
LOG_HEX_SEP = "##ZLOGV1##".encode(encoding=ENCODING)


# TODO: better name?
class UnhexlifyReader:
    """TODO"""

    def __init__(self, logfile, rawhex=False):
        self._logfile = logfile
        self._data_started = rawhex
        self._marker = bytes()

    def read(self, size=-1, /):
        if size == 0:
            return bytes()

"""
        if args.rawhex:
            # Simply log file with only hexadecimal data
            logdata = dictionary_parser.utils.convert_hex_file_to_bin(args.logfile)
        else:
            hexdata = ''

            with open(args.logfile, "r", encoding="iso-8859-1") as hexfile:
                for line in hexfile.readlines():
                    hexdata += line.strip()

            if LOG_HEX_SEP not in hexdata:
                logger.error("ERROR: Cannot find start of log data, exiting...")
                sys.exit(1)

            idx = hexdata.index(LOG_HEX_SEP) + len(LOG_HEX_SEP)
            hexdata = hexdata[idx:]

            if len(hexdata) % 2 != 0:
                # Make sure there are even number of characters
                idx = int(len(hexdata) / 2) * 2
                hexdata = hexdata[:idx]

            idx = 0
            while idx < len(hexdata):
                # When running QEMU via west or ninja, there may be additional
                # strings printed by QEMU, west or ninja (for example, QEMU
                # is terminated, or user interrupted, etc). So we need to
                # figure out where the end of log data stream by
                # trying to convert from hex to bin.
                idx += 2

                try:
                    binascii.unhexlify(hexdata[:idx])
                except binascii.Error:
                    idx -= 2
                    break

            logdata = binascii.unhexlify(hexdata[:idx])
"""



def convert_hex_file_to_bin(hexfile):
    """This converts a file in hexadecimal to binary"""
    bin_data = b''

    with open(hexfile, "r", encoding="iso-8859-1") as hfile:
        for line in hfile.readlines():
            hex_str = line.strip()

            bin_str = binascii.unhexlify(hex_str)
            bin_data += bin_str

    return bin_data


def extract_one_string_in_section(section, str_ptr):
    """Extract one string in an ELF section"""
    data = section['data']
    max_offset = section['size']
    offset = str_ptr - section['start']

    if offset < 0 or offset >= max_offset:
        return None

    ret_str = ""

    while (offset < max_offset) and (data[offset] != 0):
        ret_str += chr(data[offset])
        offset += 1

    return ret_str


def find_string_in_mappings(string_mappings, str_ptr):
    """
    Find string pointed by string_ptr in the string mapping
    list. Return None if not found.
    """
    if string_mappings is None:
        return None

    if len(string_mappings) == 0:
        return None

    if str_ptr in string_mappings:
        return string_mappings[str_ptr]

    # No direct match on pointer value.
    # This may be a combined string. So check for that.
    for ptr, string in string_mappings.items():
        if ptr <= str_ptr < (ptr + len(string)):
            whole_str = string_mappings[ptr]
            return whole_str[str_ptr - ptr:]

    return None
