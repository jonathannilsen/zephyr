#!/usr/bin/env python3
#
# Copyright (c) 2021 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
Log Parser for Dictionary-based Logging

This uses the JSON database file to decode the input binary
log data and print the log messages.
"""

import argparse
import binascii
import logging
import sys

import dictionary_parser
from dictionary_parser.log_database import LogDatabase


LOGGER_FORMAT = "%(message)s"
logger = logging.getLogger("parser")


def parse_args():
    """Parse command line arguments"""
    argparser = argparse.ArgumentParser(allow_abbrev=False)

    argparser.add_argument("dbfile", help="Dictionary Logging Database file")
    argparser.add_argument("logfile", help="Log Data file - set to '-' to read from stdin")
    argparser.add_argument("--hex", action="store_true",
                           help="Log Data file is in hexadecimal strings")
    argparser.add_argument("--rawhex", action="store_true",
                           help="Log file only contains hexadecimal log data")
    argparser.add_argument("--debug", action="store_true",
                           help="Print extra debugging information")

    return argparser.parse_args()


def open_log_file(args):
    """
    Read the log from file
    """
    logfile = None

    # TODO: check if it reacts correctly to EOF...

    # Open log data file for reading
    if args.logfile != "-":
        logfile = open(args.logfile, "rb")
        if not logfile:
            logger.error("ERROR: Cannot open log data file: %s, exiting...", args.logfile)
            sys.exit(1)
    else:
        logfile = sys.stdin.buffer

    if args.hex:
        return dictionary_parser.utils.UnhexlifyReader(logfile, rawhex=args.rawhex)

    return logfile


def main():
    """Main function of log parser"""
    args = parse_args()

    # Setup logging for parser
    logging.basicConfig(format=LOGGER_FORMAT)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Read from database file
    database = LogDatabase.read_json_database(args.dbfile)
    if database is None:
        logger.error("ERROR: Cannot open database file: %s, exiting...", args.dbfile)
        sys.exit(1)

    log_parser = dictionary_parser.get_parser(database)
    if log_parser is None:
        logger.error("ERROR: Cannot find a suitable parser matching database version!")
        sys.exit(1)

    logger.debug("# Build ID: %s", database.get_build_id())
    logger.debug("# Target: %s, %d-bit", database.get_arch(), database.get_tgt_bits())
    if database.is_tgt_little_endian():
        logger.debug("# Endianness: Little")
    else:
        logger.debug("# Endianness: Big")
    logger.debug("# Database version: %d", database.get_version())

    with open_log_file(args) as logfile:
        ret = log_parser.parse_log_data(logfile, debug=args.debug)
        if not ret:
            logger.error("ERROR: there were error(s) parsing log data")
            sys.exit(1)


if __name__ == "__main__":
    main()
