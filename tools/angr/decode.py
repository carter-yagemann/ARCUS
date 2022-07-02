#!/usr/bin/env python
#
# Copyright 2019 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from optparse import OptionParser
import os
import sys
import tempfile

import pefile

import xed
import griffin

VERSION = "0.2.0"


def disasm_xed(options, args):
    for addr in xed._disasm_pt_file_iter(args[0], "block"):
        sys.stdout.write("block: " + hex(addr) + "\n")


def main():
    parser = OptionParser(
        usage="Usage: %prog griffin_trace", version="Griffin Decoder " + VERSION
    )

    options, args = parser.parse_args()

    if len(args) != 1:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args[0]):
        sys.stderr.write(args[0] + " is either not a file or does not exist\n")
        sys.exit(1)

    disasm_xed(options, args)


if __name__ == "__main__":
    main()
