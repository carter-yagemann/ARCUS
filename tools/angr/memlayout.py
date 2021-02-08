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

from optparse import OptionParser, OptionGroup
import os
import sys

import griffin

PROGRAM_VERSION = '1.0.0'
PROGRAM_USAGE = 'Usage: %prog griffin_trace'

def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE,
                          version='memlayout ' + PROGRAM_VERSION)
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.print_usage()
        sys.exit(1)

    return (options, args)

def main():
    """The main method."""
    options, args = parse_args()
    trace_fp = args[0]

    if not os.path.isfile(trace_fp):
        sys.stderr.write("File not found: %s\n" % trace_fp)
        return

    layout = griffin.init_mem_layout(trace_fp)
    for item in layout:
        sys.stdout.write("%#x  %s\n" % (item['base_va'], item['filepath']))

if __name__ == '__main__':
    main()
