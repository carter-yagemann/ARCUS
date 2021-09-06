#!/usr/bin/env python
#
# Copyright 2020 Carter Yagemann
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

import json
from optparse import OptionParser, OptionGroup
import os
import sys

import griffin
import xed

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

PROGRAM_VERSION = '1.0.1'
PROGRAM_USAGE = 'Usage: %prog trace'

# object => list of (sym_name, sym_val) tuples
SYMBOLS = dict()

def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE,
                          version='snapsymbols ' + PROGRAM_VERSION)
    options, args = parser.parse_args()

    if len(args) < 1:
        parser.print_usage()
        sys.exit(1)

    return (options, args)

def va2rva(addr, layout):
    """Given an address, return its RVA and object filepath as a tuple."""
    match = (None, None)
    for obj in layout:
        obj_fp = obj['filepath']
        obj_base = obj['base_va']
        rva = addr - obj_base
        if rva >= 0 and (match[0] is None or rva < match[0]):
            match = (rva, obj_fp)
    return match

def snapshot_addrs(api_dir):
    """Return the starting addresses of the snapshots contained in api_dir."""
    snap_addrs = set()
    for item in os.listdir(api_dir):
        regs_file = os.path.join(api_dir, item, 'regs.json')
        if os.path.isfile(regs_file):
            try:
                with open(regs_file, 'r') as ifile:
                    snap_addrs.add(json.load(ifile)['rip'])
            except:
                pass
    return snap_addrs

def snap2layout(trace_dir, name):
    """Given a snapshot name, return a list where each item contains the keys:

    base_va -- Base VA for an object.
    filepath -- Full path to that object on disk.
    """
    layout = list()
    bin_dir = os.path.join(trace_dir, 'api', name, 'bin')
    for item in os.listdir(bin_dir):
        info = {'base_va': int(item.split('-', 1)[0], 16),
                'filepath': os.path.join(os.path.join(bin_dir, item))}
        layout.append(info)
    return layout

def load_symbols(obj_fp):
    """Given the path to an object, add its symbols to the SYMBOLS dictionary."""
    obj_key = os.path.basename(obj_fp).split('-', 1)[1]
    SYMBOLS[obj_key] = list()

    with open(obj_fp, 'rb') as ifile:
        elf = ELFFile(ifile)
        sym_tables = [s for s in elf.iter_sections()
                      if isinstance(s, SymbolTableSection)]

        for section in sym_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue  # empty

            for symbol in section.iter_symbols():
                SYMBOLS[obj_key].append([symbol.name, symbol['st_value']])

def get_symbol(addr, snap_name, trace_dir):
    """Given a VA and the name of a snapshot, try to find a matching symbol.

    Returns symbol name string or None if no match is found.
    """
    rva, obj_fp = va2rva(addr, snap2layout(trace_dir, snap_name))
    if rva is None:
        return None

    try:
        obj_key = os.path.basename(obj_fp).split('-', 1)[1]
    except IndexError:
        sys.stderr.write("Invalid obj_fp: %s\n" % str(obj_fp))
        return None

    if not os.path.isfile(obj_fp):
        sys.stderr.write("File not found: %s\n" % obj_fp)
        return None

    if not obj_key in SYMBOLS:
        load_symbols(obj_fp)

    for name, val in SYMBOLS[obj_key]:
        if val == rva:
            return name

    return None

def main():
    """The main method."""
    options, args = parse_args()

    trace_dir = args[0]
    api_dir = os.path.join(trace_dir, 'api')

    if not os.path.isdir(api_dir):
        sys.stderr.write("Directory not found: %s\n" % api_dir)
        return

    # trace filepath
    trace_fp = None
    for can in ['trace.griffin', 'trace.griffin.gz']:
        can_fp = os.path.join(trace_dir, can)
        if os.path.isfile(can_fp):
            trace_fp = can_fp
            break
    if trace_fp is None:
        sys.stderr.write("Failed to find trace file in: %s\n" % trace_dir)
        sys.exit(1)
    # VAs of snapshots
    snap_addrs = snapshot_addrs(api_dir)

    # map snapshot addresses to symbol names
    targets = dict()
    plt_addr = None
    for addr in xed.disasm_pt_file(trace_fp):
        if not plt_addr is None:
            # previous addr was PLT, this addr is target
            # (last jump is most likely to be the real symbol, rather than a lazy load,
            #  so we intentionally allow overwriting)
            plt_sym = get_symbol(addr, "%x-0" % plt_addr, trace_dir)
            if not plt_sym is None:
                targets[plt_addr] = plt_sym
            plt_addr = None

        if addr in snap_addrs:
            plt_addr = addr

    for addr in targets:
        sys.stdout.write("%x: %s\n" % (addr, str(targets[addr])))

if __name__ == '__main__':
    main()
