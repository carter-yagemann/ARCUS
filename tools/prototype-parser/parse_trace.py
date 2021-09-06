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

from __future__ import print_function

import logging
import multiprocessing
from optparse import OptionParser, OptionGroup
import os
import queue
import subprocess
import sys
from traceback import format_exc

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

PROGRAM_VERSION = '1.0.2'
PROGRAM_USAGE = 'Usage: %prog [options] tracer_output_dir prototype_output_dir'

def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE,
                          version='Parse Trace ' + PROGRAM_VERSION)

    group_parse = OptionGroup(parser, 'Parse Options')
    group_parse.add_option('-I', '--include', action='store', type='str', default=None,
            help='Additional directories (comma separated) to scan for finding prototype declarations')
    group_parse.add_option('-l', '--logging', action='store', type='int', default=20,
            help='Log level [10-50] (default: 20 - Info)')
    parser.add_option_group(group_parse)

    group_debug = OptionGroup(parser, 'Debug Options')
    group_debug.add_option('-s', '--sync', action='store_true', default=False,
            help='Process synchronously so stack traces can be recovered from crashed workers')

    options, args = parser.parse_args()

    # input validation
    if len(args) != 2:
        parser.print_help()
        sys.exit(1)
    if not options.include is None:
        try:
            options.include = options.include.split(',')
        except:
            print('Failed to parse --include option: %s' % str(options.include), file=sys.stderr)
            sys.exit(1)

    return (options, args)

def find_pkg_config():
    """Returns the path to the pkg-config binary, if found, otherwise None."""
    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, 'pkg-config')
        if os.path.isfile(candidate):
            return candidate
    return None

def parse_symbol_names(trace_dir):
    """Get the symbol names for the snapshots contained in the trace.

    Keyword Arguments:
    trace_dir -- The root directory of the trace.

    Returns:
    A list of tuples (symbol_name, path_to_snapshot_directory).
    """
    res = list()

    # functionality already exists in a tool called snapsymbols.py, piggyback off it
    scanner_bin = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../angr/snapsymbols.py')
    if not os.path.isfile(scanner_bin):
        log.critical("Cannot find program for scanning snapshot symbols: %s" % scanner_bin)
        sys.exit(2)

    FNULL = open(os.devnull, 'w')  # suppress error messages
    scanner = subprocess.Popen([scanner_bin, trace_dir], stdout=subprocess.PIPE, stderr=FNULL, bufsize=1)

    for line in scanner.stdout:
        line = line.decode().rstrip()
        parts = line.split(': ', 1)
        if len(parts) != 2:
            log.warning("Failed to parse scanner output line: %s" % line)
            continue
        if parts[1] == 'None':
            log.warning("Scanner could not resolve symbol for PLT stub: %s" % parts[0])
            continue

        info = [parts[1], os.path.join(trace_dir, 'api/%s-0' % parts[0])]
        if not os.path.isdir(info[1]):
            log.warning("Failed to find snapshot directory for symbol: %s" % info[1])
            continue

        res.append(info)

    # cleanup
    scanner.wait()
    FNULL.close()
    if scanner.returncode != 0:
        log.warning("Scanner returned non-zero return code: %d" % scanner.returncode)

    return res

def get_exported_symbols(obj_fp):
    """Given the file path to an object, return a set of exported symbols it contains."""
    obj_syms = set()

    with open(obj_fp, 'rb') as ifile:
        try:
            elf = ELFFile(ifile)
        except ELFError:
            # failed to parse ELF, likely not an actual ELF
            return obj_syms

        sym_tables = [s for s in elf.iter_sections()
                      if isinstance(s, SymbolTableSection)]

        for section in sym_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                continue  # empty

            for symbol in section.iter_symbols():
                if isinstance(symbol['st_shndx'], str) and symbol['st_shndx'] == 'SHN_UNDEF':
                    continue  # undefined symbol (imported)

                obj_syms.add(symbol.name)

    return obj_syms

def get_default_include_dirs():
    """Check if some common include directories exist on the system, returning a list."""
    can_dirs = ['/usr/include',
                '/usr/local/include',
                '/usr/lib']

    return [dir for dir in can_dirs if os.path.isdir(dir)]

def pkg_config_get_includes(job, name):
    """Try to find additional directories to include for an object name."""
    includes = list()

    if job.pkg_config is None:
        job.msg_queue.add((logging.ERROR, "No pkg-config binary found, cannot query it"))
        return includes

    FNULL = open(os.devnull, 'w')  # suppress error messages
    pc_session = subprocess.Popen([job.pkg_config, '--cflags', name], stdout=subprocess.PIPE,
                                  stderr=FNULL, bufsize=1)

    for line in pc_session.stdout:
        line = line.decode().rstrip()
        for part in line.split(' '):
            if part.startswith('-I'):
                inc_path = part[2:]
                if len(inc_path) > 0:
                    includes.append(inc_path)

    # cleanup
    pc_session.wait()
    FNULL.close()

    if pc_session.returncode != 0:
        job.msg_queue.put((logging.DEBUG, "Object not found in pkg-config: %s" % name))

    return includes

def is_c_file(filename):
    """Returns true if the file has a valid C/C++ extension."""
    exts = ['.c', '.cpp', '.h']
    for ext in exts:
        if filename.endswith(ext):
            return True
    return False

def search_includes(include_dirs, symbol, msg_queue):
    """Search the include directories for files that possibly define the provided symbol."""
    can_fps = set()
    for inc_dir in include_dirs:
        for root, dirs, fnames in os.walk(inc_dir):
            for fname in fnames:
                if not is_c_file(fname):
                    continue
                fp = os.path.join(root, fname)
                try:
                    with open(fp, 'r') as ifile:
                        for line in ifile:
                            if symbol in line:
                                can_fps.add(fp)
                                break
                except UnicodeDecodeError:
                    msg_queue.put((logging.DEBUG, 'Failed to decode: %s' % fp))

    # function parsing is pretty fast, so while we could try to prioritize candidate
    # root source files, bruteforce is easier and works well
    return list(can_fps)

def extract_prototype(root_fp_cans, symbol, include_dirs, output_dir, msg_queue):
    """Extract and save the prototype for the provided symbol using the candidate files."""
    cpp_args = ['-I%s' % idir for idir in include_dirs]
    parse_bin = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'parse_function.py')
    if not os.path.isfile(parse_bin):
        msg_queue.put((logging.ERROR, 'Cannot find prototype extraction script: %s' % parse_bin))
        return

    with open(os.devnull, 'w') as FNULL:
        for root_fp in root_fp_cans:
            cmd = [parse_bin, root_fp, symbol, output_dir] + cpp_args
            msg_queue.put((logging.DEBUG, 'Running command: %s' % str(cmd)))

            parser = subprocess.Popen(cmd, stdout=FNULL, stderr=FNULL, bufsize=1)

            try:
                parser.wait(300)
            except subprocess.TimeoutExpired:
                msg_queue.put((logging.WARNING, 'Parsing command timed out, killing...'))
                parser.terminate()
                try:
                    parser.wait(20)
                except subprocess.TimeoutExpired:
                    parser.kill()

            if parser.returncode == 0:
                msg_queue.put((logging.DEBUG, 'Successfully extracted prototype from: %s' % root_fp))
                return

    msg_queue.put((logging.ERROR, 'All candidates failed to yield prototype for: %s' % symbol))

class Job(object):
    def __init__(self, sym_name, snapshot_dir, msg_queue, options, pkg_config, output_dir):
        self.sym_name = sym_name
        self.snapshot_dir = snapshot_dir
        self.msg_queue = msg_queue
        self.options = options
        self.pkg_config = pkg_config
        self.output_dir = output_dir

def process_symbol_inner(job):
    """Try to build a prototype for one symbol."""
    job.msg_queue.put((logging.DEBUG, "Starting prototype generation for symbol: %s" % job.sym_name))

    # Step 2: Find the object that export the symbol we care about
    can_objs = set()
    snap_bin_dir = os.path.join(job.snapshot_dir, 'bin')
    for item in os.listdir(snap_bin_dir):
        item_path = os.path.join(snap_bin_dir, item)
        try:
            item_syms = get_exported_symbols(item_path)
        except Exception as ex:
            job.msg_queue.put((logging.ERROR, "Failed to parse object for symbols: %s" % str(ex)))
        if job.sym_name in item_syms:
            try:
                can_objs.add(item.split('-', 1)[1].split('.', 1)[0].split('-', 1)[0])
            except IndexError:
                job.msg_queue.put((logging.ERROR, "Failed to extract object name from filename: %s" % item))

    if len(can_objs) < 1:
        job.msg_queue.put((logging.ERROR, "Failed to find object that exports symbol: %s" % job.sym_name))
        return

    # Step 3: Check pkg-config for additional include directories to scan
    if not job.options.include is None:
        include_dirs = job.options.include.copy()
    else:
        include_dirs = list()

    include_dirs += get_default_include_dirs()

    if not job.pkg_config is None:
        for name in can_objs:
            include_dirs += pkg_config_get_includes(job, name)

    if len(include_dirs) < 1:
        job.msg_queue.put((logging.ERROR, "Failed to find include directories to scan for symbol: %s" % job.sym_name))
        return

    job.msg_queue.put((logging.DEBUG, "Include directories to scan: %s" % str(include_dirs)))

    # Step 4: Pinpoint the correct source file to use as the root for buliding the AST
    root_fp_cans = search_includes(include_dirs, job.sym_name, job.msg_queue)

    job.msg_queue.put((logging.DEBUG,
            "Candidate files for extracting %s: %s" % (job.sym_name, str(root_fp_cans))))

    # Step 5: Build the prototype JSON (piggyback off parse_function.py, which already has the functionality)
    extract_prototype(root_fp_cans, job.sym_name, include_dirs, job.output_dir, job.msg_queue)

def process_symbol(job):
    """Real functionality is in process_symbol_inner, this is a try-except wrapper to make
    sure jobs invoked asynchronously don't crash silently."""
    try:
        return process_symbol_inner(job)
    except Exception as ex:
        job.msg_queue.put((logging.ERROR,
            'Uncaught exception while handling %s: %s' % (job.sym_name, format_exc())))

def main():
    """Main method."""
    options, args = parse_args()
    trace_dir, out_dir = args
    pkg_config = find_pkg_config()

    # intialize logging
    log.setLevel(options.logging)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(levelname)7s | %(asctime)-15s | %(message)s'))
    log.addHandler(handler)

    # environment checks
    if pkg_config is None:
        log.warning("pkg-config is not installed on this system, relying on --includes option")
        if options.include is None:
            log.error("Option --includes is also not provided, no way to automatically find source files to scan")
            sys.exit(1)

    # Step 1: Get symbol names for snapshots
    log.info("Extracting symbol names from snapshots (this may take awhile)")
    sym_info = parse_symbol_names(trace_dir)

    # the remaining steps are dispatched to workers for parallel processing
    log.info("Extracting prototypes")
    manager = multiprocessing.Manager()
    msg_queue = manager.Queue(128)
    workers = multiprocessing.Pool()

    jobs = list()
    for sym_name, snap_dir in sym_info:
        # skip symbols that already have prototypes in the output directory
        if os.path.isfile(os.path.join(out_dir, "%s.json" % sym_name)):
            log.info("Prototype exists in output directory, skipping: %s" % sym_name)
        else:
            jobs.append(Job(sym_name, snap_dir, msg_queue, options, pkg_config, out_dir))

    if not options.sync:
        res = workers.map_async(process_symbol, jobs)
    else:
        res = workers.map(process_symbol, jobs)

    if not options.sync:
        while not res.ready():
            try:
                level, msg = msg_queue.get(True, 1)
                log.log(level, msg)
            except queue.Empty:
                continue

    # print remaining messages and shutdown workers
    workers.close()
    while not msg_queue.empty():
        level, msg = msg_queue.get()
        log.log(level, msg)
    manager.shutdown()

if __name__ == '__main__':
    log = logging.getLogger('parse_trace')
    main()
