#!/usr/bin/env python3
#
# Copyright 2022 Carter Yagemann
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

import gzip
from hashlib import sha256
import json
import logging
from optparse import OptionParser, OptionGroup
import os
from shutil import copyfile
import sys

import angr

PROGRAM_VERSION = "1.0.0"
PROGRAM_USAGE = (
    "Usage: %prog [options] <output_directory> <tracee_path> [tracee_args]..."
)


def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE, version="%prog " + PROGRAM_VERSION)

    group_logging = OptionGroup(parser, "Logging Options")
    group_logging.add_option(
        "-l",
        "--logging",
        action="store",
        type="int",
        default=20,
        help="Log level [10-50] (default: 20 - Info)",
    )
    group_logging.add_option(
        "--logging-angr",
        action="store",
        type="int",
        default=40,
        help="Level for Angr (default: Error)",
    )
    parser.add_option_group(group_logging)

    parser.disable_interspersed_args()
    options, args = parser.parse_args()
    if len(args) < 2:
        parser.print_usage()
        sys.exit(1)
    return (options, args)


def init_logging(options):
    logging.getLogger(__name__).setLevel(options.logging)
    logging.getLogger(angr.__name__).setLevel(options.logging_angr)


def sha256_file(filepath):
    """Returns a sha256 has of a file's contents. Returns None on error."""
    if not os.path.isfile(filepath):
        return None

    try:
        with open(filepath, "rb") as ifile:
            return sha256(ifile.read()).hexdigest()
    except:
        return None


def dump_state(dir, args):
    """Creates dir/state.json formatted for use by analysis.py."""
    state_path = os.path.join(dir, "state.json")
    state = dict()
    # argv
    state["argv"] = list()
    for arg in args:
        state["argv"].append({"type": "str", "value": arg})
    # env
    state["env"] = list()
    for key in os.environ:
        val = os.environ[key]
        state["env"].append(
            {
                "key_type": "str",
                "key_val": key,
                "key_size": None,
                "val_type": "str",
                "val_val": val,
                "val_size": None,
            }
        )

    with open(state_path, "w") as ofile:
        json.dump(state, ofile)


def dump_settings(dir, args, setdict):
    """Creates dir/settings.json"""
    settings_path = os.path.join(dir, "settings.json")
    settings = dict()
    # version
    settings["version"] = PROGRAM_VERSION
    # settings
    settings["settings"] = setdict
    # tracee_cmd
    settings["traced-cmd"] = args[1:]

    with open(settings_path, "w") as ofile:
        json.dump(settings, ofile)


def dump_regs(output_dir, state):
    """Dumps the registers for state in JSON format to dir/regs.json."""
    regs_path = os.path.join(output_dir, "regs.json")
    reg_dict = dict()

    for reg_name in state.arch.registers:
        offset, size = state.arch.registers[reg_name]
        reg_val = state.registers.load(offset, size)
        reg_dict[reg_name] = state.solver.eval(reg_val, cast_to=int)

    with open(regs_path, "w") as ofile:
        json.dump(reg_dict, ofile)


def dump_mem(dir, state):
    """Dumps the memory for state into a set of files in dir.

    Keyword Arguments:
    dir -- The directory to dump the memory into.
    state -- angr state to dump.
    """
    memdir = os.path.join(dir, "mem/")
    bindir = os.path.join(dir, "bin/")
    misc = os.path.join(dir, "misc.json")
    misc_json = dict()
    fetched_bins = list()

    if not os.path.exists(memdir):
        os.mkdir(memdir)
    if not os.path.exists(bindir):
        os.mkdir(bindir)

    for elf in state.project.loader.all_objects:
        for segment in elf.segments:
            va_start = segment.vaddr
            va_end = segment.vaddr + segment.memsize
            if not 0 < (va_end - va_start) < 0x80000000:
                continue  # too big, skip
            full_name = elf.binary
            name = elf.binary_basename

            # do not dump CLE-specific segments
            if full_name.startswith("cle##"):
                continue

            # dump memory segment
            ofilepath = os.path.join(memdir, "%x-%s.bin" % (va_start, name))
            raw_mem = state.memory.load(va_start, va_end - va_start)
            raw_mem = state.solver.eval(raw_mem, cast_to=bytes)
            with open(ofilepath, "wb") as ofile:
                ofile.write(raw_mem)

            # fetch binary
            if os.path.isfile(full_name) and not full_name in fetched_bins:
                binfn = "%x-%s" % (va_start, name)
                binfp = os.path.join(bindir, binfn)
                copyfile(full_name, binfp)

                fetched_bins.append(full_name)

                if elf.is_main_bin:
                    misc_json["main"] = binfn

    # additional important information
    misc_json["brk"] = state.posix.brk
    with open(os.path.join(dir, "misc.json"), "w") as ofile:
        json.dump(misc_json, ofile)


def dump_files(outdir, tracee_args):
    """Save copies of files touched by the tracee.

    Currently, this just checks each argv to see if it's a valid filepath.
    """
    files_json = {"files": {}, "cwd": None}
    files_dir = os.path.join(outdir, "files")

    if not os.path.exists(files_dir):
        os.mkdir(files_dir)

    # record cwd
    files_json["cwd"] = os.getcwd()

    # check tracee's argv for any valid filepaths
    for arg in tracee_args:
        if os.path.isfile(arg):
            shasum = sha256_file(arg)
            dest = os.path.join(files_dir, shasum)
            if not os.path.exists(dest):
                copyfile(arg, dest)
            files_json["files"][os.path.abspath(arg)] = {
                "data": os.path.join("files/", shasum),
                "symbolic": False,
            }

        # We do not handle directories because they can be very deep,
        # have symlinks pointing outside the directory, etc. It's also
        # possible to use syscall hooking to collect only the files
        # touched by the tracee, but this incurs overhead and requires
        # the tracer to be attached at all times. Staying attached is
        # inevitable in some advanced modes (API snapshot), but we want
        # to keep the default mode as simple and hands-off as possible.

    # write files.json
    with open(os.path.join(outdir, "files.json"), "w") as ofile:
        json.dump(files_json, ofile)


def dump_trace(outdir, state):
    """Record the basic block sequence executed by state"""
    with gzip.open(os.path.join(outdir, "trace.perf.gz"), "wt") as ofile:
        ofile.write("[pid: 123456]\n")
        for addr in state.history.bbl_addrs:
            ofile.write("%x\n" % addr)


def resolve_path(name):
    """Tries to find name in PATH.

    Returns empty string if no match is found.
    """
    path_dirs = os.environ["PATH"].split(":")
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, name)
        if os.path.isfile(candidate):
            return candidate

    return ""  # no match


def main():
    """The main method."""
    options, args = parse_args()
    output_dir = args[0]
    tracee_path = args[1]

    init_logging(options)

    if not os.path.exists(tracee_path):
        # user may have provided a program name in PATH
        tracee_path = resolve_path(tracee_path)

    if not os.path.isfile(tracee_path):
        log.error("%s is not a file\n" % tracee_path)
        sys.exit(1)

    # realpath() dereferences symlinks that would otherwise confuse enable_griffin()
    tracee_path = os.path.realpath(tracee_path)
    tracee_args = [os.path.basename(tracee_path)] + args[2:]

    if not os.path.exists(output_dir):
        try:
            os.mkdir(output_dir)
        except Exception as ex:
            log.error("Failed to make %s: %s\n" % (output_dir, str(ex)))
            sys.exit(1)
    if not os.path.isdir(output_dir):
        log.error("%s is not a directory\n" % output_dir)
        sys.exit(1)

    log.info("Creating angr project for: %s" % tracee_path)
    proj = angr.Project(tracee_path)

    init_state = proj.factory.entry_state(
            concrete_fs=True,
            args=tracee_args,
            env=os.environ,
    )

    dump_state(output_dir, tracee_args)
    dump_files(output_dir, tracee_args)
    dump_regs(output_dir, init_state)
    dump_mem(output_dir, init_state)

    simgr = proj.factory.simgr(init_state)

    log.info("Starting exploration")
    simgr.run()

    log.info("Exploration complete, processing results")
    if len(simgr.stashes['deadended']) < 1:
        log.error("No states reached end of execution")
        sys.exit(1)
    elif len(simgr.stashes['deadended']) > 1:
        log.warning("Multiple states exited, picking one")

    end_state = simgr.stashes['deadended'][0]

    log.info("Dumping trace from state: %s" % end_state)
    dump_trace(output_dir, end_state)
    dump_settings(output_dir, args, options.__dict__)

    log.info("Trace successfully written to: %s" % output_dir)

if __name__ == "__main__":
    __name__ = "simulator"
    log = logging.getLogger(__name__)
    main()
