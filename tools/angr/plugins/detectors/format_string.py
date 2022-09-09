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

import logging

import angr
import pyvex

import taint

log = logging.getLogger(__name__)


def get_simproc(state):
    """Returns the simulation procedure this state is about to enter,
    if one exists, otherwise returns None."""
    sym_name = state.project.loader.find_plt_stub_name(state.addr)
    if sym_name is None:
        return None

    sym = state.project.loader.find_symbol(sym_name)
    if sym is None:
        return None

    hook_addr, _ = state.project.simos.prepare_function_symbol(
        sym_name, basic_addr=sym.rebased_addr
    )

    if state.project.is_hooked(hook_addr):
        return state.project.hooked_by(hook_addr)

    return None


def add_detection(state, handler, bad_addr=None, bad_idx=None):
    caller_addr = state.history.bbl_addrs[-1]
    if caller_addr in detections:
        return False  # duplicate
    detections[caller_addr] = (handler, bad_addr, bad_idx)
    return True


def check_scan_args(state, fmt_idx):
    """Check if any of the arguments in the format string perform an
    unbounded amount of writing.

    Returns True if state is vulnerable, otherwise False.
    """
    simproc = get_simproc(state)
    if simproc is None:
        log.warning(
            "Cannot find simulation procedure for %s"
            % state.project.loader.describe_addr(state.addr)
        )
        return False

    args = state.project.factory.cc().get_args(state, simproc.prototype)
    fmt_arg = args[fmt_idx]
    try:
        fmt_ptr = state.solver.eval(fmt_arg)
    except angr.errors.SimUnsatError:
        return False

    res = state.memory.find(fmt_ptr, b"\x00", max_search=1024, max_symbolic_bytes=256)
    if len(res[2]) < 1:
        log.warning("Failed to find format string")
        return False
    if res[2][0] < 1:
        log.warning("Found empty format string?")
        return False

    fmt_str = state.memory.load(fmt_ptr, size=res[2][0])
    fmt_str = state.solver.eval(fmt_str, cast_to=bytes).decode("ascii")
    fmt_len = len(fmt_str)

    for idx, char in enumerate(fmt_str[:-1]):
        # check for string scan with no size specifier
        if char == "%" and fmt_str[idx + 1] == "s":
            log.warn("Scanning string of unbounded size")
            return add_detection(state, analyze_state_unbounded_arg)

    return False


def check_fmt_str(state, fmt_idx):
    """Check if the format string pointer or data is symbolic, which
    indicates that something outside the program can control it.

    Returns True if state is vulnerable, otherwise False.
    """
    simproc = get_simproc(state)
    if simproc is None:
        log.warning(
            "Cannot find simulation procedure for %s"
            % state.project.loader.describe_addr(state.addr)
        )
        return False

    args = state.project.factory.cc().get_args(state, simproc.prototype)

    if len(args) <= fmt_idx:
        log.error(
            "Function prototype only has %d arguments, "
            "but format string is suppose to be at index %d" % (len(args), fmt_idx)
        )
        return False

    fmt_arg = args[fmt_idx]

    if state.solver.symbolic(fmt_arg):
        log.warn("Symbolic format string pointer")
        return add_detection(state, analyze_state_sym_str, bad_idx=fmt_idx)
    try:
        fmt_ptr = state.solver.eval(fmt_arg)
    except angr.errors.SimUnsatError:
        return False

    log.debug("Format String Pointer: %#x" % fmt_ptr)

    res = state.memory.find(fmt_ptr, b"\x00", max_search=4096, max_symbolic_bytes=256)
    # did we find an end to this string?
    if len(res[2]) < 1:
        log.warning("Failed to find format string")
        return False
    # did we find a variable length string?
    if len(res[2]) > 1:
        for offset in res[2][:1]:
            byte = state.memory.load(fmt_ptr + offset, size=1)
            if len(state.solver.eval_upto(byte, 2)) > 1:
                log.error("Variable length format string")
                return add_detection(state, analyze_state_sym_str, bad_addr=fmt_ptr)
            else:
                # byte must be null, string is fixed length
                break

    fmt_str = state.memory.load(fmt_ptr, size=res[2][0])
    if state.solver.symbolic(fmt_str):
        log.error("Symbolic format string")
        return add_detection(state, analyze_state_sym_str, bad_addr=fmt_ptr)

    fmt_str = state.solver.eval(fmt_str, cast_to=bytes).decode("ascii")
    fmt_str = fmt_str.replace("\n", "\\n").replace("\t", "\\t")
    log.debug("Format String: '%s'" % fmt_str)
    return False


def _taint_irexpr(expr, tainted_tmps, load_tmps, load_addrs):
    """Given an non-OP IRExpr, add any tmps or regs to the provided sets.

    This is a helper for taint_irexpr and should not be called directly.
    """
    if isinstance(expr, pyvex.expr.RdTmp):
        log.debug("tainting t%d" % expr.tmp)
        tainted_tmps.add(expr.tmp)
    elif isinstance(expr, pyvex.expr.Load):
        if isinstance(expr.addr, pyvex.expr.Const):
            load_addrs.add(expr.con)
        elif isinstance(expr.addr, pyvex.expr.RdTmp):
            load_tmps.add(expr.addr.tmp)


def taint_irexpr(expr, tainted_tmps, load_tmps, load_addrs):
    """Given an IRExpr, add any tmps or loads to the provided sets."""
    if isinstance(
        expr, (pyvex.expr.Qop, pyvex.expr.Triop, pyvex.expr.Binop, pyvex.expr.Unop)
    ):
        for arg in expr.args:
            _taint_irexpr(arg, tainted_tmps, load_tmps, load_addrs)
    else:
        _taint_irexpr(expr, tainted_tmps, load_tmps, load_addrs)


def find_bad_addr(states, state_idx, arg_idx):
    """Given a series of states, a state index and an argument index, return the memory address
    that argument depends on.

    Keyword Args:
    states -- A list of states.
    state_idx -- Which state to analyze.
    arg_idx -- Which argument to analyze.

    Returns:
    A memory address or None if there was a problem.
    """
    bug_state = states[state_idx]

    simproc = bug_state.project.hooked_by(bug_state.addr)
    if simproc is None:
        log.warning("Cannot find simulation procedure for %s" % (
                bug_state.project.loader.describe_addr(bug_state.addr)))
        return None

    # get location of argument
    loc = bug_state.project.factory.cc().arg_locs(simproc.prototype)[arg_idx]

    if isinstance(loc, angr.calling_conventions.SimRegArg):
        reg_offset = bug_state.arch.registers[loc.reg_name][0]

        # find state that wrote the register's value
        write_idx = state_idx - 1
        final_val = bug_state.solver.eval(
            bug_state.registers.load(reg_offset, size=bug_state.arch.bits // 8)
        )
        for state in states[:state_idx][::-1]:
            if (
                state.solver.eval(
                    state.registers.load(reg_offset, state.arch.bits // 8)
                )
                != final_val
            ):
                break
            write_idx -= 1

        write_state = states[write_idx]
        write_irsb = write_state.block(write_state.addr).vex

        # find PUT statement for the register
        put_idx = len(write_irsb.statements) - 1
        for stmt in write_irsb.statements[::-1]:
            if isinstance(stmt, pyvex.stmt.Put) and stmt.offset == reg_offset:
                break
            put_idx -= 1
        if put_idx < 0:
            log.error("Failed to find VEX Put statement for register argument")
            return None

        put_data = write_irsb.statements[put_idx].data
        if isinstance(put_data, pyvex.expr.Const):
            return put_data.con

        # tmp placed in register, find all loads associated with this tmp
        load_tmps = set()
        load_addrs = set()
        tainted_tmps = {put_data.tmp}

        for stmt in write_irsb.statements[:put_idx][::-1]:
            if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
                taint_irexpr(stmt.data, tainted_tmps, load_tmps, load_addrs)

        if len(load_tmps) > 0:
            # found some tmps holding load addresses, resolve them
            tmps = taint.get_mem_accesses(
                write_state, states[write_idx + 1], loads=True, stores=False
            )
            for tmp, ast in tmps:
                if tmp in load_tmps:
                    return write_state.solver.eval(ast)
        elif len(load_addrs):
            # no load tmps found, but we have constant addresses
            return load_addrs[0]
        else:
            # couldn't find anything of value
            log.error(
                "Could not find any memory addresses used to calculate register argument"
            )
            return None

    elif isinstance(loc, angr.calling_conventions.SimStackArg):
        sp_bv = bug_state.registers.load(bug_state.arch.sp_offset, size=bug_state.arch.bits // 8)
        return bug_state.solver.eval(sp_bv) + loc.stack_offset
    else:
        log.error("Unknown argument type: %s" % type(loc))
        return None


def analyze_state(simgr, trace, state, report):
    prev_addr = state.history.bbl_addrs[-1]
    if not prev_addr in detections:
        log.error("Cannot find info on detected state")
        return

    return detections[prev_addr][0](simgr, trace, state, report)


def analyze_state_unbounded_arg(simgr, trace, state, report):
    # an unbounded arg is its own root cause
    ldr = state.project.loader
    prev_state_desc = ldr.describe_addr(state.history.bbl_addrs[-1])
    log.info("Blaming caller for having an unbounded arg: %s" % prev_state_desc)
    report.add_detail(
        "blame",
        {"address": state.history.bbl_addrs[-1], "description": prev_state_desc},
    )


def analyze_state_sym_str(simgr, trace, state, report):
    # some objects we're going to reference frequently
    proj = state.project
    ldr = state.project.loader
    tech = simgr._techniques[0]
    prev_addr = state.history.bbl_addrs[-1]

    if not prev_addr in detections:
        log.error("Cannot find info on detected state")
        return

    bad_addr, bad_idx = detections[prev_addr][1:]
    pred_states = [state for state in tech.predecessors if not state is None]
    try:
        detected_idx = pred_states.index(state)
    except ValueError:
        log.error(
            "Cannot find detected state in technique's predecessors, cannot continue"
        )
        return

    if bad_addr is None:
        # Detection was based on a register, not a memory location.
        # We need a memory location.
        bad_addr = find_bad_addr(pred_states, detected_idx, bad_idx)

    if bad_addr is None:
        blame_state = pred_states[detected_idx - 1]
    else:
        # find state to blame (last one to write to bad address)
        final_val = state.solver.eval(state.mem[bad_addr].uint64_t.resolved)
        blame_state = None
        for state in pred_states[:detected_idx][::-1]:
            if state.solver.eval(state.mem[bad_addr].uint64_t.resolved) != final_val:
                blame_state = state
                break

    if blame_state is None:
        # all we can do is blame the caller
        if detected_idx > 0:
            description = ldr.describe_addr(pred_states[detected_idx - 1].addr)
            log.info("Blaming for corrupting format string: %s" % description)
            report.add_detail(
                "blame",
                {
                    "address": pred_states[detected_idx - 1].addr,
                    "description": description,
                },
            )
        else:
            log.error("Failed to find state to blame")
        return

    blame_desc = ldr.describe_addr(blame_state.addr)
    log.info("Blaming for corrupting format string: %s" % blame_desc)
    report.add_detail("blame", {"address": blame_state.addr, "description": blame_desc})


def check_for_vulns(simgr, proj):
    """Check for format string, args mismatch."""
    # key: function name
    # val: index of format string argument
    formatparsers = {
        "vsnprintf": 2,
        "vsprintf": 1,
        "vdprintf": 1,
        "vfprintf": 1,
        "snprintf": 2,
        "vprintf": 0,
        "sprintf": 1,
        "dprintf": 1,
        "fprintf": 1,
        "printf": 0,
    }

    scanners = {
        "vsscanf": 1,
        "vfscanf": 1,
        "fscanf": 1,
        "sscanf": 1,
        "vscanf": 0,
        "scanf": 0,
    }

    if len(simgr.stashes["active"]) < 1:
        return False

    state = simgr.stashes["active"][0]

    if state.solver.symbolic(state._ip):
        # This plugin cannot handle states with symbolic program counters
        return True

    sym_name = proj.loader.find_plt_stub_name(state.addr)
    if sym_name is None:
        return True
    sym_name = sym_name.split("_")[-1]

    if sym_name in formatparsers:
        if check_fmt_str(state, formatparsers[sym_name]):
            simgr.stashes["fmt"].append(state)
    if sym_name in scanners:
        if check_scan_args(state, scanners[sym_name]):
            simgr.stashes["fmt"].append(state)

    return True


detections = dict()

stash_name = "fmt"
pretty_name = "Format String"
