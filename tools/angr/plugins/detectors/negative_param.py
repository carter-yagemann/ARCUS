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
from cle.address_translator import AT
import pyvex

import taint

log = logging.getLogger(__name__)


class ArgNegativeException(Exception):
    pass


def check_args(state, indexes):
    """Checks if arguments that should not be negative are.

    Keyword Args:
    state - The state to check.
    indexes - A list of argument indexes to check.

    Raises ArgNegativeException if limit is exceeded.

    Exception Properties:
    idx - Argument index.
    name - Symbol name.
    value - The argument's value.
    offset - SimArgument (e.g. SimRegArg, SimStackArg)

    Returns None.
    """
    simproc = state.project.hooked_by(state.addr)
    if simproc is None:
        log.warning(
            "Cannot find simulation procedure for %s"
            % state.project.loader.describe_addr(state.addr)
        )
        return

    args = state.project.factory.cc().get_args(state, simproc.prototype)

    for idx in indexes:
        arg = args[idx]
        try:
            arg_val = state.solver.max(arg)
        except angr.errors.SimUnsatError:
            continue
        if arg_val >= 0xF000000000000000:
            ex = ArgNegativeException("negative-size-param")
            ex.idx = idx
            ex.name = state.project.loader.find_plt_stub_name(state.addr)
            ex.value = arg_val
            ex.offset = state.project.factory.cc().arg_locs(simproc.prototype)[idx]
            raise ex


def blame_load_concrete_val(state, preds, load_addr):
    """Try to find a state to blame for an address containing a bad concrete value.

    Keyword Args:
    state -- The state where the bad value was detected.
    preds -- The predecessors to that state.
    load_addr -- The address where the value was read from.

    Returns a state or None if we couldn't find one to blame.
    """
    ldr = state.project.loader

    diverge_seg = ldr.find_segment_containing(load_addr)
    if diverge_seg and not diverge_seg.is_writable:
        log.warn("Read corrupted value from read-only memory!")

    # iterate over predecessors to find when value at memory address last changed
    curr_val = state.mem[load_addr].uint64_t.resolved
    log.debug("Current value: %s" % curr_val)
    for prev_state in preds[::-1]:
        if prev_state is None:
            continue

        prev_val = prev_state.mem[load_addr].uint64_t.resolved
        if not state.solver.is_true(curr_val == prev_val):
            return prev_state


def blame_load_unconstrained_val(state, preds, load_addr):
    """Try to find a state to blame for an address containing an unconstrained value.

    Keyword Args:
    state -- The state where the bad value was detected.
    preds -- The predecessors to that state.
    load_addr -- The address where the value was read from.

    Returns a state or None if we couldn't find one to blame.
    """
    ldr = state.project.loader

    # iterate over predecessors to find when memory lost its unique value
    curr_val = state.mem[load_addr].uint64_t.resolved
    for prev_state in preds[::-1]:
        if prev_state is None:
            continue

        prev_val = prev_state.mem[load_addr].uint64_t.resolved
        if not state.solver.is_true(curr_val == prev_val):
            return prev_state


def analyze_state(simgr, trace, state, report):
    # some objects we're going to reference frequently
    proj = state.project
    ldr = state.project.loader
    tech = simgr._techniques[0]

    if not state in detected_state:
        log.error("Failed to find exception %s raised" % str(state))
        return

    ex = detected_state[state]

    # get caller address of current state
    caller_addr = None
    for addr in state.history.bbl_addrs.hardcopy[::-1]:
        obj = ldr.find_object_containing(addr)
        if addr in getattr(obj, "reverse_plt", ()):
            # we don't want the PLT stub
            continue
        if state.block(addr).vex.jumpkind.startswith("Ijk_Call"):
            caller_addr = addr
            break

    if caller_addr is None:
        log.error(
            "Cannot find the caller that passed the negative parameter to the callee"
        )
        return

    # find a memory address that held the bad value
    if isinstance(ex.offset, angr.calling_conventions.SimRegArg):
        # register, we have to find where this register was loaded from
        reg_offset = state.arch.registers[ex.offset.reg_name][0]
        prev_state = ex.preds[-1]
        prev_vex = prev_state.block(prev_state.addr).vex
        assert prev_state.addr == state.history.bbl_addrs[-1]
        # find tmp that was loaded into argument register
        ld_tmp = None
        for stmt in prev_vex.statements[::-1]:
            if isinstance(stmt, pyvex.stmt.Put) and stmt.offset == reg_offset:
                ld_tmp = stmt.data.tmp
                break
        if ld_tmp is None:
            log.error("Failed to find where argument register was loaded")
            return
        log.debug("Looking for value of t%d" % ld_tmp)
        # taint ld_tmp to find which of these accesses is relevant
        tainted_tmps = {ld_tmp}
        tainted_regs = list()
        for stmt in prev_vex.statements[::-1]:
            if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
                taint.taint_irexpr(stmt.data, tainted_tmps, tainted_regs)
            elif isinstance(stmt, pyvex.stmt.Put) and stmt.offset in tainted_regs:
                taint.taint_irexpr(stmt.data, tainted_tmps, tainted_regs)
        log.debug("Tainted tmps: %s" % str(tainted_tmps))
        log.debug("Tainted regs: %s" % str(set(tainted_regs)))
        # get all memory accesses
        accesses = dict()
        for tmp, ast in taint.get_mem_accesses(
            prev_state, state, loads=True, stores=False
        ):
            accesses[tmp] = ast
        log.debug("Accesses in previous IRSB: %s" % str(accesses))
        # see if a tainted tmp is also a memory access
        bad_mem = None
        for tmp in tainted_tmps:
            if tmp in accesses:
                bad_mem = prev_state.solver.eval(accesses[tmp])
                break
        if bad_mem is None:
            log.error("Failed to find memory address argument register depends on")
            return

    elif isinstance(ex.offset, angr.calling_conventions.SimStackArg):
        # stack memory
        bad_mem = prev_state.solver.eval(state.regs.rsp) + ex.offset.stack_offset
    else:
        log.error("Unknown argument type: %s" % type(ex.offset))
        return

    # find which state last modified the bad memory
    last_val = state.mem[bad_mem].uint64_t.resolved
    if not state.solver.symbolic(last_val):
        blame_state = blame_load_concrete_val(state, ex.preds, bad_mem)
    else:
        blame_state = blame_load_unconstrained_val(state, ex.preds, bad_mem)

    if blame_state is None:
        log.error("Failed to find state to blame")
        return

    log.info(
        "Blaming %s for negative value passed to %s"
        % (ldr.describe_addr(blame_state.addr), ex.name)
    )
    report.add_detail(
        "blame",
        {
            "address": blame_state.addr,
            "description": ldr.describe_addr(blame_state.addr),
        },
    )
    report.add_detail("victim", {"address": state.addr, "description": ex.name})

    # hash for this bug based on blame and caller addresses
    blame_addr = blame_state.addr
    blame_obj = ldr.find_object_containing(blame_addr)
    if not blame_obj is None:
        blame_rva = AT.from_va(blame_addr, blame_obj).to_rva()
    else:
        blame_rva = blame_addr

    caller_obj = ldr.find_object_containing(caller_addr)
    if not caller_obj is None:
        caller_rva = AT.from_va(caller_addr, caller_obj).to_rva()
    else:
        caller_rva = caller_addr

    report.set_hash("%x" % (blame_rva ^ (caller_rva << 1)))

    if state.project.is_hooked(blame_state.addr):
        # if the blamed state is a SimProcedure, we want to also report the caller
        caller_addr = blame_state.history.bbl_addrs[-2]
        caller_desc = ldr.describe_addr(caller_addr)
        log.info("Blamed state was called by %s" % caller_desc)
        report.add_detail(
            "caller", {"address": caller_addr, "description": caller_desc}
        )


def get_call_depth(state):
    if not "call_depth" in state.globals:
        return 0
    return state.globals["call_depth"]


def check_for_vulns(simgr, proj):
    """Check for args that should never be negative being negative.

    Inspired by AddressSanitizer (negative-size-param) check.
    """
    global detected_state
    never_negative = {
        "calloc": [0, 1],
        "fread": [1, 2],
        "fwrite": [1, 2],
        "malloc": [0],
        "memcpy": [2],
        "memset": [2],
        "realloc": [1],
        "reallocarray": [1, 2],
        "strncpy": [2],
    }

    if len(simgr.stashes["active"]) < 1:
        return False

    state = simgr.stashes["active"][0]

    if state.solver.symbolic(state._ip):
        # This plugin cannot handle states with symbolic program counters
        return True

    simproc = proj.hooked_by(state.addr)
    if simproc is None:
        return True

    sym_name = simproc.display_name
    if sym_name in never_negative and get_call_depth(state) > 0:
        try:
            check_args(state, never_negative[sym_name])
        except ArgNegativeException as ex:
            log.info(
                "Arg index %d of %s is likely negative (%s): %#x"
                % (ex.idx, ex.name, str(ex), ex.value)
            )
            ex.preds = simgr._techniques[0].predecessors.copy()
            bad_state = state.copy()
            simgr.stashes["neg"].append(bad_state)
            detected_state[bad_state] = ex

    return True


detected_state = dict()
stash_name = "neg"
pretty_name = "Negative Parameter"
