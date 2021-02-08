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
import os

import angr
import claripy
from cle.address_translator import AT
import pyvex

import dwarf

log = logging.getLogger(__name__)
watching = 'int_ovf_watching'
detection = 'int_ovf_detection'
# Universally unique tags
tag = 0
tag2addr = dict()

def watching_add(state, key, val):
    if not watching in state.deep:
        state.deep[watching] = dict()
    state.deep[watching][key] = val

def watching_remove(state, key):
    if watching in state.deep:
        del state.deep[watching][key]

def pp_stmt(stmt, temps, tmp_idxs):
    msg = str(stmt)
    for idx in tmp_idxs:
        msg = msg.replace("t%d" % idx, str(temps[idx]))
    return msg

def smallest_type(val):
    """Returns the smallest bitvector type that could store this value.

    Example: smallest_type(7) returns 8, smallest_type(1234) returns 16.
    """
    for size in [8, 16, 32, 64, 128, 256, 512, 1024]:
        if val < 2**size:
            return size
    return 8

def get_capstone_from_vex(vex, stmt_idx):
    """Given the index for a vex statement, return the corresponding capstone index."""
    slice = vex.statements[:stmt_idx]
    insns = 0
    for stmt in slice[::-1]:
        if isinstance(stmt, pyvex.stmt.IMark):
            insns += 1
    return insns - 1

def analyze_state(simgr, trace, state, report):
    ldr = state.project.loader

    # get caller address of current state
    caller_addr = None
    for addr in state.history.bbl_addrs.hardcopy[::-1]:
        obj = ldr.find_object_containing(addr)
        if addr in getattr(obj, 'reverse_plt', ()):
            # we don't want the PLT stub
            continue
        if state.block(addr).vex.jumpkind.startswith('Ijk_Call'):
            caller_addr = addr
            break

    if caller_addr is None:
        log.error("Cannot find the caller that passed the bad parameter to the callee")
        return

    # we already know where the under/overflow occurred, report it!
    blame_addr, blame_idx = state.globals[detection]
    stmt = state.block(blame_addr).vex.statements[blame_idx]

    log.info("Blaming '%s' in block %s for passing over/underflowed "
             "argument to %s, called by %s" % (str(stmt), ldr.describe_addr(blame_addr),
             ldr.describe_addr(state.addr), ldr.describe_addr(caller_addr)))
    report.add_detail('blame', {'address': blame_addr,
                                'description': ldr.describe_addr(blame_addr),
                                'callsite': ldr.describe_addr(caller_addr),
                                'VEX_IR': str(stmt)})

    # unique hash for this bug based on the overflow site and recipient
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

    report.set_hash('%x' % (blame_rva ^ (caller_rva << 1)))

    # report details for DARPA-AIE-AIMEE-HECTOR project
    aimee_details = list()

    for addr, label in [(blame_addr, "overflowed_variable"),
            (caller_addr, "overflowed_call")]:
        ovf_obj = ldr.find_object_containing(addr)
        if not ovf_obj is None:
            ovf_name = os.path.basename(ovf_obj.binary)
            try:
                dwarfinfo = dwarf.DwarfDebugInfo(ovf_obj.binary)
                ovf_rva = AT.from_va(addr, ovf_obj).to_rva()
                ovf_filename, ovf_line = dwarfinfo.get_src_line(ovf_rva)
                aimee_details.append({'object': ovf_name, 'file': ovf_filename,
                    'line': ovf_line, 'label': label})
            except DwarfException:
                continue

    if len(aimee_details) > 0:
        report.add_detail('aimee', aimee_details)

def _taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given an non-OP IRExpr, add any tmps or regs to the provided sets.

    This is a helper for taint_irexpr and should not be called directly.
    """
    if not tainted_regs is None and isinstance(expr, pyvex.expr.Get):
        tainted_regs.append(expr.offset)
    elif isinstance(expr, pyvex.expr.RdTmp):
        tainted_tmps.add(expr.tmp)
    # unlike taint.py's taint_irexpr, we don't taint beyond load expressions

def taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given an IRExpr, add any tmps or regs to the provided sets."""
    if isinstance(expr, (pyvex.expr.Qop, pyvex.expr.Triop, pyvex.expr.Binop, pyvex.expr.Unop)):
        for arg in expr.args:
            _taint_irexpr(arg, tainted_tmps, tainted_regs)
    else:
        _taint_irexpr(expr, tainted_tmps, tainted_regs)

def get_regs(irsb, idx):
    """Returns all registers associated with the WrTmp statement at idx in irsb."""
    wrtmp = irsb.statements[idx]
    stmts = irsb.statements[:idx + 1]  # all dependencies should come before WrTmp statement

    tainted_tmps = {wrtmp.tmp}
    tainted_regs = list()

    for stmt in stmts[::-1]:
        if isinstance(stmt, pyvex.stmt.Put) and isinstance(stmt.data, pyvex.expr.RdTmp):
            if stmt.data.tmp in tainted_tmps:
                tainted_regs.append(stmt.offset)
        elif isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
            taint_irexpr(stmt.data, tainted_tmps, tainted_regs)

    return set(tainted_regs)

def get_tmps(irsb, idx):
    """Returns all tmps associated with the Put statement at idx in irsb."""
    put = irsb.statements[idx]
    stmts = irsb.statements[:idx + 1]  # all dependencies should come before statement

    tainted_tmps = set()
    taint_irexpr(put.data, tainted_tmps)

    for stmt in stmts[::-1]:
        if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
            taint_irexpr(stmt.data, tainted_tmps)

    return tainted_tmps

def check_tmp(state, stmt, output, input, check_over=False, check_under=False):
    tmps = state.scratch.temps
    if len(tmps) < output or len(tmps) < input:
        return False
    if tmps[output] is None or tmps[input] is None:
        return False

    try:
        if check_over and state.solver.satisfiable(extra_constraints=[tmps[output] < tmps[input]]):
            log.debug("Overflow: %s" % pp_stmt(stmt, tmps, [input, output]))
            return True
    except claripy.errors.ClaripyOperationError:
        log.warning("Claripy solver error while checking for overflow")

    try:
        # TODO - Heuristic: we're guessing the size of the bitvectors
        if check_over and smallest_type(state.solver.max(tmps[output])) > smallest_type(state.solver.max(tmps[input])):
            log.debug("Overflow: %s" % pp_stmt(stmt, tmps, [input, output]))
            return True
    except claripy.errors.ClaripyOperationError:
        log.warning("Claripy solver error while checking for underflow")

    try:
        if not check_over and state.solver.satisfiable(extra_constraints=[tmps[output] > tmps[input]]):
            log.debug("Underflow: %s" % pp_stmt(stmt, tmps, [input, output]))
            return True
    except claripy.errors.ClaripyOperationError:
        log.warning("Claripy solver error while checking for underflow")

    return False

def _get_tmp_arg(state, tmps, arg):
    if isinstance(arg, pyvex.expr.Const):
        return arg.con.value
    elif len(tmps) <= arg.tmp:
        return None
    else:
        try:
            return state.solver.eval(tmps[arg.tmp])
        except:
            return None

def check_tmp_mul(state, stmt, output, args):
    tmps = state.scratch.temps
    tmp_a = _get_tmp_arg(state, tmps, args[0])
    tmp_b = _get_tmp_arg(state, tmps, args[1])

    if tmp_a is None or tmp_b is None:
        return False

    res = tmp_a * tmp_b

    # TODO - Heuristic: we're guessing the size of the bitvectors
    if smallest_type(res) > min(smallest_type(tmp_a), smallest_type(tmp_b)):
        return True

    return False

def check_hooked(simgr, proj, curr_state):
    global tag2addr

    # check for args read from watched registers or memory
    simproc = curr_state.project.hooked_by(curr_state.addr)
    if simproc.cc is None:
        return True
    try:
        # TODO - FormatParser is a subclass of SimProcedure with a misleading simproc.num_args value
        arg_locs = simproc.cc.arg_locs(is_fp=[False] * simproc.num_args)
        log.debug("Arg Locations: %s" % str(arg_locs))
        for loc in arg_locs:
            if isinstance(loc, angr.calling_conventions.SimRegArg):
                offset = curr_state.arch.registers[loc.reg_name][0]
            elif isinstance(loc, angr.calling_conventions.SimStackArg):
                offset = curr_state.solver.eval(curr_state.regs.rsp) + loc.stack_offset
            else:
                log.error("Unknown argument type: %s" % type(loc))
                continue

            if watching in curr_state.deep and offset in curr_state.deep[watching]:
                blame_tag = curr_state.deep[watching][offset]
                blame_addr, blame_idx = tag2addr[blame_tag]
                log.warn("Under/Overflowed argument passed to function")
                curr_state.globals[detection] = (blame_addr, blame_idx)
                simgr.stashes['int'].append(curr_state.copy())
                return True

    except angr.errors.SimUnsatError:
        return True

    return True

def _tag_tmp(blown_tmps, tmp, addr, stmt_idx):
    global tag, tag2addr
    log.debug("Creating tag: %d" % tag)
    blown_tmps[tmp] = tag
    tag2addr[tag] = (addr, stmt_idx)
    tag += 1

def _get_tag(blown_tmps, tmps):
    tags = set()
    for tmp in tmps:
        if tmp in blown_tmps:
            tags.add(blown_tmps[tmp])
    assert len(tags) > 0
    if len(tags) > 1:
        log.warning("Operation depends on multiple overflowed tmps, picking oldest tag")
    return min(tags)

def pp_reg_offset(state, offset):
    reg_names = state.arch.register_names
    if offset in reg_names:
        return "%d (%s)" % (offset, reg_names[offset])
    else:
        return "%d (N/A)" % offset

def check_for_vulns(simgr, proj):
    if len(simgr.stashes['active']) < 1:
        return False

    # get current and previous states
    curr_state = simgr.stashes['active'][0]

    if curr_state.solver.symbolic(curr_state._ip):
        # This plugin cannot handle states with symbolic program counters
        return True

    sym_obj = proj.loader.find_symbol(curr_state.addr, fuzzy=True)
    if not sym_obj is None and sym_obj.name == '__libc_start_main.after_main':
        return True

    if len(simgr._techniques[0].predecessors) > 0:
        prev_state = simgr._techniques[0].predecessors[-1]
    else:
        prev_state = None  # no previous states

    # are we in a state that can't/shouldn't be checked?
    if prev_state is None:
        return True  # first state in analysis
    if curr_state.history.bbl_addrs[-1] != prev_state.addr:
        return True  # can happen if a state fails to step
    prev_obj = prev_state.project.loader.find_object_containing(prev_state.addr)
    if prev_obj is None or prev_obj is prev_state.project.loader.extern_object:
        return True

    # we can analyze, check basic block for blown (over or underflown) bitvectors
    block = prev_state.block(prev_state.addr)
    vex = block.vex
    cap = block.capstone

    rbp_off = prev_state.arch.registers['rbp'][0]
    rsp_off = prev_state.arch.registers['rsp'][0]

    tmps = curr_state.scratch.temps
    blown_tmps = dict()  # tmps that are over or underflowed, value is a tag
    for idx, stmt in enumerate(vex.statements):
        if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop):
            # check if binop is arithmetic that can over/underflow and if so, detect any blown tmps
            if not isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
                continue  # not a tmp
            regs = get_regs(vex, idx)
            if rbp_off in regs or rsp_off in regs:
                continue  # rsp and rbp manipulations are always lifted into overflowing statements

            mnemonic = cap.insns[get_capstone_from_vex(vex, idx)].mnemonic
            if mnemonic.startswith('add') and (stmt.data.op.startswith('Iop_Add') or stmt.data.op.startswith('Iop_Shl')):
                if check_tmp(curr_state, stmt, stmt.tmp, stmt.data.args[0].tmp, check_over=True):
                    _tag_tmp(blown_tmps, stmt.tmp, prev_state.addr, idx)
                    log.debug("t%d is overflowed" % stmt.tmp)
            elif mnemonic.startswith('sub') and (stmt.data.op.startswith('Iop_Sub') or stmt.data.op.startswith('Iop_Shr')):
                if check_tmp(curr_state, stmt, stmt.tmp, stmt.data.args[0].tmp, check_under=True):
                    _tag_tmp(blown_tmps, stmt.tmp, prev_state.addr, idx)
                    log.debug("t%d is underflowed" % stmt.tmp)
            elif mnemonic.startswith('imul') and stmt.data.op.startswith('Iop_Mul'):
                if check_tmp_mul(curr_state, stmt, stmt.tmp, stmt.data.args):
                    _tag_tmp(blown_tmps, stmt.tmp, prev_state.addr, idx)
                    log.debug("t%d is overflowed (Multiplication)" % stmt.tmp)

        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Load):
            # if a tmp is given a value loaded from an address that is storing a blown tmp,
            # this tmp is also blown
            if isinstance(stmt.data.addr, pyvex.expr.RdTmp):
                if len(tmps) < stmt.data.addr.tmp:
                    continue
                if tmps[stmt.data.addr.tmp] is None:
                    continue
                mem_addr = curr_state.solver.eval(tmps[stmt.data.addr.tmp])
            else:  # constant
                mem_addr = stmt.data.addr.con

            if watching in curr_state.deep and mem_addr in curr_state.deep[watching]:
                log.debug("t%d loaded watched address %#x" % (stmt.tmp, mem_addr))
                blown_tmps[stmt.tmp] = curr_state.deep[watching][mem_addr]

        elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Get):
            # if a tmp is given a value loaded from a blown register, the tmp is blown
            if watching in curr_state.deep and stmt.data.offset in curr_state.deep[watching]:
                log.debug("t%d loaded watched register: %s" % (stmt.tmp,
                        pp_reg_offset(curr_state, stmt.data.offset)))
                blown_tmps[stmt.tmp] = curr_state.deep[watching][stmt.data.offset]

        elif isinstance(stmt, pyvex.stmt.Put):
            # if a blown tmp is put into a register, the register is blown, otherwise
            # it's now clean
            dep_tmps = get_tmps(vex, idx)
            if len(blown_tmps) > 0:
                log.debug("Put depends on: %s, Blown tmps: %s" % (str(dep_tmps), str(blown_tmps)))
            if len(dep_tmps & set(blown_tmps.keys())) > 0:
                log.debug("Watching: %s" % pp_reg_offset(curr_state, stmt.offset))
                watch_tag = _get_tag(blown_tmps, dep_tmps)
                watching_add(curr_state, stmt.offset, watch_tag)
            elif watching in curr_state.deep and stmt.offset in curr_state.deep[watching]:
                log.debug("Clearing: %s" % pp_reg_offset(curr_state, stmt.offset))
                watching_remove(curr_state, stmt.offset)

        elif isinstance(stmt, pyvex.stmt.Store):
            # if a blown tmp is being stored to memory, that address is now blown, otherwise
            # it's now clean
            if isinstance(stmt.addr, pyvex.expr.RdTmp):
                if stmt.addr.tmp >= len(tmps):
                    continue
                if tmps[stmt.addr.tmp] is None:
                    continue
                mem_addr = curr_state.solver.eval(tmps[stmt.addr.tmp])
            else:  # constant
                mem_addr = stmt.addr.con.value

            dep_tmps = get_tmps(vex, idx)
            if len(blown_tmps) > 0:
                log.debug("Store depends on: %s" % str(dep_tmps))
            if len(dep_tmps & set(blown_tmps.keys())) > 0:
                log.debug("Watching %#x" % mem_addr)
                watch_tag = _get_tag(blown_tmps, dep_tmps)
                watching_add(curr_state, mem_addr, watch_tag)
            elif watching in curr_state.deep and mem_addr in curr_state.deep[watching]:
                log.debug("Clearing %#x" % mem_addr)
                watching_remove(curr_state, mem_addr)

    # check if current state is receiving an over/underflowed argument
    if curr_state.project.is_hooked(curr_state.addr):
        return check_hooked(simgr, proj, curr_state)

    # TODO - We currently do not know how to handle unhooked calls because
    # it's hard to infer how many arguments are being passed.

    # TODO - Handle return

    return True

stash_name = 'int'
pretty_name = 'Integer Over/Underflow'
