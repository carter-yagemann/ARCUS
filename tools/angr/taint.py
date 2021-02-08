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

from angr.errors import *
from claripy.errors import ClaripyOperationError
import pyvex

log = logging.getLogger(name=__name__)

class TaintException(Exception):
    pass

def get_tmp_assignment(irsb, tmp):
    """Given a tmp and IRSB, return the statement that assigns the tmp its value."""
    for stmt in irsb.statements[::-1]:
        if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp == tmp:
            return stmt
    raise TaintException("Failed to find assignment of t%d" % tmp)

def _taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given an non-OP IRExpr, add any tmps or regs to the provided sets.

    This is a helper for taint_irexpr and should not be called directly.
    """
    if not tainted_regs is None and isinstance(expr, pyvex.expr.Get):
        log.debug("tainting offset=%d" % expr.offset)
        tainted_regs.append(expr.offset)
    elif isinstance(expr, pyvex.expr.RdTmp):
        log.debug("tainting t%d" % expr.tmp)
        tainted_tmps.add(expr.tmp)
    elif isinstance(expr, pyvex.expr.Load):
        taint_irexpr(expr.addr, tainted_tmps, tainted_regs)

def taint_irexpr(expr, tainted_tmps, tainted_regs=None):
    """Given an IRExpr, add any tmps or regs to the provided sets."""
    if isinstance(expr, (pyvex.expr.Qop, pyvex.expr.Triop, pyvex.expr.Binop, pyvex.expr.Unop)):
        for arg in expr.args:
            _taint_irexpr(arg, tainted_tmps, tainted_regs)
    else:
        _taint_irexpr(expr, tainted_tmps, tainted_regs)

def get_forward_ict_mem_addr(state, result):
    """Given a state that executed an indirect call or jump (forward indirect control
       transfer), return the memory address it read to derive the target address.

    Keyword Arguments:
    state -- The state prior to performing the forward ICT.
    result -- State resulting from the ICT.
    """
    irsb = state.block(state.addr).vex
    dst_expr = irsb.next
    if not isinstance(dst_expr, pyvex.expr.RdTmp):
        raise TaintException("State is not on an IRSB that executes an indirect control transfer")
    dst_tmp = dst_expr.tmp

    ld_expr = None
    ld_stmt_idx = None
    for idx, stmt in enumerate(irsb.statements[::-1]):
        if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp == dst_tmp:
            ld_expr = stmt.data
            ld_stmt_idx = len(irsb.statements) - idx - 1
            break
    if ld_expr is None:
        raise TaintException("Failed to find tmp holding memory load address")

    if isinstance(ld_expr, pyvex.expr.Load):
        # dst_tmp is a load expression like: LDle:I64(t7)
        if isinstance(ld_expr.addr, pyvex.expr.Const):
            # reads fixed memory address, we have our answer
            return ld_expr.addr.con.value
        else:
            # reads tmp, need to consult resulting state to determine what this value was
            ld_val = ld_expr.addr.tmp
    else:
        # we need to do a backwards taint to find the load tmp associated with this calculation
        ld_addrs = set()
        tainted_tmps = set()
        taint_irexpr(ld_expr, tainted_tmps)
        for stmt in irsb.statements[:ld_stmt_idx][::-1]:
            if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
                taint_irexpr(stmt.data, tainted_tmps)
                if isinstance(stmt.data, pyvex.expr.Load):
                    ld_addrs.add(stmt.data.addr)

        log.debug("Load Addresses: %s" % str(ld_addrs))

        if len(list(ld_addrs)) < 1:
            raise TaintException("Cannot find load associated with ICT")

        ld_val = list(ld_addrs)[0]
        if len(ld_addrs) > 1:
            log.warning("Multiple loads associated with target, picked: %s" % str(ld_val))

    if isinstance(ld_val, pyvex.expr.Const):
        return ld_val.con
    elif isinstance(ld_val, pyvex.expr.RdTmp):
        return result.solver.eval(result.scratch.tmp_expr(ld_val.tmp))
    else:
        return result.solver.eval(result.scratch.tmp_expr(ld_val))

def get_mem_accesses(state, result, loads=True, stores=True, include_regs=False):
    """Given a state and one of its successors, return every memory address
       data was stored and/or loaded to.

    Keyword Arguments:
    state -- The state to get loads/stores for.
    result -- The resulting state to extract ASTs from.
    loads -- Whether to return loads.
    stores -- Whether to return stores.
    include_regs -- Whether to include register operations (Put/Get) too.

    Returns:
    A list of (tmp #, AST) tuples.
    """
    try:
        irsb = state.block(state.addr).vex
    except SimEngineError:
        return list()  # couldn't get a block, likely address is unmapped

    accessed_mems = list()
    tmps2eval = set()

    for stmt in irsb.statements[::-1]:
        # Store
        if stores and isinstance(stmt, pyvex.stmt.Store):
            if isinstance(stmt.addr, pyvex.expr.Const):
                accessed_mems.append((None, stmt.addr.con.value))  # direct write
            else:
                tmps2eval.add(stmt.addr.tmp)
        # WrTmp
        elif isinstance(stmt, pyvex.stmt.WrTmp):
            # Load
            if loads and isinstance(stmt.data, pyvex.expr.Load):
                ld_expr = stmt.data
                if isinstance(ld_expr.addr, pyvex.expr.Const):
                    accessed_mems.append((None, ld_expr.addr.con.value))  # direct read
                else:
                    tmps2eval.add(ld_expr.addr.tmp)
            # Get
            elif loads and include_regs and isinstance(stmt.data, pyvex.expr.Get):
                accessed_mems.append((None, stmt.data.offset))
        # Put
        elif stores and include_regs and isinstance(stmt, pyvex.stmt.Put):
            accessed_mems.append((None, stmt.offset))

    log.debug("resolving accesses: {%s}" % ','.join(['t%d' % tmp for tmp in tmps2eval]))

    for tmp in tmps2eval:
        try:
            ast = result.scratch.tmp_expr(tmp)
        except SimValueError:
            log.debug("Failed to find t%d in resulting state" % tmp)
            continue
        accessed_mems.append((tmp, ast))

    return accessed_mems

def is_cond_branch(irsb):
    """Returns true if IRSB contains a conditional branch."""
    return True in [isinstance(stmt, pyvex.stmt.Exit) for stmt in irsb.statements]

def get_cond_exit_mem_addr(state, result):
    """Given a state on an IRSB with a conditional exit, return a list of memory address that
    the exit depends on. List may be empty.

    Keyword Arguments:
    state -- The state immediately before the conditional exit was taken.
    result -- The state immediately after.
    """
    irsb = state.block(state.addr).vex

    # find last exit statement
    exit_stmt = None
    for stmt in irsb.statements[::-1]:
        if isinstance(stmt, pyvex.stmt.Exit):
            exit_stmt = stmt
            break
    if exit_stmt is None:
        raise TaintException("Failed to find an exit statement to analyze")

    exit_expr = exit_stmt.guard
    assert isinstance(exit_expr, pyvex.expr.RdTmp)

    # find all tmps associated with this guard
    tainted_tmps = set()
    taint_irexpr(exit_expr, tainted_tmps)
    for stmt in irsb.statements[::-1]:
        if isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp in tainted_tmps:
            taint_irexpr(stmt.data, tainted_tmps)

    # tmps from tainted_tmps assigned a value loaded from memory
    load_tmps = set()
    for tmp in tainted_tmps:
        wrtmp = get_tmp_assignment(irsb, tmp)
        if isinstance(wrtmp.data, pyvex.expr.Load):
            load_tmps.add(tmp)

    log.debug("assigned value from mem: {%s}" % ','.join(['t%d' % tmp for tmp in load_tmps]))

    # resolve load addresses (not what was read from those addresses)
    load_mems = set()
    for tmp in load_tmps:
        ld_stmt = get_tmp_assignment(irsb, tmp)              # e.g., t2 = LDle:I64(t8)
        ld_expr = ld_stmt.data                               # e.g., LDle:I64(t8)
        if isinstance(ld_expr.addr, pyvex.expr.Const):
            load_mems.add(ld_expr.addr.con.value)            # reads fixed memory address
        else:
            ld_tmp = ld_expr.addr.tmp                        # e.g., t8
            try:
                result_expr = result.scratch.tmp_expr(ld_tmp)
            except SimValueError:
                log.warning("Failed to find t%d in resulting state" % ld_tmp)
                continue

            load_mems.add(result.solver.eval(result_expr))

    log.debug("load addrs: {%s}" % ','.join([hex(addr) for addr in load_mems]))

    return list(load_mems)

def infer_function_prototype(state, func_path):
    """Infers the prototype of a function.

    Keyword Arguments:
    state -- The first state at the start of a function.
    func_path -- A list of basic block addresses representing a single path through
                 the function. Analysis will stop upon seeing a return instruction
                 or reaching the end of the list.

    Returns:
    A prototype list, see analysis.py:symbolize_api for format details.
    """
    reg_reads = set()
    special_regs = [state.arch.ip_offset, state.arch.sp_offset,
                    state.arch.bp_offset, state.arch.lr_offset]
    clobbered = set([reg for reg in special_regs if isinstance(reg, int)])
    stack_boundary = state.solver.eval(state.registers.load(state.arch.sp_offset))

    log.debug("Starting function prototype inference")

    # infer number of arguments by looking for un-clobbered reads
    # (roughly inspired by "scat: Learning from a Single Execution of a Binary"
    #  by Goër, et al.)
    for addr in func_path:
        try:
            irsb = state.block(addr).vex
        except SimEngineError:
            log.warning("Failed to lift block at %#x" % addr)
            break

        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.Put):
                if not stmt.offset in clobbered:
                    if stmt.offset in state.arch.register_names:
                        offset_name = state.arch.register_names[stmt.offset]
                    else:
                        offset_name = str(stmt.offset)
                    log.debug("%s is clobbered" % offset_name)
                    clobbered.add(stmt.offset)
            elif isinstance(stmt, pyvex.stmt.WrTmp):
                if isinstance(stmt.data, pyvex.expr.Get):
                    offset = stmt.data.offset
                    if not offset in clobbered and offset in state.arch.register_names:
                        log.debug("%s is a parameter" % state.arch.register_names[stmt.data.offset])
                        reg_reads.add(stmt.data.offset)

            # TODO - Parameters passed via stack

        if irsb.jumpkind.startswith("Ijk_Ret"):
            log.debug("Reached return basic block, stopping")
            break

    # infer type of each argument (also inspired by Goër, et al.)
    args = list()
    for offset in reg_reads:
        starting_val = state.solver.eval(state.registers.load(offset))
        section = state.project.loader.find_section_containing(starting_val)
        val_size = None
        if starting_val in func_path:
            # value matches the address of an executed basic block,
            # very likely a code pointer
            val_type = 'Ptr_Code'
        elif not section is None:
            if section.is_executable:
                val_type = 'Ptr_Code'
            else:
                val_type = 'Ptr_Data'
        elif starting_val > state.project.loader.max_addr:
            # likely pointing somewhere on the original stack
            val_type = 'Ptr_Data'
        else:
            val_type = 'Int'
            val_size = state.arch.bits

        args.append({'value_type': val_type, 'value_data': None, 'value_size': val_size,
                     'offset_type': 'Register', 'offset': offset})

    # some debug info
    pp_args = list()
    for arg_dict in args:
        offset = arg_dict['offset']
        val_type = arg_dict['value_type']
        if offset in state.arch.register_names:
            offset_str = state.arch.register_names[offset]
        else:
            offset_str = hex(offset)
        pp_args.append('%s (%s)' % (val_type, offset_str))
    log.debug("Prototype (arbitrary order): func(%s)" % (', '.join(pp_args)))

    return args
