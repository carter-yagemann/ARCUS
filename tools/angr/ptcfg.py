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

import angr
from angr.analyses.cfg import CFGEmulated
import networkx
import pyvex
import xed

def prune_cfg(cfg, pt):
    """Prune an Angr CFG using a PT trace. pt can be a path to a GRIFFIN
       file or a list of basic block addresses.

    This method modifies cfg directly. The resulting graph will contain
    only nodes that appear in the trace.

    Returns a list of nodes that were pruned.
    """
    if isinstance(pt, str):
        blocks = xed.disasm_pt_file(pt)
    elif isinstance(pt, list):
        blocks = pt
    else:
        raise ValueError("pt must be a filepath or list of basic block addresses")

    block_addrs = set(blocks)
    pruned_nodes = list()

    # first pass: normal nodes that do not appear in the trace
    for node in cfg.graph.nodes():
        if not node.addr in block_addrs and not node.is_syscall and not node.is_simprocedure:
            # cannot remove a node while iterating
            pruned_nodes.append(node)

    for node in pruned_nodes:
        cfg.graph.remove_node(node)

    # second pass: syscall and simp nodes that have lost all their predecessors
    for node in cfg.graph.nodes():
        if node.is_syscall or node.is_simprocedure:
            # predecessors list isn't updated when a node is removed from the CFG
            # also self references don't count
            preds = [pred for pred in node.predecessors if not pred in pruned_nodes and pred != node]
            if len(preds) == 0:
                pruned_nodes.append(node)

    for node in pruned_nodes:
        # already removed normal nodes
        if node.is_syscall or node.is_simprocedure:
            cfg.graph.remove_node(node)

    return pruned_nodes

class BasicNode(object):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

def cfg_from_trace(addrs, project, cfg_args={}):
    """Create a CFGEmulated that represents a single linear trace.

    Keyword Args:
    addrs -- A list of basic block addresses representing the linear path followed
             by a trace.
    project -- An Angr project from which to create the CFG.
    cfg_args -- A dictionary of kwargs to pass to CFGEmulated.

    Returns:
    A CFGEmulated object.
    """
    # create a basic graph where each address in addrs is a node and edges only
    # exist between each address and its successor address in the list
    base_graph = networkx.DiGraph()
    nodes = dict()
    prev_addr = None
    for addr in addrs:
        if not addr in nodes:
            # factory will perform lifting and figure out the block's size, which is
            # required by CFGEmulated
            block = project.factory.block(addr)
            nodes[addr] = BasicNode(addr, block.size)
            base_graph.add_node(nodes[addr])
        if prev_addr:
            base_graph.add_edge(nodes[prev_addr], nodes[addr])
        prev_addr = addr

    # sanity check
    assert(base_graph.number_of_nodes() == len(set(addrs)))

    # keep_state and state_add_options are set according to
    # the Angr docs so this CFG can be used to generate a DDG:
    #
    #     https://docs.angr.io/built-in-analyses/backward_slice
    #
    return project.analyses.CFGEmulated(address_whitelist=addrs,
                                        base_graph=base_graph,
                                        keep_state=True,
                                        state_add_options=angr.sim_options.refs,
                                        **cfg_args)

def slice2str(bb_seq, slice, curr_obj_only=False):
    """Given a sequence of basic blocks (i.e. a trace) and a slice, returns a
       multi-line string containing the sequence of statements leading up to
       the slice target.

    Compared to BackwardSlice's dbg_repr, this representation:
        1) Does not print irrelevant statements, even if they're in the same
        "IMark" as a relevant statement.
        2) Prints the statements in order based on hte trace, not as a list
        sorted by address.

    Keyword Args:
    bb_seq -- A sequence of basic block addresses representing a trace.
    slice -- A BackwardSlice object.
    curr_obj_only -- Only include statements that are in the same object as
    the last address in bb_seq.

    Returns a string.
    """
    if curr_obj_only:
        curr_obj = slice.project.loader.find_object_containing(bb_seq[-1])
        addr_range = (curr_obj.min_addr, curr_obj.max_addr)
    else:
        addr_range = None

    stmt_strs = list()
    for addr in bb_seq:
        if curr_obj_only and (addr < addr_range[0] or addr > addr_range[1]):
            continue  # filtered
        if not addr in slice.chosen_statements.keys():
            continue

        if slice.project.is_hooked(addr):
            stmt_strs.append("+[  0] ------ SimProcedure(%#x) ------" % addr)
        else:
            chosen_stmts = slice.chosen_statements[addr]
            vex_block = slice.project.factory.block(addr).vex
            for i, stmt in enumerate(vex_block.statements):
                if i in chosen_stmts:
                    stmt_strs.append("+[% 3d] %s" % (i, str(stmt)))
                elif isinstance(stmt, pyvex.stmt.IMark):
                    stmt_strs.append(" [% 3d] ------ IMark(%s, %d, %d) ------" % (i,
                            slice.project.loader.describe_addr(stmt.addr), stmt.len,
                            stmt.delta))

    # cleanup: remove IMarks with no chosen statements
    last_stmt_idx = len(stmt_strs) - 1
    stmt_strs_filtered = list()
    for idx, stmt in enumerate(stmt_strs):
        if idx == last_stmt_idx and 'IMark' in stmt:
            continue  # If the last statement is an IMark, it's empty
        elif idx != last_stmt_idx and 'IMark' in stmt and 'IMark' in stmt_strs[idx + 1]:
            continue  # IMark is empty if it's followed by another IMark
        else:
            stmt_strs_filtered.append(stmt)

    return "\n".join(stmt_strs_filtered)
