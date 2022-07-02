#!/usr/bin/env python
#
# Copyright 2019 Matthew Pruett
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

import sys
import angr
import IPython
import networkx as nx
from copy import deepcopy
from angr.sim_variable import SimRegisterVariable
from angr.analyses.code_location import CodeLocation
import pyvex


def getStmtId(project, address):
    # Get vex representation of block
    bb_vex = project.factory.block(address, opt_level=0).vex
    bb_vex.pp()

    # Get the stmt id of the statement beyond the last
    return len(bb_vex.statements)


def getTempTypes(stmt_list, irsb):
    # NOTE: Not implemented
    temps = set()

    # Determine which temps are in written to in slice
    for stmt in stmt_list:
        if isinstance(stmt, pyvex.ITStmt.WrTmp):
            temps.add(stmt.tmp)

    # Get types of temps used


def find_sim_proc_node(cl, graph):
    sim_proc_node = None
    for node in graph:
        if str(node) == str(cl):
            sim_proc_node = node
    return sim_proc_node


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python slicer.py program_name target_address")

    # Load project
    program = "toybox-cfi/bin/" + sys.argv[1]
    p = angr.Project(program, load_options={"auto_load_libs": False})

    # Create CFG and DDG
    cfg = p.analyses.CFGEmulated(
        keep_state=True,
        state_add_options=angr.sim_options.refs,
        context_sensitivity_level=2,
        iropt_level=0,
    )
    ddg = p.analyses.DDG(cfg)

    # Set target address and node
    target_addr = int(sys.argv[2], 16)
    target_node = cfg.get_any_node(target_addr, anyaddr=True)
    print(target_node)
    stmtId = getStmtId(p, target_node.addr)
    print("stmtId: " + str(stmtId))

    # Get data dependency predicates
    cl = CodeLocation(target_node.addr, stmtId)

    dep_graph = ddg.graph

    # Create pruned DDG
    pruned_ddg = deepcopy(dep_graph)

    print("\n\nRemoving nodes...\n\n")

    # Remove rbp and rsp related edges
    rbp = SimRegisterVariable(56, 8)
    rsp = SimRegisterVariable(48, 8)

    for src, dst, data in dep_graph.edges(data=True):
        if data["type"] == "reg":
            if data["data"] == rbp or data["data"] == rsp:
                # Remove edge
                if src.sim_procedure is not None:
                    src = find_sim_proc_node(src, pruned_ddg)
                if dst.sim_procedure is not None:
                    dst = find_sim_proc_node(dst, pruned_ddg)
                pruned_ddg.remove_edge(src, dst)

    # Prune DDG to remove non-dependency nodes
    all_preds = nx.ancestors(dep_graph, cl)
    all_preds.add(cl)

    for node in dep_graph:
        if node not in all_preds:
            # Equality check does not work for copies of
            # CodeLocations that represent SimProcedures
            if node.sim_procedure is not None:
                to_prune = find_sim_proc_node(node, pruned_ddg)
                pruned_ddg.remove_node(to_prune)
            else:
                pruned_ddg.remove_node(node)

    # Get final dependency list
    # TODO: Remove vex at target address
    final_deps = nx.ancestors(pruned_ddg, cl)

    print("Dependencies of " + str(cl) + ":")
    for dep in final_deps:
        print(dep)

    slice_stmts = []

    tyenv = None

    print("")
    # TODO: Fix sorting for more complicated programs
    for dep in sorted(final_deps, key=lambda x: x.stmt_idx):
        irsb = p.factory.block(dep.block_addr, opt_level=0).vex
        tyenv = irsb.tyenv
        stmt = irsb.statements[dep.stmt_idx]
        slice_stmts.append(stmt)
        stmt.pp()
    print("")

    # Create new state
    slice_state = p.factory.blank_state()

    # New IRSB
    # Not sure about address
    custom_irsb = pyvex.IRSB.empty_block(
        p.arch, 0x500000, statements=slice_stmts, size=len(slice_stmts)
    )

    # Make tyenv from previous tyenv data
    # If there is a type mismatch. Just raise exception now
    # This can be dealt with if necessary later on by splitting
    # the IRSB into multiple IRSBs or with temp renaming
    custom_irsb.tyenv = tyenv

    # Need to whitelist all statements if no exit specified
    whitelist = list(range(len(slice_stmts)))

    # Custom stepping with new IRSB
    final_state = slice_state.step(irsb=custom_irsb, whitelist=whitelist)

    # Insert next steps here

    IPython.embed()


if __name__ == "__main__":
    main()
