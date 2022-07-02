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
from networkx.algorithms.shortest_paths.generic import shortest_path_length

import angrpt
import taint
import ptcfg

log = logging.getLogger(__name__)

# TODO - Entire plugin is hardcoded for 64-bit code pointers (uint64_t), replace
#        with arch independent types.


def is_plt(ldr, addr):
    """Returns True if addr is the start of a PLT."""
    obj = ldr.find_object_containing(addr)
    if obj and addr in getattr(obj, "reverse_plt", ()):
        return True
    return False


def find_node(graph, state):
    """Finds the correct node that represents the provided state."""
    sense = graph.context_sensitivity_level
    prev_addrs = state.history.bbl_addrs.hardcopy[::-1][:sense]
    # graph could be missing edges for various reasons, so we'll do a best
    # effort search
    match_node = None
    match_len = 0
    for node in graph.model.get_all_nodes(state.addr):
        curr_len = 0
        curr_node = node
        for idx in range(sense):
            next = [
                pred
                for pred in graph.get_predecessors(curr_node)
                if pred.addr == prev_addrs[idx]
            ]
            if len(next) > 0:
                curr_node = next[0]
                curr_len += 1
            else:
                break

        if curr_len > match_len:
            match_node = node
            match_len = curr_len

    log.debug("find_node: best match len = %d" % match_len)
    return match_node


def analyze_blame(simgr, blame_state, report):
    """Try to figure out the root cause behind a blamed state's behavior.

    Keyword Args:
    simgr -- A simulation manager.
    blame_state -- The state to analyze.
    report -- reporting.BugReport
    """
    # some objects we're going to reference frequently
    proj = blame_state.project
    ldr = blame_state.project.loader
    tech = simgr._techniques[0]

    blame_addr = blame_state.addr
    blame_irsb = blame_state.block(blame_addr).vex
    blame_idx = [
        idx for idx, pred in enumerate(tech.predecessors) if pred == blame_state
    ][0]

    log.info("Analyzing root cause for behavior of %s" % ldr.describe_addr(blame_addr))
    log.debug("Blamed IRSB:\n%s" % str(blame_irsb))

    pred_states = [state for state in tech.predecessors if not state is None]
    pred_addrs = [state.addr for state in pred_states]
    assert blame_addr in pred_addrs

    # find existing (negligent) guardians for blamed IRSB
    log.debug("Creating partial CFG...")
    partial_cfg = ptcfg.cfg_from_trace(
        pred_addrs, proj, cfg_args={"initial_state": pred_states[0]}
    )
    blame_node = find_node(partial_cfg, blame_state)
    log.debug("Creating partial CDG...")
    partial_cdg = proj.analyses.CDG(partial_cfg)
    existing_guards = partial_cdg.get_guardians(blame_node)

    # filter out guardians that are SimProcedures
    existing_guards = [guard for guard in existing_guards if not guard.is_simprocedure]
    log.debug("Existing Guardians: %s" % str(existing_guards))
    log.debug("Found %d guardians" % len(existing_guards))

    if len(existing_guards) > 0:
        # pick closest guardian
        if len(existing_guards) == 1:
            # only one choice, no need to waste time computing a shortest path length
            failed_guard = existing_guards[0]
        else:
            # pick the guaridan closest to the blamed node
            curr_closest = (None, -1)
            for guard in existing_guards:
                dist = shortest_path_length(partial_cfg.graph, guard, blame_node)
                log.debug("Distance from %s to blamed node: %d" % (str(guard), dist))
                if curr_closest[0] is None or dist < curr_closest[1]:
                    curr_closest = (guard, dist)
            log.debug(
                "Picking %s with distance %d" % (str(curr_closest[0]), curr_closest[1])
            )
            failed_guard = curr_closest[0]
    else:
        # TODO - What do we do if no guardians exist? (e.g. bad string passed to strcpy)
        #
        # This is most likely to happen with simulated functions because the simulation
        # masks the function's internal logic and thus may hide control dependencies. The
        # next best thing we can do is blame an argument passed to the function, at which
        # point our analysis becomes the same as that performed by the "large allocation"
        # plugin.
        #
        # That plugin isn't finished yet, so for now we bail.
        if proj.is_hooked(blame_addr):
            pred_idx = blame_idx - 1
            pred = None
            while pred_idx >= 0:
                curr_state = tech.predecessors[pred_idx]
                if curr_state and not is_plt(ldr, curr_state.addr):
                    pred = ldr.describe_addr(curr_state.addr)
                    break
                pred_idx -= 1

            report_details = {
                "type": "input_validation",
                "callee": {
                    "address": blame_state.addr,
                    "description": ldr.describe_addr(blame_state.addr),
                },
            }
            if pred:
                log.info(
                    "Recommendation: Verify the parameters passed to %s by %s"
                    % (str(blame_node), pred)
                )
                report_details["caller"] = {
                    "address": curr_state.addr,
                    "description": pred,
                }
            else:
                log.info(
                    "Recommendation: Verify the parameters passed to %s"
                    % (str(blame_node))
                )

            # print parameters passed to simprocedure
            simproc = proj.hooked_by(blame_addr)
            state_args = simproc.cc.get_args(blame_state, simproc.prototype)
            sim_args = list()
            report_details["parameters"] = list()
            for idx in range(simproc.num_args):
                try:
                    arg = state_args[idx]
                    arg_min = blame_state.solver.min(arg)
                    arg_max = blame_state.solver.max(arg)
                    if arg_min == arg_max:
                        sim_args.append("%#x" % arg_min)  # concrete, no range
                        report_details["parameters"].append(
                            {"type": "concrete", "value": arg_min}
                        )
                    else:
                        sim_args.append("[%#x-%#x]" % (arg_min, arg_max))
                        report_details["parameters"].append(
                            {
                                "type": "symbolic",
                                "value_min": arg_min,
                                "value_max": arg_max,
                            }
                        )
                except angr.errors.SimUnsatError:
                    sim_args.append("N/A")
                    report_details["parameters"].append({"type": "unknown"})

            log.info("Parameters: %s" % ", ".join(sim_args))
            report.add_detail("recommendation", report_details)
        else:
            log.error(
                "Cannot determine root cause: No guardians and blamed node isn't a simulated"
            )
        return

    # find last time trace visited the failed guardian
    failed_guard_state = None
    for idx, state in enumerate(tech.predecessors[:blame_idx][::-1]):
        if state is None:
            continue

        if state.addr == failed_guard.addr:
            failed_guard_state = state
            failed_guard_idx = blame_idx - (idx + 1)
            break
    if failed_guard_state is None:
        log.error("Failed to find last visit to failing guardian")
        return
    else:
        guard_addr_desc = ldr.describe_addr(failed_guard_state.addr)
    assert tech.predecessors[failed_guard_idx] == failed_guard_state

    # find constraint(s) needed to exit loop, thereby avoiding the blamed state
    succs = failed_guard_state.step()
    succ_taken_addr = tech.predecessors[failed_guard_idx + 1].addr
    succs_miss = [succ for succ in succs.successors if succ.addr != succ_taken_addr]

    log.debug(
        "Possible exits (%d/%d): %s"
        % (len(succs_miss), len(succs.all_successors), str(succs_miss))
    )
    if len(succs_miss) > 1:
        log.warn(
            "Found %d ways to avoid blamed state, only going to analyze one"
            % len(succs_miss)
        )

    if len(succs_miss) > 0 and len(succs_miss[0].history.recent_constraints) > 0:
        new_con_str = str(succs_miss[0].history.recent_constraints)
        log.info("Recommendation: Add %s to %s" % (new_con_str, str(failed_guard)))
        report.add_detail(
            "recommendation",
            {
                "type": "add_constraints",
                "guard": {
                    "address": failed_guard_state.addr,
                    "description": guard_addr_desc,
                },
                "constraints": new_con_str,
            },
        )
    else:
        log.info("Recommendation: Add additional checks to %s" % str(failed_guard))
        report.add_detail(
            "recommendation",
            {
                "type": "add_constraints",
                "guard": {
                    "address": failed_guard_state.addr,
                    "description": guard_addr_desc,
                },
                "constraints": None,
            },
        )


def blame_load_concrete_val(state, tech, load_addr):
    """Try to find a state to blame for an address containing the wrong concrete value.

    Keyword Args:
    state -- The state where angr diverged from the trace.
    tech -- The exploration technique.
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
    log.debug(
        "Num predecessors: %d" % len([s for s in tech.predecessors if not s is None])
    )
    for prev_state in tech.predecessors[::-1]:
        if prev_state is None:
            continue

        prev_val = prev_state.mem[load_addr].uint64_t.resolved
        if not state.solver.is_true(curr_val == prev_val):
            log.info(
                "Blaming for incorrect value: %s" % ldr.describe_addr(prev_state.addr)
            )
            return prev_state


def blame_load_unconstrained_val(state, tech, load_addr):
    """Try to find a state to blame for an address containing an unconstrained value.

    Keyword Args:
    state -- The state where angr diverged from the trace.
    tech -- The exploration technique.
    load_addr -- The address where the value was read from.

    Returns a state or None if we couldn't find one to blame.
    """
    ldr = state.project.loader

    # iterate over predecessors to find when memory lost its unique value
    curr_val = state.mem[load_addr].uint64_t.resolved
    log.debug(
        "Num predecessors: %d" % len([s for s in tech.predecessors if not s is None])
    )
    for prev_state in tech.predecessors[::-1]:
        if prev_state is None:
            continue

        prev_val = prev_state.mem[load_addr].uint64_t.resolved
        if not state.solver.is_true(curr_val == prev_val):
            log.info(
                "Blaming for unconstrained value: %s"
                % ldr.describe_addr(prev_state.addr)
            )
            return prev_state


def analyze_state(simgr, trace, state, report):
    log.info("Symbolic IP detected. Analyzing state...")
    # some objects we're going to reference frequently
    proj = state.project
    ldr = state.project.loader
    tech = simgr._techniques[0]

    # get address immediately before the diverge
    diverge_addr = state.history.bbl_addrs[-1]

    # if the analysis diverged because of a security check function (e.g. __stack_chk_fail),
    # we want the IRSB that performed the check (diverge_addr is currently the PLT stub)
    if is_plt(ldr, diverge_addr):
        diverge_addr = state.history.bbl_addrs[-3]

    # now we have the real diverge address, get info on it
    diverge_obj = ldr.find_object_containing(diverge_addr)
    diverge_irsb = state.block(diverge_addr).vex
    # including the last state that visited it (and its successor)
    diverge_state = None
    result_state = state
    for prev_state in tech.predecessors[::-1]:
        if prev_state.addr == diverge_addr:
            diverge_state = prev_state
            break
        else:
            result_state = prev_state

    if diverge_state is None:
        log.error("Failed to find diverging state")
        return

    # Phase 1: Find a state to "blame" for the exit
    #     (e.g. who wrote the data that caused this exit)
    log.info("Analyzing exit at %s" % ldr.describe_addr(diverge_addr))
    log.debug("Diverging IRSB:\n%s" % str(diverge_irsb))

    blame_state = None

    if diverge_irsb.jumpkind.startswith("Ijk_Boring") and taint.is_cond_branch(
        diverge_irsb
    ):
        try:
            cond_mems = taint.get_cond_exit_mem_addr(diverge_state, result_state)
            log.debug(
                "Conditional addresses: [%s]"
                % ",".join([hex(addr) for addr in cond_mems])
            )

            # try blaming using each address until a state is found or we run out of addresses
            # we prioritize high addresses first because these are most likely to be stack or heap
            for addr in sorted(cond_mems, reverse=True):
                log.debug("Considering %#x" % addr)
                if not diverge_state.solver.symbolic(
                    diverge_state.mem[addr].uint64_t.resolved
                ):
                    blame_state = blame_load_concrete_val(diverge_state, tech, addr)
                else:
                    blame_state = blame_load_unconstrained_val(
                        diverge_state, tech, addr
                    )

                if blame_state:
                    break

        except taint.TaintException as ex:
            log.error(
                "Failed to find memory dependency for conditional branch: %s" % str(ex)
            )
            return

    elif not diverge_irsb.direct_next:
        # no direct next, but also not a conditional branch, likely an indirect control
        # transfer (ICT), such as icall, ijmp, or ret.
        try:
            target_mem = taint.get_forward_ict_mem_addr(diverge_state, result_state)
        except taint.TaintException as ex:
            log.error("Failed to derive indirect target memory address: %s" % str(ex))
            return
        if not diverge_state.solver.symbolic(
            diverge_state.mem[target_mem].uint64_t.resolved
        ):
            blame_state = blame_load_concrete_val(diverge_state, tech, target_mem)
        else:
            blame_state = blame_load_unconstrained_val(diverge_state, tech, target_mem)

    else:
        log.error("No analysis technique implemented for %s" % diverge_irsb.jumpkind)

    if blame_state is None:
        log.error("Failed to find a state to blame")
        return

    # report blamed state
    report.add_detail(
        "blame",
        {
            "address": blame_state.addr,
            "description": ldr.describe_addr(blame_state.addr),
        },
    )

    # since we have a state to blame, we can mark this bug with a more concise hash
    blame_addr = blame_state.addr
    blame_obj = ldr.find_object_containing(blame_addr)
    if not blame_obj is None:
        blame_rva = AT.from_va(blame_addr, blame_obj).to_rva()
    else:
        blame_rva = blame_addr

    diverge_obj = ldr.find_object_containing(diverge_addr)
    if not diverge_obj is None:
        diverge_rva = AT.from_va(diverge_addr, diverge_obj).to_rva()
    else:
        diverge_rva = diverge_addr

    report.set_hash("%x" % (blame_rva ^ (diverge_rva << 1)))

    # Phase 2: Find the root cause for the blamed state's behavior
    analyze_blame(simgr, blame_state, report)


def check_impending_hijack(simgr, state):
    """If the provided state is about to execute a return or call, checks if doing
    so will result in a control hijack."""
    loader = state.project.loader

    try:
        state_irsb = state.block(state.addr).vex
    except angr.errors.SimEngineError:
        # program reached unmapped memory
        simgr.stashes["sip"].append(state)
        simgr._techniques[0].predecessors.append(state)
        return True

    is_ret = state_irsb.jumpkind.startswith("Ijk_Ret")
    if "call_depth" in state.globals and state.globals["call_depth"] < 1 and is_ret:
        # if tracing is started mid-execution, the stack used for analysis will have
        # fewer frames than the real execution, so we should not perform this check
        # if we've ran out
        return False

    if not state_irsb.direct_next:
        # step the state and check for successors that are either unconstrained
        # or reached unmapped memory regions
        succs = state.step()
        if len(succs.unconstrained_successors) > 0:
            # program counter became unconstrained
            simgr.stashes["sip"].append(succs.unconstrained_successors[0])
            simgr._techniques[0].predecessors.append(state)
            return True
        elif len(succs.successors) > 0:
            for succ in succs.successors:
                if (
                    succ.solver.symbolic(succ._ip)
                    or loader.find_object_containing(succ.addr) is None
                ):
                    # program counter is symbolic or jumped to unmapped memory
                    simgr.stashes["sip"].append(succ)
                    simgr._techniques[0].predecessors.append(state)
                    return True

    return False


def check_for_vulns(simgr, proj):
    """Check for symbolic instruction pointer"""
    global checked_traced

    # angr will crash if either of these checks is True, so it's okay to move these states
    simgr.move("active", "sip", lambda s: s.solver.symbolic(s._ip))
    simgr.move("unconstrained", "sip", lambda s: s.solver.symbolic(s._ip))

    if len(simgr.stashes["traced"]) > 0 and not checked_traced:
        checked_traced = True
        # If program segfaulted because of a corrupted return pointer, trace will end
        # on the return IRSB. We need to take one more step to see the bug manifest.
        check_impending_hijack(simgr, simgr.stashes["traced"][0])

    return True


checked_traced = False

stash_name = "sip"
pretty_name = "Symbolic IP"
