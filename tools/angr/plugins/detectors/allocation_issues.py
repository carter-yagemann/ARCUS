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

import logging
import taint
import ptcfg
from reporting import BugReport

import angr
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from angr.project import Project
from angr.calling_conventions import SimCC
from claripy.errors import ClaripyOperationError
from cle.address_translator import AT
from typing import List

log = logging.getLogger(__name__)

dangle_threshold = 300


class VulnMetadata:
    def __init__(self, start_idx, end_idx):
        self.start_idx = (start_idx,)
        self.end_idx = end_idx

    def _get_graphs(self, project, tech):
        # Create CFG and CDG
        pred_states = [state for state in tech.predecessors if state is not None]
        if project.is_hooked(pred_states[-1].addr):
            pred_states.pop()
        pred_addrs = [
            state.addr
            for state in pred_states
            if self.start_idx <= state.globals["trace_idx"] <= self.end_idx
        ]

        log.debug("Creating partial CFG...")
        cfg = ptcfg.cfg_from_trace(
            pred_addrs, project, cfg_args={"initial_state": pred_states[0]}
        )
        log.debug("Creating partial CDG...")
        cdg = project.analyses.CDG(cfg)
        return cfg, cdg


class DFMetadata(VulnMetadata):
    def __init__(
        self, start_idx, end_idx, first_free_addr, second_free_addr, buffer_addr
    ):
        """
        :param start_idx: Index in trace of first free
        :param end_idx: Index in trace of second free
        :param first_free_addr: Address where first free was called
        :param second_free_addr: Address where second free was called
        :param buffer_addr: Address of freed buffer
        """
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.first_free_addr = first_free_addr
        self.second_free_addr = second_free_addr
        self.buffer_addr = buffer_addr

    def get_root_cause(self, tech, state, report):
        # human readable description of relevant basic blocks
        loader = state.project.loader
        first_free_addr_desc = loader.describe_addr(self.first_free_addr)
        second_free_addr_desc = loader.describe_addr(self.second_free_addr)

        buffer_addr_val = state.solver.eval(self.buffer_addr)

        # fill in report details
        report.add_detail(
            "frees",
            [
                {"address": self.first_free_addr, "description": first_free_addr_desc},
                {
                    "address": self.second_free_addr,
                    "description": second_free_addr_desc,
                },
            ],
        )
        report.add_detail("buffer", buffer_addr_val)

        # print description
        log.info(
            "For double freeing of buffer %#x, first free was called at %s (before trace"
            " index: %d), second free was called by %s (before trace index: %d)"
            % (
                buffer_addr_val,
                first_free_addr_desc,
                self.start_idx,
                second_free_addr_desc,
                self.end_idx,
            )
        )

        # generate unique hash for bug
        first_obj = loader.find_object_containing(self.first_free_addr)
        second_obj = loader.find_object_containing(self.second_free_addr)
        if not first_obj is None:
            first_rva = AT.from_va(self.first_free_addr, first_obj).to_rva()
        else:
            first_rva = self.first_free_addr

        if not second_obj is None:
            second_rva = AT.from_va(self.second_free_addr, second_obj).to_rva()
        else:
            second_rva = self.second_free_addr

        report.set_hash("%x" % (second_rva ^ (first_rva << 1)))


class UAFMetadata(VulnMetadata):
    def __init__(
        self,
        start_idx,
        end_idx,
        free_addr,
        buffer_addr,
        buffer_size,
        use_offset,
        use_block,
        use_temp,
    ):
        """
        :param start_idx: Index in trace of free
        :param end_idx: Index in trace of use
        :param free_addr: Address where free occurred
        :param buffer_addr: Address of freed buffer
        :param buffer_size: Size of freed buffer
        :param use_offset: Offset of use within buffer
        :param use_block: Block address where use occurred
        :param use_temp: Temp containing use address
        """
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.free_addr = free_addr
        self.buffer_addr = buffer_addr
        self.buffer_size = buffer_size
        self.use_offset = use_offset
        self.use_block = use_block
        self.use_temp = use_temp

    def get_root_cause(self, tech, state, report):
        # human readable descriptions of relevant basic blocks
        loader = state.project.loader
        free_loc_desc = loader.describe_addr(self.free_addr)
        use_loc_desc = loader.describe_addr(self.use_block)

        # concretize some values
        buffer_addr_val = state.solver.eval(self.buffer_addr)
        use_offset_val = state.solver.eval(self.use_offset)
        buffer_size_val = state.solver.eval(self.buffer_size)

        # fill in report details
        report.add_detail(
            "buffer",
            {
                "start": buffer_addr_val,
                "size": buffer_size_val,
                "access_index": use_offset_val,
            },
        )
        report.add_detail(
            "free", {"address": self.free_addr, "description": free_loc_desc}
        )
        report.add_detail(
            "use", {"address": self.use_block, "description": use_loc_desc}
        )

        # print description
        log.info(
            "Buffer %#x was freed at %s (before trace index: %d) and then used by %s "
            "(trace index: %d), to access offset %d"
            % (
                buffer_addr_val,
                free_loc_desc,
                self.start_idx,
                use_loc_desc,
                self.end_idx,
                use_offset_val,
            )
        )

        # see if there was a guardian that could have prevented this
        cfg, cdg = self._get_graphs(state.project, tech)
        blame_node = cfg.model.get_any_node(self.use_block)

        guardians = cdg.get_guardians(blame_node)
        report.add_detail(
            "guards", [{"address": g.addr, "description": g.name} for g in guardians]
        )

        if len(guardians) == 0:
            log.info(
                "No guardians currently exist in the program that could prevent this use"
            )
        else:
            log.info(
                "Blaming guardian: %s at %#x" % (guardians[0].name, guardians[0].addr)
            )

        # generate unique hash for bug
        free_obj = loader.find_object_containing(self.free_addr)
        use_obj = loader.find_object_containing(self.use_block)
        if not free_obj is None:
            free_rva = AT.from_va(self.free_addr, free_obj).to_rva()
        else:
            free_rva = self.free_addr

        if not use_obj is None:
            use_rva = AT.from_va(self.use_block, use_obj).to_rva()
        else:
            use_rva = self.use_block

        report.set_hash("%x" % (use_rva ^ (free_rva << 1)))


class DangleMetadata(VulnMetadata):
    def __init__(
        self,
        start_idx,
        end_idx,
        start_addr,
        end_addr,
        caller_addr,
        buffer_addr,
        ptr_loc,
        ptr_val,
    ):
        """
        :param start_idx: Index in trace where ptr was created
        :param end_idx: Index in trace where ptr became dangling
        :param start_addr: Basic block address where ptr was created
        :param end_addr: Basic block address where ptr became dangling
        :param caller_addr: Basic block address of caller to free function
        :param buffer_addr: Base address of buffer ptr pointed to
        :param ptr_loc: Address in memory where ptr was stored
        :param ptr_val: Value of pointer (what it pointed to)
        """
        self.start_idx = start_idx
        self.end_idx = end_idx
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.caller_addr = caller_addr
        self.buffer_addr = buffer_addr
        self.ptr_loc = ptr_loc
        self.ptr_val = ptr_val

    def get_root_cause(self, tech, state, report):
        # human readable descriptions of relevant basic blocks
        loader = state.project.loader
        start_desc = loader.describe_addr(self.start_addr)
        end_desc = loader.describe_addr(self.end_addr)
        caller_desc = loader.describe_addr(self.caller_addr)

        # concretize some values
        buffer_addr_val = state.solver.eval(self.buffer_addr)
        ptr_loc_val = state.solver.eval(self.ptr_loc)
        ptr_val_val = state.solver.eval(self.ptr_val)

        # fill in report details
        report.add_detail("buffer", {"start": buffer_addr_val})
        report.add_detail(
            "dangle", {"store_address": ptr_loc_val, "ptr_value": ptr_val_val}
        )
        report.add_detail(
            "create", {"address": self.start_addr, "description": start_desc}
        )
        report.add_detail(
            "free",
            {
                "address": self.end_addr,
                "description": end_desc,
                "caller": {"address": self.caller_addr, "description": caller_desc},
            },
        )

        # print description
        log.info(
            "Pointer at %#x was set at %s (trace index: %d), the buffer it "
            "pointed to was freed at %s (trace index: %d) by %s (trace index: %d), "
            "and left dangling"
            % (
                ptr_loc_val,
                start_desc,
                self.start_idx,
                end_desc,
                self.end_idx,
                caller_desc,
                self.caller_addr,
            )
        )

        # in this case we don't care about guardians, the caller is to blame
        log.info(
            "Blaming %s for calling free and then leaving pointers dangling"
            % caller_desc
        )

        # generate unique hash for bug
        create_obj = loader.find_object_containing(self.start_addr)
        caller_obj = loader.find_object_containing(self.caller_addr)
        if not create_obj is None:
            create_rva = AT.from_va(self.start_addr, create_obj).to_rva()
        else:
            create_rva = self.start_addr

        if not caller_obj is None:
            caller_rva = AT.from_va(self.caller_addr, caller_obj).to_rva()
        else:
            caller_rva = self.caller_addr

        report.set_hash("%x" % (caller_rva ^ (create_rva << 1)))


def is_stack_va(addr, state):
    """Returns True if VA is on stack (assumes POSIX environment)."""
    if state.solver.is_true(addr <= state.posix.brk):
        return False
    return True


def is_novel(case, state):
    is_equal = lambda a, b: state.solver.is_true(a == b)

    for prev in state.deep["vuln_metadata"]:
        # generic comparison
        if case.start_idx == prev.start_idx and case.end_idx == prev.end_idx:
            return False
        # class-specific comparisons
        if isinstance(case, DangleMetadata) and isinstance(prev, DangleMetadata):
            if is_equal(case.ptr_loc, prev.ptr_loc):
                return False
        if isinstance(case, UAFMetadata) and isinstance(prev, UAFMetadata):
            if case.use_block == prev.use_block:
                return False
        if isinstance(case, DFMetadata) and isinstance(prev, DFMetadata):
            if is_equal(case.buffer_addr, prev.buffer_addr):
                return False
    return True


def analyze_state(
    simgr: SimulationManager, trace: List[int], state: SimState, report: BugReport
) -> None:
    tech = simgr._techniques[0]
    # state has a metadata object for every prior detection to facilitate deduplication,
    # last item was first detected in this state and is the only one we need to root cause
    metadata = state.deep["vuln_metadata"][-1]
    metadata.get_root_cause(tech, state, report)


def remove_from_alloc_addrs(ptr, state: SimState):
    try:
        del state.deep["alloc_addrs"][ptr]
    except KeyError:
        log.warning("Tried to remove %s from alloc_addrs but received KeyError" % ptr)


def handle_alloc(sym_name: str, cc: SimCC, state: SimState) -> None:
    ret_addr = cc.return_addr.get_value(state)
    try:
        state.deep["mem_func_ret_addr"] = state.solver.eval_one(ret_addr)
    except angr.errors.SimValueError:
        return

    sim_proc = state.project.hooked_by(state.addr)
    if sim_proc is None:
        log.warning(
            "Cannot find simulation procedure for %s"
            % state.project.loader.describe_addr(state.addr)
        )
        return

    args = [state.solver.eval(bv) for bv in cc.get_args(state, sim_proc.prototype)]

    if sym_name == "malloc":
        state.deep["temp_size"] = args[0]
    elif sym_name == "calloc":
        state.deep["temp_size"] = args[0] * args[1]
    elif sym_name == "realloc":
        state.deep["temp_size"] = args[1]
        old_ptr = args[0]
        try:
            if state.solver.eval_one(old_ptr) != 0:
                remove_from_alloc_addrs(old_ptr, state)
        except angr.errors.SimValueError:
            pass
    elif sym_name == "reallocarray":
        state.deep["temp_size"] = args[1] * args[2]
        old_ptr = args[0]
        try:
            if state.solver.eval_one(old_ptr) != 0:
                remove_from_alloc_addrs(old_ptr, state)
        except angr.errors.SimValueError:
            pass


def has_bv_been_freed(bv, state):
    bv_value = state.solver.eval(bv)
    for start_bv, metadata in state.deep["freed_addrs"].items():
        start = state.solver.eval(start_bv)
        end = state.solver.eval(metadata[0]) + start
        if start <= bv_value < end:
            return (True, start_bv)

    return (False, None)


def allocate(cc: SimCC, state: SimState):
    new_ptr = state.solver.eval(cc.RETURN_VAL.get_value(state))
    log.debug("Adding %s to alloc_addrs" % new_ptr)
    state.deep["alloc_addrs"][new_ptr] = state.deep["temp_size"]
    state.deep["temp_size"] = None
    if new_ptr in state.deep["freed_addrs"]:
        del state.deep["freed_addrs"][new_ptr]


def handle_free(cc: SimCC, state: SimState) -> bool:
    sim_proc = state.project.hooked_by(state.addr)
    if sim_proc is None:
        log.warning(
            "Cannot find simulation procedure for %s"
            % state.project.loader.describe_addr(state.addr)
        )
        return False

    args = cc.get_args(state, sim_proc.prototype)
    ptr = state.solver.eval(args[0])
    log.debug("Handling free at %#x with ptr %s" % (state.addr, ptr))

    if ptr in state.deep["alloc_addrs"]:
        # all pointers to this buffer are now dangling
        for addr in state.deep["points_to"]:
            if state.solver.is_true(
                state.deep["points_to"][addr][2]["buffer_base"] == ptr
            ):
                log.debug("Pointer at address %s is now dangling" % str(addr))
                state.deep["points_to"][addr][1] = state.globals["trace_idx"]
                state.deep["points_to"][addr][2]["free_addr"] = state.addr
                state.deep["points_to"][addr][2][
                    "caller_addr"
                ] = state.history.bbl_addrs[-2]

        state.deep["freed_addrs"][ptr] = (
            state.deep["alloc_addrs"][ptr],
            state.history.bbl_addrs[-2],
            state.globals["trace_idx"],
        )

        # correct freeing of allocated buffer
        del state.deep["alloc_addrs"][ptr]
        return False

    # freed pointer wasn't in allocation list, this is a double free
    try:
        metadata = DFMetadata(
            state.deep["freed_addrs"][ptr][2],
            state.globals["trace_idx"],
            state.deep["freed_addrs"][ptr][1],
            state.history.bbl_addrs[-2],
            ptr,
        )

        if is_novel(metadata, state):
            log.info("Double free detected")
            state.deep["vuln_metadata"].append(metadata)
            return True

    except KeyError:
        return False

    # double free was already reported in a prior state
    return False


def update_points_to(state, addr):
    addr = state.solver.eval(addr)
    bits = state.arch.bits
    endness = state.arch.memory_endness
    is_equal = lambda a, b: state.solver.is_true(a == b)

    # skip stack pointers, even though they can technically dangle, developers
    # rarely null them and they're unlikely to become UAF bugs
    if is_stack_va(addr, state):
        return

    # read from the memory address as if it were storing a pointer
    new_ptr = state.solver.eval(
        state.memory.load(addr, size=bits // 8, endness=endness)
    )

    if addr in state.deep["points_to"]:
        old_ptr = state.deep["points_to"][addr][0]
        if is_equal(old_ptr, new_ptr):
            # already tracking, unchanged, do not touch metadata
            return
        else:
            # old pointer (and metadata) has been overwritten, delete it
            log.debug("Clearing points-to metadata at address %s" % str(addr))
            del state.deep["points_to"][addr]

    # novel pointer, does it point to dynamically allocated data?
    for base in state.deep["alloc_addrs"]:
        limit = base + state.deep["alloc_addrs"][base]
        if state.solver.is_true(state.solver.And(new_ptr >= base, new_ptr < limit)):
            # points to allocated data, record it
            log.debug("Address %s holds pointer %s" % (str(addr), str(new_ptr)))
            # -1 denotes pointer is not dangling
            state.deep["points_to"][addr] = [
                new_ptr,
                -1,
                {
                    "create_idx": state.globals["trace_idx"],
                    "create_addr": state.addr,
                    "buffer_base": base,
                },
            ]
            return


def update_dangling(state):
    bits = state.arch.bits
    endness = state.arch.memory_endness
    is_equal = lambda a, b: state.solver.is_true(a == b)

    detections = False
    to_del = list()

    for addr in state.deep["points_to"]:
        buf_ptr, dangle_idx, metadata = state.deep["points_to"][addr]

        if dangle_idx > -1:
            # pointer at addr is dangling, check for how long
            dangle_dur = state.globals["trace_idx"] - dangle_idx
            assert dangle_dur >= 0

            if dangle_dur > dangle_threshold:
                # recheck that this pointer hasn't been overwritten (e.g., due to stack
                # pops/pushes, partial overwrites), in which case it has dangled for too
                # long and should be reported
                cur_ptr = state.memory.load(addr, size=bits // 8, endness=endness)
                if is_equal(cur_ptr, buf_ptr):
                    # pointer has dangled too long and hasn't changed, create a DangleMetadata,
                    # but we don't know if it's novel yet (may already be in vuln_metadata)
                    detection = DangleMetadata(
                        metadata["create_idx"],
                        dangle_idx,
                        metadata["create_addr"],
                        metadata["free_addr"],
                        metadata["caller_addr"],
                        metadata["buffer_base"],
                        addr,
                        buf_ptr,
                    )

                    if is_novel(detection, state):
                        log.info(
                            "Dangling pointer exceeded threshold, now a use-after-free risk"
                        )
                        state.deep["vuln_metadata"].append(detection)
                        detections = True
                else:
                    log.debug(
                        "Dangling pointer changed at some point, no longer dangling"
                    )

                # can't delete while iterating
                to_del.append(addr)

    for addr in to_del:
        del state.deep["points_to"][addr]

    return detections


def initialize_globals(state: SimState):
    # stores list of freed addresses + sizes
    if "freed_addrs" not in state.deep:
        state.deep["freed_addrs"] = {}

    # stores list of allocated addresses + sizes
    if "alloc_addrs" not in state.deep:
        state.deep["alloc_addrs"] = {}

    # temporary place to store the size of buffers that are about to be
    # allocated (e.g., state immediately before entering malloc)
    if "temp_size" not in state.deep:
        state.deep["temp_size"] = None

    # tempoary place to store the return address of a called allocation
    # function (this is how we know when to extract the returned buffer pointer)
    if "mem_func_ret_addr" not in state.deep:
        state.deep["mem_func_ret_addr"] = None

    # tracks location of pointers in memory to dynamically allocated data
    if "points_to" not in state.deep:
        state.deep["points_to"] = {}

    # holds issues discovered in the state
    if "vuln_metadata" not in state.deep:
        state.deep["vuln_metadata"] = []


def check_for_vulns(simgr: SimulationManager, proj: Project) -> bool:
    if len(simgr.active) < 1:
        return False
    if len(simgr._techniques[0].predecessors) < 1:
        return True

    state = simgr.active[0]
    prev_state = simgr._techniques[0].predecessors[-1]
    initialize_globals(state)
    initialize_globals(prev_state)
    cc = proj.factory.cc()

    if state.solver.symbolic(state._ip):
        # This plugin cannot handle states with symbolic program counters
        return True

    # Handle memory management function calls
    sym_obj = proj.loader.find_symbol(state.addr, fuzzy=True)
    if sym_obj is None:
        # no symbol associated with this address
        sym_name = ""
    else:
        sym_name = sym_obj.name

    # main has returned, we don't check any further for bugs
    if sym_name == "__libc_start_main.after_main":
        return True

    if sym_name in ("malloc", "calloc", "realloc", "reallocarray"):
        handle_alloc(sym_name, cc, state)
    elif sym_name == "free":
        if handle_free(cc, state):
            # double free was detected
            simgr.stashes[stash_name].append(state.copy())
            return True

    if state.addr == state.deep["mem_func_ret_addr"]:
        allocate(cc, state)
        state.deep["mem_func_ret_addr"] = None

    # get memory accesses for *previous* state (due to how new tainter works)
    mem_accesses = taint.get_mem_accesses(prev_state, state)
    # update points-to metadata for any loaded or stored pointers
    # (we can't do this in the UAF check loop because that one can return early)
    for temp, addr in mem_accesses:
        update_points_to(state, addr)

    for temp, addr in mem_accesses:
        # check for use-after-free
        uaf, ptr = has_bv_been_freed(addr, prev_state)
        if uaf:
            metadata = UAFMetadata(
                prev_state.deep["freed_addrs"][ptr][2],
                prev_state.globals["trace_idx"],
                prev_state.deep["freed_addrs"][ptr][1],
                ptr,
                prev_state.deep["freed_addrs"][ptr][0],
                (addr - ptr),
                prev_state.addr,
                temp,
            )

            if is_novel(metadata, state):
                log.info("Use-after-free detected")
                state.deep["vuln_metadata"].append(metadata)
                simgr.stashes[stash_name].append(state.copy())

                return True

    # Check function arguments for UAF
    #
    # If we call a SimProcedure, we can't see memory accesses so just check
    # if the symbol is hooked and make sure arguments are not in freed_addrs.
    # There is unlikely chance of collisions, but that could be mitigated
    # with function models.
    already_handled_syms = ["", "malloc", "calloc", "realloc", "reallocarray", "free"]
    if not sym_name in already_handled_syms and proj.is_symbol_hooked(sym_name):
        sim_proc = proj.hooked_by(state.addr)

        if not sim_proc is None:
            args = cc.get_args(state, sim_proc.prototype)

            for arg_idx in range(sim_proc.num_args):
                arg = args[arg_idx]
                uaf, ptr = has_bv_been_freed(arg, state)
                if uaf:
                    metadata = UAFMetadata(
                        prev_state.deep["freed_addrs"][ptr][2],
                        prev_state.globals["trace_idx"],
                        prev_state.deep["freed_addrs"][ptr][1],
                        ptr,
                        prev_state.deep["freed_addrs"][ptr][0],
                        (arg - ptr),
                        prev_state.addr,
                        temp,
                    )

                    if is_novel(metadata, state):
                        log.info(
                            "SimProc %s was passed a pointer to freed memory (possible "
                            "use-after-free)" % sym_name
                        )

                        state.deep["vuln_metadata"].append(metadata)
                        simgr.stashes[stash_name].append(state.copy())
                        return True

    # No double frees (DF) or use-after-free (UAF), check for dangling pointers (DP)
    #
    # Note: The conditions for checking DF and UAF are mutually exclusive (no single state will
    # ever require both checks), which is why this method returns upon detecting a novel instance
    # of either. Dangling pointer *could* be detected in the same state as a DF or UAF, but because
    # its detection heuristic is threshold-based, we can also detect it in any successor state. In
    # short, there's no rush to detect DP.
    #
    # Also, UAF is more important because it's a confirmed case whereas DP only indicates a UAF
    # *could* occur somewhere.
    if update_dangling(state):
        simgr.stashes[stash_name].append(state.copy())
        return True

    # nothing of note was detected
    return True


stash_name = "alloc"
pretty_name = "Allocation Issues"
