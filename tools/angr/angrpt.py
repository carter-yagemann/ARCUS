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
from typing import List

import angr
from angr import BP_BEFORE, BP_AFTER, sim_options
from angr.errors import AngrTracerError
from angr.exploration_techniques import ExplorationTechnique

log = logging.getLogger(name=__name__)

class Tracer(ExplorationTechnique):
    """
    An exploration technique that follows an angr path with a concrete input.
    The tracing result is the state at the last address of the trace, which can be found in the
    'traced' stash.

    :param trace:               The basic block trace.
    :param start_address:       Override where to start analysis from, default is project entry.

    :ivar predecessors:         A list of states in the history before the final state.
    """

    def __init__(self,
            trace=None,
            start_address=None):
        super(Tracer, self).__init__()
        self._trace = trace
        self._start_address = start_address

        # keep track of the last basic block we hit
        self.predecessors = list()

    def setup(self, simgr):
        simgr.populate('missed', [])
        simgr.populate('traced', [])

        if not self._start_address is None:
            start = self._start_address
        else:
            start = self.project.entry

        self.project = simgr._project
        if len(simgr.active) != 1:
            raise AngrTracerError("Tracer is being invoked on a SimulationManager without exactly one active state")

        # find program entry point
        found_entry = False
        for idx, addr in enumerate(self._trace):
            if addr == start:
                found_entry = True
                break

        if not found_entry:
            raise AngrTracerError("Starting address isn't in trace, did you specify the correct PID?")

        # step to start of trace
        while self._trace and self._trace[idx] != simgr.one_active.addr:
            simgr.step(extra_stop_points={self._trace[idx]})
            if len(simgr.active) == 0:
                raise AngrTracerError("Could not step to the first address of the trace - simgr is empty")
            elif len(simgr.active) > 1:
                raise AngrTracerError("State split while searching for starting address")

        log.debug("Starting address %#x reached" % start)
        simgr.move('active', 'missed', lambda s: s.addr != start)
        # if multiple states reached the start address, only keep one
        if len(simgr.active) > 1:
            log.warn("%d states reached the starting address, picking 1" % len(simgr.active))
            simgr.move('active', 'missed', lambda s: s != simgr.one_active)

        # initialize the state info
        simgr.one_active.globals['trace_idx'] = idx
        simgr.one_active.globals['sync_idx'] = None
        simgr.one_active.globals['sync_timer'] = 0
        simgr.one_active.globals['call_depth'] = 0
        simgr.one_active.deep['frame_addrs'] = list()

    def complete(self, simgr):
        return bool(simgr.traced)

    def filter(self, simgr, state, **kwargs):
        # check completion
        if state.globals['trace_idx'] >= len(self._trace) - 1:
            return 'traced'
        if state.globals['call_depth'] < 0:
            return 'traced'

        # if tracing started mid-execution, the stack we use for analysis will have
        # fewer frames than the real execution, so we need to stop when we run out
        if not state.solver.symbolic(state._ip):
            next_jumpkind = state.project.factory.block(state.addr).vex.jumpkind
            if state.globals['call_depth'] < 1 and next_jumpkind.startswith("Ijk_Ret"):
                return 'traced'
            next_obj = state.project.loader.find_object_containing(state.addr)
            if state.globals['call_depth'] < 1 and next_obj == state.project.loader.extern_object:
                # entering a simproc without a return frame will cause an unconstrained return,
                # this can happen if starting mid-execution and starting method makes a tail
                # call optimized by the compiler into a jump
                # (https://en.wikipedia.org/wiki/Tail_call#In_assembly)
                log.warning("Entering simulation procedure without a return frame, cannot continue")
                return 'traced'

        return simgr.filter(state, **kwargs)

    def step(self, simgr, stash='active', **kwargs):
        simgr.drop(stash='missed')
        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        # maintain the predecessors list
        self.predecessors.append(state)

        # perform the step, ask qemu to stop at the termination point
        stops = set(kwargs.pop('extra_stop_points', ())) | {self._trace[-1]}
        succs_dict = simgr.step_state(state, extra_stop_points=stops, **kwargs)

        # failed to find a state that follows the traced path
        if not None in succs_dict:
            raise AngrTracerError("Could not find successor for address %#x" % state.addr)

        succs = succs_dict[None] + succs_dict['unsat']

        # follow the trace
        if len(succs) == 1:
            self._update_state_tracking(succs[0])
        elif len(succs) == 0:
            log.info('Remaining states: ' + ', '.join([str(key) + ': ' + str(len(succs_dict[key])) for key in succs_dict]))
            # if there is an unconstrained state, we've found a bug in the traced program
            if 'unconstrained' in succs_dict and len(succs_dict['unconstrained']) > 0:
                log.warn('Encountered unconstrained state while stepping')
                return succs_dict
            raise AngrTracerError("All states disappeared!")
        else:
            succ = self._pick_correct_successor(succs)
            succs_dict[None] = [succ]
            succs_dict['missed'] = [s for s in succs if s is not succ]

        log.debug('Remaining states: ' + ', '.join([str(key) + ': ' + str(len(succs_dict[key])) for key in succs_dict]))
        assert len(succs_dict[None]) == 1
        return succs_dict

    def _pick_correct_successor(self, succs):
        # there's been a branch of some sort. Try to identify which state stayed on the trace.
        assert len(succs) > 0
        idx = succs[0].globals['trace_idx']
        trace_addr = self._trace[idx + 1]

        res = []
        for succ in succs:
            try:
                if trace_addr == succ.addr:
                    res.append(succ)
            except AngrTracerError:
                pass

        if not res:
            prev_vex = succs[0].block(succs[0].history.bbl_addrs[-1]).vex
            prev_cap = succs[0].block(succs[0].history.bbl_addrs[-1]).capstone
            if trace_addr > prev_vex.addr and trace_addr < (prev_vex.addr + prev_vex.size):
                # the trace address is in the middle of the last executed block
                # next trace address should match one of the successor states
                next_trace_addr = self._trace[idx + 2]
                for succ in succs:
                    try:
                        if next_trace_addr == succ.addr:
                            succ.globals['trace_idx'] += 1
                            res.append(succ)
                    except AngrTracerError:
                        pass
                if len(res) < 1:
                    log.error("Trace is in the middle of block %#x, cannot find %#x or %#x from %s" % (prev_vex.addr, trace_addr, next_trace_addr, str(succs)))
                    raise AngrTracerError("Cannot find next trace address")
            elif prev_cap.insns[-1].mnemonic.startswith('rep'):
                log.warn("State split at rep instruction: %s" % prev_cap.insns[-1].mnemonic)
                rep_con, rep_op = prev_cap.insns[-1].mnemonic.split(' ')[:2]
                if rep_op == 'cmpsb':
                    # comparison repeats are often followed immediately by a binary branch (e.g. jne)
                    # we can jump straight to where the trace says we were suppose to be
                    succs[0].regs.rip = trace_addr
                    res.append(succs[0])
                elif rep_op == 'scasb':
                    if rep_con in ['repnz', 'repne'] and succs[-1].solver.eval(succs[-1].regs.al) == 0:
                        # scasb is often used as a fast implementation of strlen:
                        #
                        #     mov    $ptr,%rdi
                        #     or     $0xffffffffffffffff,%rcx
                        #     xor    %eax,%eax
                        #     repnz scas %es:(%rdi),%al
                        #     not    %rcx
                        #
                        # To save time, we'll just set RCX such that (!RCX < 4096) and move on.
                        log.warn("Encountered 'repnz scasb' that looks like it behaves like strlen, applying heuristic")
                        new_rcx = succs[-1].solver.BVS('scasb', 64)
                        con = succs[-1].solver.And(new_rcx > 0xFFFFFFFFFFFFF000, new_rcx <= 0xFFFFFFFFFFFFFFFF)
                        succs[-1].regs.rcx = new_rcx
                        succs[-1].add_constraints(con)
                        res.append(succs[-1])
                    else:
                        raise AngrTracerError("Unhandled variant of 'rep scasb'")
                elif rep_op in ['stosb', 'stosd', 'stosq', 'movsb', 'movsd', 'movsq']:
                    # dealing with symbolic data, always write as much as possible to be conservative
                    res.append(succs[0])
                else:
                    raise AngrTracerError("Unhandled split caused by repeat: %s" % prev_cap.insns[-1].mnemonic)
            else:
                log.debug(succs[0].block(succs[0].history.bbl_addrs[-1]).capstone.insns)
                log.error("Looking for successor %#x, only have: %s" % (trace_addr, ','.join([hex(succ.addr) for succ in succs])))
                raise AngrTracerError("No states followed the trace?")

        if len(res) > 1:
            raise AngrTracerError("The state split but several successors have the same (correct) address?")

        self._update_state_tracking(res[0])
        return res[0]

    def _update_stack_frame_list(self, state):
        """Maintain a list of stack frame addresses in the state's global dictionary."""
        kind = state.history.jumpkind
        if  kind.startswith('Ijk_Call'):
            curr_frame = state.solver.eval(state.regs.rsp)
            state.deep['frame_addrs'].append(curr_frame)
        elif kind.startswith('Ijk_Ret') and len(state.deep['frame_addrs']) > 0:
            state.deep['frame_addrs'].pop()

    def _update_state_tracking(self, state: 'angr.SimState'):
        idx = state.globals['trace_idx']
        sync = state.globals['sync_idx']
        timer = state.globals['sync_timer']

        # update call depth
        if state.history.jumpkind.startswith('Ijk_Call'):
            state.globals['call_depth'] += 1
        elif state.history.jumpkind.startswith('Ijk_Ret'):
            state.globals['call_depth'] -= 1

        # update stack frames list
        self._update_stack_frame_list(state)

        if state.history.recent_block_count > 1:
            # multiple blocks were executed this step. they should follow the trace *perfectly*
            # or else something is up
            # "something else" so far only includes concrete transmits, or...
            # https://github.com/unicorn-engine/unicorn/issues/874
            # ^ this means we will see desyncs of the form unicorn suddenly skips a bunch of qemu blocks
            assert state.history.recent_block_count == len(state.history.recent_bbl_addrs)

            if sync is not None:
                raise AngrTracerError("Unicorn bug, desync while syncing")

            contains_reps = False
            for addr in state.history.recent_bbl_addrs:
                # Intel repeat instructions are a pain because the trace never treats them as their own
                # basic block, but the emulator sometimes will. Thus we should not raise an exception
                # if we see some addresses that do not appear in the trace.
                if state.block(addr).capstone.insns[-1].mnemonic.startswith("rep"):
                    contains_reps = True

                if addr == state.unicorn.transmit_addr:
                    continue

                if self._trace[idx] == addr:
                    idx += 1
                else:
                    if not contains_reps:
                        raise AngrTracerError('Unicorn bug, emulation desync')

            idx -= 1 # use normal code to do the last synchronization

        if sync is not None:
            timer -= 1
            if self._trace[sync] == state.addr:
                state.globals['trace_idx'] = sync
                state.globals['sync_idx'] = None
                state.globals['sync_timer'] = 0
            elif timer > 0:
                state.globals['sync_timer'] = timer
            else:
                raise Exception("Trace failed to synchronize! We expected it to hit %#x (untranslated), but it failed to do this within a timeout" % self._trace[sync])

        elif self._trace[idx + 1] == state.addr:
            # normal case
            state.globals['trace_idx'] = idx + 1
        elif self.project.loader._extern_object is not None and self.project.loader.extern_object.contains_addr(state.addr):
            # externs
            proc = self.project.hooked_by(state.addr)
            if proc is None:
                raise Exception("Extremely bad news: we're executing an unhooked address in the externs space")
            if proc.is_continuation:
                orig_trace_addr = self.project.loader.find_symbol(proc.display_name).rebased_addr
                # this is fine. we do nothing and then next round it'll get handled by the is_hooked(state.history.addr) case
                pass
            elif state.addr == getattr(self.project.simos, 'vsyscall_addr', None):
                if not self._sync_callsite(state, idx, state.history.addr):
                    raise AngrTracerError("Could not synchronize following vsyscall")
            else:
                # see above
                pass
        elif state.history.jumpkind.startswith('Ijk_Sys'):
            # syscalls
            state.globals['sync_idx'] = idx + 1
            state.globals['sync_timer'] = 2
            state.globals['call_depth'] += 1
        elif state.history.jumpkind.startswith('Ijk_Exit') or state.globals['call_depth'] < 0:
            # termination!
            state.globals['trace_idx'] = len(self._trace) - 1
        elif self.project.is_hooked(state.history.addr):
            # simprocedures - is this safe..?
            self._fast_forward(state)
        elif self._analyze_misfollow(state, idx):
            # misfollow analysis will set a sync point somewhere if it succeeds
            pass
        else:
            raise AngrTracerError("Oops! angr did not follow the trace.")

        if state.globals['sync_idx'] is not None and self.project.loader.find_object_containing(state.addr):
            log.info("Trace: %d-%d/%d synchronizing %d %s", state.globals['trace_idx'], state.globals['sync_idx'],
                    len(self._trace), state.globals['sync_timer'], self.project.loader.describe_addr(state.addr))
        elif state.globals['sync_idx'] is not None:
            log.info("Trace: %d-%d/%d synchronizing %d %#x", state.globals['trace_idx'], state.globals['sync_idx'],
                    len(self._trace), state.globals['sync_timer'], state.addr)
        elif self.project.loader.find_object_containing(state.addr):
            log.info("Trace: %d/%d %s", state.globals['trace_idx'], len(self._trace), self.project.loader.describe_addr(state.addr))
        else:
            log.info("Trace: %d/%d %#x", state.globals['trace_idx'], len(self._trace), state.addr)

    def _analyze_misfollow(self, state, idx):
        angr_addr = state.addr
        trace_addr = self._trace[idx + 1]
        diverge_addr = self._trace[idx]
        obj = self.project.loader.find_object_containing(angr_addr)
        ldr = self.project.loader

        log.info("Misfollow: angr says %#x (%s), trace says %#x (%s)", angr_addr, ldr.describe_addr(angr_addr),
                trace_addr, ldr.describe_addr(trace_addr))

        # there are a few known instructions that our emulator considers to be the start of a new basic block
        # whereas our disassembler does not, they'll sync back up on the next step.
        try:
            curr_block = state.block(angr_addr)
        except angr.errors.SimEngineError:
            log.error("Reached unmapped memory: %#x" % state.addr)
            return False

        if len(curr_block.capstone.insns) > 0:
            mnemonics = [insn.mnemonic for insn in state.block(diverge_addr).capstone.insns]
            if mnemonics[-1].startswith('rep'):
                try:
                    end_idx = self._trace.index(trace_addr, idx)
                except ValueError:
                    raise AngrTracerError("At a disparate instruction, can't find where to sync to")
                state.globals['sync_idx'] = end_idx
                state.globals['trace_idx'] = idx
                state.globals['sync_timer'] = 1000
                return True
        else:
            # a block with no instructions can happen in a few odd cases (e.g. xsavec), we should sync on
            # the next step or crash if the emulator doesn't support the instruction
            state.globals['sync_idx'] = idx + 1  # trace address
            state.globals['trace_idx'] = idx
            state.globals['sync_timer'] = 1
            return True

        if 'IRSB' in state.history.recent_description:
            last_block = state.block(state.history.bbl_addrs[-1])
            if self._trace[idx + 1] in last_block.instruction_addrs:
                # we have disparate block sizes!
                # specifically, the angr block size is larger than the trace's.
                # allow the trace to catch up.
                while self._trace[idx + 1] in last_block.instruction_addrs:
                    idx += 1

                log.info('...resolved: disparate block sizes (angr ahead of trace)')

                if self._trace[idx + 1] == state.addr:
                    state.globals['trace_idx'] = idx + 1
                    return True
                else:
                    state.globals['trace_idx'] = idx
                    return True

            elif last_block.vex.direct_next:
                # disparate block sizes!
                # angr's block size is *smaller* than the trace's
                # allow angr to catch up.
                log.info('...resolved: disparate block sizes (trace ahead of angr)')

                state.globals['sync_idx'] = idx + 1  # trace address
                state.globals['trace_idx'] = idx
                state.globals['sync_timer'] = 5
                return True

        prev_addr = state.history.bbl_addrs[-1]
        prev_obj = ldr.find_object_containing(prev_addr)

        if prev_addr in getattr(prev_obj, 'reverse_plt', ()):
            prev_name = prev_obj.reverse_plt[prev_addr]
            prev_prev_addr = state.history.bbl_addrs[-2]
            log.info('...syncing at PLT callsite for %s', prev_name)
            if self.project.is_symbol_hooked(prev_name):
                if not self._sync_callsite(state, idx, prev_prev_addr):
                    # this can happen if a library calls a hooked symbol
                    self._fast_forward(state)
                return True
            else:
                # qemu is behind angr because of a dynamic load
                self._fast_forward(state)
                return True

        # Sometimes the emulator will mark the instruction after a syscall as the start of a new basic block,
        # whereas the disassembler will not. As a result, the trace will seem to be one basic block ahead of the
        # emulation state. Easiest way to fix this is to move the trace index back one and then they will
        # resync when emulation resumes.
        if len(state.history.bbl_addrs) >= 2:
            prev_prev_addr = state.history.bbl_addrs[-2]
            if state.block(prev_prev_addr).vex.jumpkind.startswith('Ijk_Sys') and self._trace[idx] == angr_addr:
                state.globals['trace_idx'] = idx
                return True

        log.info('...all analyses failed.')
        return False

    def _sync_callsite(self, state, idx, callsite_addr):
        retsite_addr = state.block(callsite_addr).size + callsite_addr
        try:
            retsite_idx = self._trace.index(retsite_addr, idx)
        except ValueError:
            log.error("Trying to fix desync at callsite but return address does not appear in trace")
            return False

        state.globals['sync_idx'] = retsite_idx
        state.globals['trace_idx'] = idx
        state.globals['sync_timer'] = 10000
        return True

    def _fast_forward(self, state):
        target_addr = state.addr
        log.debug("Searching for %#x starting at index %d" % (target_addr, state.globals['trace_idx'] + 1))
        try:
            target_idx = self._trace.index(target_addr, state.globals['trace_idx'] + 1)
        except ValueError:
            desc = self.project.loader.describe_addr(target_addr)
            msg = "Trace failed to fast forward. Couldn't find %s." % desc
            hook = self.project.hooked_by(state.history.addr)
            if not hook is None:
                msg += " Trace may have ended inside hooked function %s." % hook.display_name
            raise AngrTracerError(msg)

        state.globals['trace_idx'] = target_idx
