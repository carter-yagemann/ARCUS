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

import explore

import angr
from angr.exploration_techniques import ExplorationTechnique
import claripy
import pyvex

log = logging.getLogger(__name__)

class ArgumentMax(ExplorationTechnique):
    """Searches for bugs by maxing arguments in certain simulation procedures.

    Keyword Args:
    predecessors -- The list of states generated by Tracer.
    trace -- The list of basic block addresses in the original PT trace.
    """

    simproc_args = {
        # libc
        'calloc':         [0, 1],
        'fgets':          [1],
        'fread':          [1, 2],
        'fwrite':         [1, 2],
        'malloc':         [0],
        'memcpy':         [2],
        'memset':         [2],
        'realloc':        [1],
        'setvbuf':        [3],
        'snprintf':       [1],
        '__snprintf_chk': [1, 2],
        'strncpy':        [2],
        'vsnprintf':      [1],
        # linux kernel
        'brk':            [0],
        'mmap':           [1],
        'munmap':         [1],
        # posix
        'accept':         [2],
        'bzero':          [1],
        'pread64':        [2],
        'pwrite64':       [2],
        'read':           [2],
        'recv':           [2],
        'recvfrom':       [2, 5],
        'send':           [2],
        'write':          [2],
    }

    def __init__(self, predecessors, trace, options):
        super(ArgumentMax, self).__init__()
        self.orig_preds = predecessors
        self.predecessors = predecessors
        self.trace = trace
        self.candidates = list()

    def setup(self, simgr):
        """Select candidate simprocs to max"""
        if not 'missed' in simgr.stashes:
            simgr.populate('missed', [])
        simgr.drop(stash='active')

        loader = self.project.loader

        for idx, state in enumerate(self.orig_preds):
            simproc = state.project.hooked_by(state.addr)
            if simproc is None:
                # not a simproc
                continue

            sym_name = simproc.display_name
            if not sym_name in self.simproc_args:
                # we don't care about this symbol
                continue

            target_idxs = self.simproc_args[sym_name]

            proc_args = state.project.factory.cc().get_args(state, simproc.prototype)
            if not True in [state.solver.symbolic(proc_args[idx]) for idx in target_idxs]:
                # all arguments we would want to max are concrete, nothing to do
                continue

            self.candidates.append((state, self.orig_preds[:idx]))

        log.info("Candidates found: %d" % len(self.candidates))

        self._rewind(simgr)

    def step(self, simgr, stash='active', **kwargs):
        simgr.drop(stash='missed')

        # this can happen if a detector plugin removes our active state because
        # further execution is no longer possible (e.g., symbolic IP)
        if len(simgr.stashes['active']) < 1:
            log.warn("No more active states, rewinding")
            self._rewind(simgr)

        return simgr.step(stash=stash, **kwargs)

    def step_state(self, simgr, state, **kwargs):
        # maintain the predecessors list
        self.predecessors.append(state)
        succs = {'active': [], 'missed': []}

        loader = self.project.loader
        if loader.find_object_containing(state.addr):
            log.info("Argument Max Explorer: (%d) (%d) %s", len(self.candidates) + 1,
                    state.globals['wander_budget'], loader.describe_addr(state.addr))
        else:
            log.info("Argument Max Explorer: (%d) (%d) %#x", len(self.candidates) + 1,
                    state.globals['wander_budget'], state.addr)

        # if we're heading into a function we care about, maximize the target arguments
        simproc = self.project.hooked_by(state.addr)
        if simproc is None:
            sym_name = ''
        else:
            sym_name = simproc.display_name

        if sym_name in self.simproc_args:
            target_idxs = self.simproc_args[sym_name]
            log.info("Maxing arguments in: %s:%s" % (sym_name, str(target_idxs)))
            args_info = state.project.factory.cc().get_arg_info(state, simproc.prototype)
            for idx in target_idxs:
                loc = args_info[idx][2]
                val = args_info[idx][3]
                max_val = state.solver.max(val)
                state.add_constraints(
                        state.solver.Or(val == max_val,
                                        val >= (1 << state.arch.bits)))

        try:
            candidates = [succ for succ in state.step() if succ.solver.satisfiable()]
        except Exception as ex:
            # state cannot be stepped, we're done with this run
            log.debug("Cannot step (%s), rewinding" % str(ex))
            self._rewind(simgr)
            if len(simgr.stashes['active']) > 0:
                succs['active'] = [simgr.stashes['active'][0]]
            return succs

        if len(candidates) < 1:
            # no candidate states, rewind
            log.debug("Cannot step, rewinding")
            self._rewind(simgr)
            if len(simgr.stashes['active']) > 0:
                succs['active'] = [simgr.stashes['active'][0]]
            return succs

        # shouldn't matter where we go
        succs['active'] = [candidates[0]]
        succs['missed'] = candidates[1:]
        # we're wandering freely
        succs['active'][0].globals['wander_budget'] -= 1
        if succs['active'][0].globals['wander_budget'] < 1:
            # we've hit our wander limit, it's time to give up and rewind
            log.warning("Wander budget exhausted, ending run")
            succs['missed'].append(succs['active'][0])
            succs['active'] = list()

        if len(succs['active']) == 0:
            log.debug("Rewinding")
            self._rewind(simgr)
            if len(simgr.stashes['active']) > 0:
                succs['active'] = [simgr.stashes['active'][0]]

        return succs

    def _rewind(self, simgr):
        """Queues up the next candidate by rewinding and then setting it as active"""
        simgr.drop(stash='active')
        try:
            active, preds = self.candidates.pop(0)
        except IndexError:
            log.info("No candidates left")
            return
        # once we max out the args, we don't want to wander forever, so set a budget
        active.globals['wander_budget'] = 150
        simgr.stashes['active'] = [active]
        self.predecessors = preds

    def complete(self, simgr):
        """Returns True when there's nothing left to explore"""
        return len(simgr.stashes['active']) < 1 and len(self.candidates) < 1

explorer = ArgumentMax
