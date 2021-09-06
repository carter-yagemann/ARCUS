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
import angr
import taint
import ptcfg

import IPython

from typing import List
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from angr.project import Project

log = logging.getLogger(__name__)


def analyze_state(simgr: SimulationManager, trace: List[int], state: SimState) -> None:
    proj = state.project
    cc = proj.factory.cc()
    tech = simgr._techniques[0]

    # Create CFG and DDG
    pred_states = [state for state in tech.predecessors if state is not None]
    if proj.is_hooked(pred_states[-1].addr):
        pred_states.pop()
    pred_addrs = [state.addr for state in pred_states]

    # log.debug("Creating partial CFG...")
    # partial_cfg = ptcfg.cfg_from_trace(pred_addrs, proj, cfg_args={'initial_state': pred_states[0]})
    # log.debug("Creating partial DDG...")
    # partial_cdg = proj.analyses.DDG(partial_cfg)

    # Determine root cause
    log.info('Root cause:')

    # Suggest fix
    log.info('Suggested fixes:')
    log.info('Place guardian if (ptr) before dereferencing pointer.')


def check_for_vulns(simgr: SimulationManager, proj: Project) -> bool:
    if len(simgr.active) < 1:
        return False

    state = simgr.active[0]

    if proj.loader.describe_addr(state.addr).startswith('__libc_start_main.after_init'):
        return True

    mem_accesses = taint.get_mem_accesses(state)

    for temp, addr in mem_accesses:
        try:
            if state.solver.eval_one(addr) == 0:
                log.info('Null pointer dreference at 0x%X in temp %d' % (state.addr, temp))  # Uses wrong address?
                simgr.stashes['nptr'].append(state.copy())
                return False
        except angr.errors.SimUnsatError:
            log.warning('State is unsat')
        except angr.errors.SimValueError:
            pass

    return True

stash_name = 'nptr'
pretty_name = 'Null Pointer Deref'
