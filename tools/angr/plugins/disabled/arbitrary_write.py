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

import taint

log = logging.getLogger(__name__)

def analyze_state(simgr, trace, state):
    # some objects we're going to reference frequently
    proj = state.project
    ldr = state.project.loader
    tech = simgr._techniques[0]

    # TODO - Implement analysis

def check_for_vulns(simgr, proj):
    if len(simgr.stashes['active']) < 1:
        return False

    state = simgr.stashes['active'][0]

    # skip arbitrary read/write checks if state is in the external object
    if proj.loader.find_object_containing(state.addr) == proj.loader.extern_object:
        return True

    read_write_limit = 0x8000000  # 128 MB

    # check arbitrary writes
    writes = taint.get_mem_accesses(state, loads=False, stores=True)
    for tmp, write in writes:
        if not state.solver.symbolic(write):
            continue
        try:
            write_min = state.solver.min(write)
            write_max = state.solver.max(write)
        except angr.errors.SimUnsatError:
            continue
        write_range = write_max - write_min
        if write_range > read_write_limit:
            log.info("Arbitrary write at %#x" % state.addr)
            simgr.stashes['awr'].append(state.copy())

    return True

stash_name = 'awr'
pretty_name = 'Arbitrary Write'
