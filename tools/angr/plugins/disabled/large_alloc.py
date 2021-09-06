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

log = logging.getLogger(__name__)

class ArgLimitException(Exception):
    pass

def sizeof_fmt(num, suffix='B'):
    """Pretty printing for byte sizes."""
    for unit in ["",'K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def check_alloc_args(state, indexes, limit):
    """Checks if an allocation function has an absurd parameter value (likely due to vulnerability).

    Keyword Args:
    state - The state to check.
    indexes - A list of argument indexes to check.
    limit - The largest allowable value.

    Raises ArgLimitException if limit is exceeded.

    Exception Properties:
    idx - Argument index.
    name - Symbol name.
    limit - Value of exceeded limit.
    max - The argument's max value (max > limit).

    Returns None.
    """
    for idx in indexes:
        arg = state.project.factory.cc().arg(state, idx)
        try:
            arg_val = state.solver.max(arg)
        except angr.errors.SimUnsatError:
            continue
        if arg_val > limit:
            ex = ArgLimitException("limit exceeded")
            ex.idx = idx
            ex.name = state.project.loader.find_plt_stub_name(state.addr)
            ex.limit = limit
            ex.max = arg_val
            raise ex

def analyze_state(simgr, trace, state):
    # some objects we're going to reference frequently
    proj = state.project
    ldr = state.project.loader
    tech = simgr._techniques[0]

    if not state in detected_states:
        log.error("Failed to find exception %s raised" % str(state))
        return

    ex = detected_states[state]
    blame_addr = state.addr

    # TODO - Implement root cause analysis

def check_for_vulns(simgr, proj):
    """Check for allocation function receiving large size argument"""
    alloc_funcs = {
        'malloc':       [0],
        'calloc':       [0, 1],
        'realloc':      [1],
        'reallocarray': [1, 2],
    }
    alloc_limit = 0x40000000  # 1 GB

    if len(simgr.stashes['active']) < 1:
        return False

    state = simgr.stashes['active'][0]

    sym_name = proj.loader.find_plt_stub_name(state.addr)
    if sym_name in alloc_funcs:
        try:
            check_alloc_args(state, alloc_funcs[sym_name], alloc_limit)
        except ArgLimitException as ex:
            log.info("Arg %d of %s exceeded limit of %s: %s" %
                    (ex.idx, ex.name, sizeof_fmt(ex.limit), sizeof_fmt(ex.max)))
            state_copy = state.copy()
            simgr.stashes['arg'].append(state_copy)
            # stash exception so we can refer to it during analysis
            detected_states[state_copy] = ex

    return True

detected_states = dict()
stash_name = 'arg'
pretty_name = 'Large Allocation'
