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

import angrpt
import ptcfg
import taint
from plugins.detectors import symbolic_ip as sip

log = logging.getLogger(__name__)

def analyze_state(simgr, trace, state, report):
    # for now, we just piggyback off the symbolic IP detector's analysis
    sip.analyze_state(simgr, trace, state, report)

def check_for_vulns(simgr, proj):
    vuln_funcs = [
        'abort',
        '__stack_chk_fail',
    ]

    if len(simgr.active) < 1:
        return False

    state = simgr.active[0]
    sym_obj = proj.loader.find_symbol(state.addr, fuzzy=True)
    if not sym_obj is None and sym_obj.name in vuln_funcs:
        # this state is inside a function that's only called if a memory
        # error has occurred
        log.info("Reached %s, which is an aborting error handler; "
                 "we've triggered a bug" % sym_obj.name)
        simgr.stashes[stash_name].append(state.copy())
        simgr.drop()

    return True

stash_name = 'vuln'
pretty_name = 'Vulnerability Hooks'
