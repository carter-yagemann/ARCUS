#!/usr/bin/env python
#
# Copyright 2022 Carter Yagemann
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

import json
import logging
import os

from angr.exploration_techniques import ExplorationTechnique

log = logging.getLogger(name=__name__)

class Metrics(ExplorationTechnique):
    """
    An exploration technique that doesn't actually explore, but simply tracks
    and records metrics over discovered states.

    Metrics can be saved as a snapshot to a file. Saving multiple snapshots will
    append to the file.
    """

    def __init__(self):
        super(Metrics, self).__init__()

        self.metrics = {
            "max_constraints": {
                "value": 0,
                "description": "The maximum number of constraints seen in a"
                        " state up to this point.",
            },
            "max_ast_nodes": {
                "value": 0,
                "description": "The maximum number of AST nodes seen in a"
                        " state so far, summed across all constraints",
            },
            "max_sum_ast_depth": {
                "value": 0,
                "description": "Maximum AST depth, summed across all "
                        "constraints, seen in a state so far."
            },
            "max_call_depth": {
                "value": 0,
                "description": "Maximum call depth reached across states"
                        " seen so far."
            },
            "max_steps": {
                "value": 0,
                "description": "Maximum number of steps taken from a starting"
                        " state so far."
            },
        }

        # key: AST, value: number of nodes in its AST
        self.ast_cache = dict()

        # some warning flags
        self.has_warn_call_depth = False

    def save_snapshot(self, ofp, name):
        """Save a snapshot of the current metrics to a file.

        Keyword Arguments:
        ofp -- Output filepath. If it doesn't exist, it will be created.
        name -- Name of this snapshot. This allows multiple snapshots to be
        appended to the same file.
        """
        if os.path.isfile(os.path.realpath(ofp)):
            with open(ofp, 'r') as ifile:
                data = json.loads(ifile.read())
        elif os.path.exists(ofp):
            log.error("Output filepath exists, but is not a file, cannot"
                    " overwrite: %s" % ofp)
            return
        else:
            data = dict()

        data[name] = self.metrics

        with open(ofp, 'w') as ofile:
            ofile.write(json.dumps(data))

    def step_state(self, simgr, state, **kwargs):
        num_cons = len(state.solver.constraints)
        self._max('max_constraints', num_cons)

        num_nodes = sum([self._ast_nodes(c) for c in state.solver.constraints])
        self._max('max_ast_nodes', num_nodes)

        ast_depth = sum([c.depth for c in state.solver.constraints])
        self._max('max_sum_ast_depth', ast_depth)

        # this global is maintained by angrpt.Tracer
        if 'call_depth' in state.globals:
            self._max('max_call_depth', state.globals['call_depth'])
        elif not self.has_warn_call_depth:
            log.warning("State does not have 'call_depth' global, metrics will"
                    " not measure call depth!")
            self.has_warn_call_depth = True

        self._max('max_steps', len(state.history.bbl_addrs))

        return simgr.step_state(state, **kwargs)

    def _max(self, key, value):
        """Sets the metric identified by key to the max of its current value and
        the newly provided value."""
        cur_val = self.metrics[key]['value']
        self.metrics[key]['value'] = max(cur_val, value)

    def _ast_nodes(self, con):
        """Given a constraint from angr, return the number of nodes in its
        AST."""
        # cache
        if con in self.ast_cache:
            return self.ast_cache[con]

        num_nodes = len(list(con.children_asts())) + 1

        # update cache
        self.ast_cache[con] = num_nodes

        return num_nodes
