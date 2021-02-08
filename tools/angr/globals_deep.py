#!/usr/bin/env python
#
# Copyright 2020 Carter Yagemann
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

from copy import deepcopy
import logging

from angr.state_plugins.plugin import SimStatePlugin

log = logging.getLogger(name=__name__)

class SimStateDeepGlobals(SimStatePlugin):
    """Based on angr's original globals state plugin, only difference is this one deep copies"""

    def __init__(self, backer=None):
        super(SimStateDeepGlobals, self).__init__()
        try:
            self._backer = deepcopy(backer) if backer is not None else {}
        except RecursionError:
            log.warning("Failed to deep copy, using shallow instead")
            self._backer = backer if backer is not None else {}

    def set_state(self, state):
        pass

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument

        for other in others:
            for k in other.keys():
                if k not in self:
                    self[k] = other[k]

        return True

    def widen(self, others): # pylint: disable=unused-argument
        l.warning("Widening is unimplemented for globals")
        return False

    def __getitem__(self, k):
        return self._backer[k]

    def __setitem__(self, k, v):
        self._backer[k] = v

    def __delitem__(self, k):
        del self._backer[k]

    def __contains__(self, k):
        return k in self._backer

    def keys(self):
        return self._backer.keys()

    def values(self):
        return self._backer.values()

    def items(self):
        return self._backer.items()

    def get(self, k, alt=None):
        return self._backer.get(k, alt)

    def pop(self, k, alt=None):
        return self._backer.pop(k, alt)

    @SimStatePlugin.memo
    def copy(self, memo):   # pylint: disable=unused-argument
        return SimStateDeepGlobals(dict(self._backer))
