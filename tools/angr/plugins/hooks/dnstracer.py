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

log = logging.getLogger(name=__name__)

class printablename(angr.SimProcedure):

    def run(self, name, withdots):
        hostname_ptr = self.project.loader.find_symbol('hostname.5591').rebased_addr
        log.debug("hostname: %#x" % hostname_ptr)

        ret = self.state.solver.BVS('printablename_ret', 64)
        con = self.state.solver.Or(ret == hostname_ptr, ret == (hostname_ptr + 1))
        self.state.add_constraints(con)

        return ret

dnstracer_hooks = {
    'printablename': printablename,
}

hook_condition = ('dnstracer', dnstracer_hooks)
is_main_object = True
