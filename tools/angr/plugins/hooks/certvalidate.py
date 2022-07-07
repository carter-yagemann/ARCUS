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


class certValidate_psBase64decode(angr.SimProcedure):
    def run(self, in_ptr, len, out, outlen):
        outlen_val = self.state.solver.eval(self.state.mem[outlen].uint16_t.resolved)
        log.debug("outlen = %d" % outlen_val)
        buf = self.state.solver.BVS("psBase64decode", outlen_val * 8)
        self.state.memory.store(out, buf)
        self.state.memory.store(
            outlen, self.state.solver.BVS("psBase64decode_outlen", 16)
        )
        ret = self.state.solver.BVS("psBase64decode_ret", 32)
        return ret


certValidate_hooks = {
    "psBase64decode": certValidate_psBase64decode,
}

hook_condition = ("certValidate", certValidate_hooks)
is_main_object = True
