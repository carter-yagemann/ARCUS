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


class _tiffMapProc(angr.SimProcedure):
    def run(self, fd, pbase, psize):
        # save current position of fd
        orig_pos = self.inline_call(
            angr.SIM_PROCEDURES["linux_kernel"]["lseek"], fd, 0, 1
        ).ret_expr
        # self.state.posix.fstat() doesn't seem reliable, seek to end to determine size
        size = self.state.solver.eval(
            self.inline_call(
                angr.SIM_PROCEDURES["linux_kernel"]["lseek"], fd, 0, 2
            ).ret_expr
        )
        # rewind to beginning
        self.inline_call(angr.SIM_PROCEDURES["linux_kernel"]["lseek"], fd, 0, 0)

        buf = self.inline_call(angr.SIM_PROCEDURES["libc"]["malloc"], size).ret_expr
        self.inline_call(angr.SIM_PROCEDURES["posix"]["read"], fd, buf, size)

        self.state.memory.store(pbase, buf, endness="Iend_LE")
        self.state.mem[psize].uint32_t = size

        # restore position of fd
        self.inline_call(angr.SIM_PROCEDURES["linux_kernel"]["lseek"], fd, orig_pos, 0)

        return 1


libtiff_hooks = {
    "_tiffMapProc": _tiffMapProc,
}

hook_condition = ("libtiff\.so.*", libtiff_hooks)
is_main_object = False
