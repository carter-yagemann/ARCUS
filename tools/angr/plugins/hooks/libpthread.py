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

import logging
import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

log = logging.getLogger(name=__name__)


class pthreads_open(angr.SimProcedure):

    def run(self, p_addr, oflag):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        malloc = angr.SIM_PROCEDURES['libc']['malloc']

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        fd = self.state.posix.open(path, oflag)

        if fd is None:
            return 0
        else:
            io_file_data = io_file_data_for_arch(self.state.arch)
            file_struct_ptr = self.inline_call(malloc, io_file_data['size']).ret_expr

            # Write the fd
            fd_bvv = self.state.solver.BVV(fd, 4 * 8) # int
            self.state.memory.store(file_struct_ptr + io_file_data['fd'],
                                    fd_bvv,
                                    endness=self.state.arch.memory_endness)

            return file_struct_ptr

class pthreads_open64(angr.SimProcedure):

    def run(self, path, oflag):
        oflag_val = self.state.solver.eval(oflag)
        oflag_val = oflag_val | angr.storage.file.Flags.O_LARGEFILE
        return self.inline_call(pthreads_open, path, oflag_val).ret_expr


libpthread_hooks = {
    "open": pthreads_open,
    "open64": pthreads_open64,
}

hook_condition = ("libpthread\.so.*", libpthread_hooks)
is_main_object = False
