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
import claripy

log = logging.getLogger(name=__name__)

class at_bitmap_init(angr.SimProcedure):

    def run(self, area, width, height, planes):
        malloc = angr.SIM_PROCEDURES['libc']['malloc']

        bitmap = self.inline_call(malloc, 0x10).ret_expr

        width_val = self.state.solver.eval(width)
        height_val = self.state.solver.eval(height)
        area_val = self.state.solver.eval(area)

        if area_val != 0:
            self.state.memory.store(bitmap + 0x4, area, endness='Iend_LE')
        else:
            if (width_val * height_val) == 0:
                self.state.memory.store(bitmap + 0x4, self.state.solver.BVV(0, 64), endness='Iend_LE')
            else:
                planes_val = self.state.solver.eval(planes)
                bitmap_ptr = self.inline_call(malloc, width_val * height_val * planes_val).ret_expr
                self.state.memory.store(bitmap + 0x4, bitmap_ptr, endness='Iend_LE')

        self.state.memory.store(bitmap + 0x2, self.state.solver.BVV(width_val, 16), endness='Iend_LE')
        self.state.memory.store(bitmap + 0x0, self.state.solver.BVV(height_val, 16), endness='Iend_LE')
        self.state.memory.store(bitmap + 0xc, planes, endness='Iend_LE')

        return bitmap


class magnitude(angr.SimProcedure):
    def run(self):
        cc = self.state.project.factory.cc_from_arg_kinds([True, True, True],
                                                          ret_fp=True)
        # x = cc.arg(self.state, 0).to_claripy().val_to_fp(claripy.FSORT_FLOAT)
        # y = cc.arg(self.state, 1).to_claripy().val_to_fp(claripy.FSORT_FLOAT)
        # z = cc.arg(self.state, 2).to_claripy().val_to_fp(claripy.FSORT_FLOAT)
        # squared = (x * x) + (y * y) + (z * z)
        # half = claripy.FPV(0.5, claripy.FSORT_FLOAT)
        sym_ret = claripy.FPS('mag', claripy.FSORT_FLOAT)
        cc.return_val.set_value(self.state, sym_ret)


class fit_with_least_squares(angr.SimProcedure):
    def run(self):
        return claripy.BVS('fit_ret', 64)


libautotrace_hooks = {
    # 'at_bitmap_init': at_bitmap_init,
    'magnitude': magnitude,
    'fit_with_least_squares': fit_with_least_squares,
}

hook_condition = ('libautotrace\.so.*', libautotrace_hooks)
is_main_object = False
