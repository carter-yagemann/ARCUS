#!/usr/bin/env python
#
# Copyright 2019 Matthew Pruett
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

import time

log = logging.getLogger(name=__name__)

class gm_clock_gettime(angr.SimProcedure):
    def run(self, which_clock, timespec_ptr):
        if not self.state.solver.is_true(which_clock == 0):
            result = {
                'tv_sec': self.state.solver.BVV(0, self.arch.bits, key=('api', 'clock_gettime', 'tv_sec')),
                'tv_nsec': self.state.solver.BVV(0, self.arch.bits, key=('api', 'clock_gettime', 'tv_nsec')),
            }

        if self.state.solver.is_true(timespec_ptr == 0):
            return -1

        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            flt = time.time()
            result = {'tv_sec': int(flt), 'tv_nsec': int(flt * 1000000000)}
        else:
            result = {
                'tv_sec': self.state.solver.BVS('tv_sec', self.arch.bits, key=('api', 'clock_gettime', 'tv_sec')),
                'tv_nsec': self.state.solver.BVS('tv_nsec', self.arch.bits, key=('api', 'clock_gettime', 'tv_nsec')),
            }

        self.state.mem[timespec_ptr].struct.timespec = result
        return 0


class gm_magick_get_token(angr.SimProcedure):
    def run(self):
        return 0


class gm_ret_sym(angr.SimProcedure):
    def run(self):
        return self.state.solver.BVS('sym_ret', self.arch.bits)


class gm_locale_compare(angr.SimProcedure):
    def run(self):
        res = self.state.solver.BVS('local_compare_result', self.arch.bits)
        self.state.solver.add(claripy.Or(res == 0, res == 1, res == -1))
        return res


gm_hooks = {
    'clock_gettime': gm_clock_gettime,
    'ReadLogConfigureFile': gm_magick_get_token,
    'MagickGetToken': gm_magick_get_token,
    'UnregisterMagickInfo': gm_magick_get_token,
    'LocaleCompare': gm_locale_compare,
    'ReadBlob': gm_ret_sym,
}

hook_condition = ('gm', gm_hooks)
is_main_object = True
