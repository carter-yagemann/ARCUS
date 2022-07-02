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

class ntpq_intern_file_load(angr.SimProcedure):

    def run(self, opts):
        # We never trace ntpq with config files, so we don't need this
        return

class ntpq_optionMakePath(angr.SimProcedure):

    def run(self, p_buf, b_sz, fname, prg_path):
        # just symbolize p_buf and we'll constrain it later
        size = self.state.solver.eval(b_sz)
        data = self.state.solver.BVS('optionMakePath', 8 * size)
        self.state.memory.store(p_buf, data)

        ret = self.state.solver.BVS('optionMakePath_ret', self.arch.bits)
        ret_c = self.state.solver.Or(ret == 0, ret == 1)
        self.state.add_constraints(ret_c)
        return ret

class ntpq_signal_no_reset(angr.SimProcedure):

    def run(self, opts):
        # Don't need signals
        return

class ntpq_validate_struct(angr.SimProcedure):

    def run(self, opts, pname):
        ret = self.state.solver.BVS('validate_struct_ret', self.arch.bits)
        ret_c = self.state.solver.Or(ret == 0, ret == -1)
        self.state.add_constraints(ret_c)
        return ret

class ntpq_env_presets(angr.SimProcedure):

    def run(self, pOpts, type):
        # do nothing
        return

ntpq_hooks = {
    'intern_file_load': ntpq_intern_file_load,
    'optionMakePath': ntpq_optionMakePath,
    'signal_no_reset': ntpq_signal_no_reset,
    'validate_struct': ntpq_validate_struct,
    'env_presets': ntpq_env_presets,
}

hook_condition = ('ntpq', ntpq_hooks)
is_main_object = True
