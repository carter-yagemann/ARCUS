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

log = logging.getLogger(name=__name__)


class lua_luaS_new(angr.SimProcedure):
    def run(self):
        # Underconstrain string creation
        log.info("Returning unconstrained string pointer")
        ret_val = claripy.BVS("lua_str", self.state.arch.bits)
        return ret_val


class lua_sym_ret(angr.SimProcedure):
    def run(self):
        # Underconstrain string creation
        log.info("Returning unconstrained value")
        ret_val = claripy.BVS("lua_str", self.state.arch.bits)
        return ret_val


lua_hooks = {
    "luaS_new": lua_luaS_new,
    "luaS_newlstr": lua_sym_ret,
    "mainposition.isra.3": lua_sym_ret,
}

hook_condition = ("lua", lua_hooks)
is_main_object = True
