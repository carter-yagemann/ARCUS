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

def alloc_fmt_str(simproc, fmt_str):
    addr = simproc.inline_call(angr.SIM_PROCEDURES['libc']['malloc'], len(fmt_str)).ret_expr
    simproc.state.memory.store(addr, fmt_str)
    return addr

def free_fmt_str(simproc, addr):
    simproc.inline_call(angr.SIM_PROCEDURES['libc']['free'], addr)


class printLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%s\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printIntLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%d\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printShortLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%hd\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printFloatLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%f\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printLongLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%ld\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printLongLongLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%lld\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printSizeTLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%zu\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printHexCharLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%02x\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printUnsignedLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%u\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printHexUnsignedCharLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%02x\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)

class printDoubleLine(angr.SimProcedure):

    def run(self, val):
        addr = alloc_fmt_str(self, b"%g\n\x00")
        self.inline_call(angr.SIM_PROCEDURES['libc']['printf'], addr, val)
        free_fmt_str(self, addr)


class sym_ret(angr.SimProcedure):
    def run(self):
        return claripy.BVS('sym_ret', 32)


class new_snprintf(angr.SimProcedure):
    def run(self, s, n, format):
        max_len = self.state.solver.max(n)
        sym_str = claripy.BVS('sym_str', max_len*8)
        self.state.memory.store(s, sym_str)
        return claripy.BVS('sym_ret', 32)


juliet_hooks = {
    'printLine': printLine,
    'printIntLine': printIntLine,
    'printShortLine': printShortLine,
    'printFloatLine': printFloatLine,
    'printLongLine': printLongLine,
    'printLongLongLine': printLongLongLine,
    'printSizeTLine': printSizeTLine,
    'printHexCharLine': printHexCharLine,
    'printUnsignedLine': printUnsignedLine,
    'printHexUnsignedCharLine': printHexUnsignedCharLine,
    'printDoubleLine': printDoubleLine,
    'printf': sym_ret,
    'fprintf': sym_ret,
    'vprintf': sym_ret,
    'vfprintf': sym_ret,
    'snprintf': new_snprintf,
}

hook_condition = ('CWE[0-9]{3}_[^.]+\.out', juliet_hooks)
is_main_object = True
