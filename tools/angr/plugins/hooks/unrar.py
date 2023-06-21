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

from .libc import libc_mbsrtowcs
from .libc import WCHAR_BYTES

log = logging.getLogger(name=__name__)


class unrar__Z9InitCRC32Pj(angr.SimProcedure):
    def run(self, crc_tab):
        # we're going to simulate all checksum calculations, so no need to
        # actually initialize the table
        return


class unrar__Z5CRC32jPKvm(angr.SimProcedure):
    def run(self, start, addr, size):
        # building constraints for checksums is hard, so just under-constrain
        return self.state.solver.BVS("crc32_checksum", self.state.arch.bits)


class unrar__ZL10InitTablesv(angr.SimProcedure):
    def run(self):
        # no need to initialize tables, we're going to simulate checksum
        # calculations
        return


class unrar__Z10Checksum14tPKvm(angr.SimProcedure):
    def run(self, start, addr, size):
        # building constraints for checksums is hard, so just under-constrain
        return self.state.solver.BVS("checksum14", self.state.arch.bits)


class unrar__Z3LogPKwS0_z(angr.SimProcedure):
    def run(self, arc_name, fmt):
        # don't care about logging
        return


class unrar__ZN7Archive15BrokenHeaderMsgEv(angr.SimProcedure):
    def run(self, this_ptr):
        # don't care about logging
        return


class unrar__ZN12ErrorHandler14CreateErrorMsgEPKwS1(angr.SimProcedure):
    def run(self, this_ptr, arc_name, file_name):
        # don't care about logging
        return


## RawRead class


class unrar__ZN7RawRead4Get1Ev(angr.SimProcedure):
    def run(self, this_ptr):
        # returns a byte read from input file
        val = self.state.solver.BVS("raw_read_get1", 8)
        if self.state.arch.bits > val.length:
            val = val.zero_extend(self.state.arch.bits - val.length)
        return val


class unrar__ZN7RawRead4Get2Ev(angr.SimProcedure):
    def run(self, this_ptr):
        # returns a ushort read from input file
        val = self.state.solver.BVS("raw_read_get2", 16)
        if self.state.arch.bits > val.length:
            val = val.zero_extend(self.state.arch.bits - val.length)
        return val


class unrar__ZN7RawRead4Get4Ev(angr.SimProcedure):
    def run(self, this_ptr):
        # returns a uint read from input file
        val = self.state.solver.BVS("raw_read_get4", 32)
        if self.state.arch.bits > val.length:
            val = val.zero_extend(self.state.arch.bits - val.length)
        return val


class unrar__ZN7RawRead4GetVEv(angr.SimProcedure):
    def run(self, this_ptr):
        # returns a uint64 read from input file
        val = self.state.solver.BVS("raw_read_getv", 64)
        if self.state.arch.bits > val.length:
            val = val.zero_extend(self.state.arch.bits - val.length)
        return val


class unrar__ZN7RawRead6SetPosEm(angr.SimProcedure):
    def run(self, this_ptr, pos):
        # simulating RawRead, so don't actually need to move position
        return


class unrar__ZN7RawRead5ResetEv(angr.SimProcedure):
    def run(self, this_ptr):
        # simulating RawRead, so don't actually need to reset
        return


class unrar__ZN7RawRead4ReadEm(angr.SimProcedure):
    def run(self, this_ptr, size):
        # simulating RawRead, so don't actually need to read from file
        return


class unrar__ZN7RawRead4ReadEPhm(angr.SimProcedure):
    def run(self, this_ptr, src_data, size):
        # simulating RawRead, so don't actually need to read from file
        return


class unrar__Z9cleandataPvm(angr.SimProcedure):
    def run(self, data, size):
        # unrar uses this method to wipe data from memory, but since
        # we're not looking for leaks, we can just skip this to save
        # a ton of steps
        return


class unrar__ZN7RawRead4GetWEPwm(angr.SimProcedure):
    MAX_SIZE = 128

    def run(self, this_ptr, field_ptr, size):
        if not self.state.solver.symbolic(size):
            log.debug("RawRead::GetW with concrete size")
            max_size = self.state.solver.eval(size)
        else:
            log.debug("RawRead::GetW with symbolic size")
            max_size = min(self.MAX_SIZE, self.state.solver.max(size))

        log.debug("Proceeding with max size: %d" % max_size * WCHAR_BYTES)

        for idx in range(0, max_size * WCHAR_BYTES, WCHAR_BYTES):
            wchar = self.state.solver.BVS("rawread_getw_%d" % idx, WCHAR_BYTES * 8)
            self.state.memory.store(
                field_ptr + (idx * WCHAR_BYTES),
                wchar,
                endness=self.state.arch.memory_endness,
            )


class unrar__ZN7RawRead4GetBEPvm(angr.SimProcedure):
    MAX_SIZE = 256

    def run(self, this_ptr, field_ptr, size):
        if not self.state.solver.symbolic(size):
            log.debug("RawRead::GetB with concrete size")
            max_size = self.state.solver.eval(size)
        else:
            log.debug("RawRead::GetB with symbolic size")
            max_size = min(self.MAX_SIZE, self.state.solver.max(size))

        log.debug("Proceeding with max size: %d" % max_size)

        for idx in range(0, max_size):
            char = self.state.solver.BVS("rawread_getb_%d" % idx, 8)
            self.state.memory.store(field_ptr + idx, char)

        # returns number of bytes read
        ret = self.state.solver.BVS("rawread_getb_ret", self.state.arch.bits)
        self.state.add_constraints(ret <= max_size)
        return ret


unrar_hooks = {
    "_Z9InitCRC32Pj": unrar__Z9InitCRC32Pj,
    "_Z5CRC32jPKvm": unrar__Z5CRC32jPKvm,
    "_ZL10InitTablesv": unrar__ZL10InitTablesv,
    "_Z10Checksum14tPKvm": unrar__Z10Checksum14tPKvm,
    "_Z3LogPKwS0_z": unrar__Z3LogPKwS0_z,
    "_ZN7Archive15BrokenHeaderMsgEv": unrar__ZN7Archive15BrokenHeaderMsgEv,
    "_ZN12ErrorHandler14CreateErrorMsgEPKwS1_": unrar__ZN12ErrorHandler14CreateErrorMsgEPKwS1,
    "_ZN7RawRead4Get4Ev": unrar__ZN7RawRead4Get4Ev,
    "_ZN7RawRead6SetPosEm": unrar__ZN7RawRead6SetPosEm,
    "_ZN7RawRead4Get1Ev": unrar__ZN7RawRead4Get1Ev,
    "_ZN7RawRead4GetVEv": unrar__ZN7RawRead4GetVEv,
    # returns same type as getv
    "_ZN7RawRead4Get8Ev": unrar__ZN7RawRead4GetVEv,
    # returns same type as get4
    "_ZN7RawRead8GetCRC50Ev": unrar__ZN7RawRead4Get4Ev,
    "_ZN7RawRead8GetCRC15Eb": unrar__ZN7RawRead4Get4Ev,
    "_ZN7RawRead8GetVSizeEm": unrar__ZN7RawRead4Get4Ev,
    "_ZN7RawRead4GetWEPwm": unrar__ZN7RawRead4GetWEPwm,
    "_ZN7RawRead4GetBEPvm": unrar__ZN7RawRead4GetBEPvm,
    "_ZN7RawRead5ResetEv": unrar__ZN7RawRead5ResetEv,
    "_ZN7RawRead4ReadEm": unrar__ZN7RawRead4ReadEm,
    "_ZN7RawRead4Get2Ev": unrar__ZN7RawRead4Get2Ev,
    "_ZN7RawRead4ReadEPhm": unrar__ZN7RawRead4ReadEPhm,
    "_Z9cleandataPvm": unrar__Z9cleandataPvm,
}

hook_condition = ("unrar", unrar_hooks)
is_main_object = True
