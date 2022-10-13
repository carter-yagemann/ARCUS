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

unrar_hooks = {
    "_Z9InitCRC32Pj": unrar__Z9InitCRC32Pj,
    "_Z5CRC32jPKvm": unrar__Z5CRC32jPKvm,
    "_ZL10InitTablesv": unrar__ZL10InitTablesv,
    "_Z10Checksum14tPKvm": unrar__Z10Checksum14tPKvm,
}

hook_condition = ("unrar", unrar_hooks)
is_main_object = True
