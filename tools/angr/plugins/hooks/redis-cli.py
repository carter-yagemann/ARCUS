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

class jemalloc_constructor(angr.SimProcedure):

    def run(self):
        return

class je_malloc(angr.SimProcedure):

    def run(self, size):
        return self.inline_call(angr.SIM_PROCEDURES['libc']['malloc'], size).ret_expr

rediscli_hooks = {
    'jemalloc_constructor': jemalloc_constructor,
    'je_malloc': je_malloc,
}

hook_condition = ('redis-cli', rediscli_hooks)
is_main_object = True
