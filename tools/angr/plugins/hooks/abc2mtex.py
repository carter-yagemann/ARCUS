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

class abc2mtex_read_settings(angr.SimProcedure):

    def run(self):
        # real function calls fopen and then returns void because we never
        # have a settings file, this SimProcedure saves time
        return

abc2mtex_hooks = {
    'read_settings': abc2mtex_read_settings,
}

hook_condition = ('abc2mtex', abc2mtex_hooks)
is_main_object = True
