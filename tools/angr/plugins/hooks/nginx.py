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

# TODO - These simprocedures are far from complete, but they're better than nothing...

import logging
import angr

log = logging.getLogger(name=__name__)


class ngx_cpystrn(angr.SimProcedure):
    def run(self, dst, src, n):
        return self.inline_call(
            angr.SIM_PROCEDURES["libc"]["strncpy"], dst, src, n
        ).ret_expr


class ngx_init_setproctitle(angr.SimProcedure):
    def run(self):
        # we don't care about proctitle and it takes a lot of time to execute
        return 0


class ngx_setproctitle(angr.SimProcedure):
    def run(self):
        # real function has 2 expensive strncpys that we don't want to
        # waste our time on
        return


class ngx_gmtime(angr.SimProcedure):
    def run(self, t, tp_ptr):
        store = lambda offset, val: self.state.memory.store(
            tp_ptr + offset, val, endness="Iend_LE"
        )

        n = self.state.solver.eval(t)
        days = n / 86400
        wday = 86400
        wday = (4 + days) % 7
        n %= 86400
        hour = n / 3600
        n %= 3600
        minute = n / 60
        sec = n % 60
        days = days - (31 + 28) + 719527
        year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1)
        yday = days - (365 * year + year / 4 - year / 100 + year / 400)
        if yday < 0:
            if (year % 4 == 0) and (year % 100 or (year % 400 == 0)):
                leap = 1
            else:
                leap = 0
            yday = 365 + leap + yday
            year -= 1
        mon = (yday + 31) * 10 / 306
        mday = yday - (367 * mon / 12 - 30) + 1
        if yday >= 306:
            year += 1
            mon -= 10
        else:
            mon += 2

        log.debug(
            "ngx_gmtime: %s sec, %s min, %s hour, %s mday, %s mon, %s year, %s wday"
            % (
                str(sec),
                str(minute),
                str(hour),
                str(mday),
                str(mon),
                str(year),
                str(wday),
            )
        )

        store(0, self.state.solver.BVV(int(sec), 32))
        store(4, self.state.solver.BVV(int(minute), 32))
        store(8, self.state.solver.BVV(int(hour), 32))
        store(12, self.state.solver.BVV(int(mday), 32))
        store(16, self.state.solver.BVV(int(mon), 32))
        store(20, self.state.solver.BVV(int(year), 32))
        store(24, self.state.solver.BVV(int(wday), 32))


class ngx_create_pidfile(angr.SimProcedure):
    def run(name, log):
        # we don't need to actually create a PID file
        return 0


class ngx_create_pool(angr.SimProcedure):
    def run(self, size, log):
        # pretend to create a pool, but we're going to use malloc & free
        return 1000


class ngx_destroy_pool(angr.SimProcedure):
    def run(self, pool):
        # we don't actually create pools, so nothing to do
        return


class ngx_palloc(angr.SimProcedure):
    def run(self, pool, size):
        return self.inline_call(angr.SIM_PROCEDURES["libc"]["malloc"], size).ret_expr


class ngx_pfree(angr.SimProcedure):
    def run(self, pool, p):
        self.inline_call(angr.SIM_PROCEDURES["libc"]["free"], p)
        return 0


class ngx_pcalloc(angr.SimProcedure):
    def run(self, pool, size):
        return self.inline_call(angr.SIM_PROCEDURES["libc"]["calloc"], 1, size).ret_expr


class ngx_pool_cleanup_add(angr.SimProcedure):
    def run(self, p, size):
        # pretend to create a cleanup handler
        return 2000


class ngx_pool_cleanup_file(angr.SimProcedure):
    def run(self, data):
        return


class ngx_pool_delete_file(angr.SimProcedure):
    def run(self, data):
        return


nginx_hooks = {
    # string processing
    "ngx_cpystrn": ngx_cpystrn,
    "ngx_snprintf": angr.SIM_PROCEDURES["libc"]["snprintf"],
    "ngx_vsnprintf": angr.SIM_PROCEDURES["libc"]["vsnprintf"],
    # costly junk we don't really want to analyze
    "ngx_init_setproctitle": ngx_init_setproctitle,
    "ngx_setproctitle": ngx_setproctitle,
    "ngx_gmtime": ngx_gmtime,
    "ngx_create_pidfile": ngx_create_pidfile,
    # memory management
    #'ngx_create_pool': ngx_create_pool,
    #'ngx_destroy_pool': ngx_destroy_pool,
    #'ngx_palloc': ngx_palloc,
    #'ngx_pfree': ngx_pfree,
    #'ngx_pcalloc': ngx_pcalloc,
    #'ngx_pool_cleanup_add': ngx_pool_cleanup_add,
    #'ngx_pool_cleanup_file': ngx_pool_cleanup_file,
    #'ngx_pool_delete_file': ngx_pool_delete_file,
}

hook_condition = ("nginx", nginx_hooks)
is_main_object = True
