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
import re

import angr
from angr.procedures import SIM_PROCEDURES as P
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

import plugins.hooks

log = logging.getLogger(name=__name__)


class linux_getdents(angr.SimProcedure):
    def run(self, fd, dirp, count):
        # resolve count
        count = self.state.solver.eval(count)
        log.debug("getdents: count = %d" % count)

        for idx in range(count):
            self.state.memory.store(dirp + idx, self.state.solver.BVS("getdents", 8))

        ret = self.state.solver.BVS("getdents_ret", 32)
        return ret


class linux_epoll_ctl(angr.SimProcedure):
    EPOLL_CTL_ADD = 1
    EPOLL_CTL_DEL = 2
    EPOLL_CTL_MOD = 3

    def run(self, epfd, op, fd, event):
        epfd = self.state.solver.eval(epfd)
        op = self.state.solver.eval(op)
        fd = self.state.solver.eval(fd)

        if not "epfds" in self.state.deep:
            self.state.deep["epfds"] = dict()
        EPFDS = self.state.deep["epfds"]

        if op == self.EPOLL_CTL_ADD or op == self.EPOLL_CTL_MOD:
            epoll_event = self.state.mem[event].uint32_t.resolved
            epoll_data = self.state.solver.eval(
                self.state.mem[event + 4].uint64_t.resolved
            )
            log.debug("Setting fd %d with data %#x to epfd %d" % (fd, epoll_data, epfd))
            if not epfd in EPFDS:
                EPFDS[epfd] = dict()
            EPFDS[epfd][fd] = (epoll_event, epoll_data)
        elif op == self.EPOLL_CTL_DEL:
            log.debug("Removing fd %d from epfd %d" % (fd, epfd))
            if epfd in EPFDS and fd in EPFDS[epfd]:
                del EPFDS[epfd][fd]
        else:
            return -1

        return 0


class linux_epoll_wait(angr.SimProcedure):
    def run(self, epfd, events, maxevents, timeout):
        epfd = self.state.solver.eval(epfd)
        events = self.state.solver.eval(events)
        store = lambda ptr, val: self.state.memory.store(ptr, val, endness="Iend_LE")

        if not "epfds" in self.state.deep:
            return -1
        EPFDS = self.state.deep["epfds"]

        if not epfd in EPFDS:
            return -1

        fds = EPFDS[epfd]
        if len(fds) == 0:
            return -1
        if len(fds) > 1:
            log.warning(
                "An epfd is monitoring more than 1 fd, we aren't sure which event to return"
            )

        maxevents = self.state.solver.max(maxevents)
        ptr = events
        for idx in range(maxevents):
            store(ptr, self.state.solver.BVS("events", 32))
            store(ptr + 4, self.state.solver.BVV(fds[0][1], 64))
            ptr += 12

        res = self.state.solver.BVS("epoll_wait_res", 32)
        con = self.state.solver.And(res >= -1, res <= maxevents)
        self.state.add_constraints(con)
        return res


class linux_fstat(angr.SimProcedure):
    def run(self, fd, stat_buf):
        stat = self.state.posix.fstat(fd)
        self._store_amd64(stat_buf, stat)
        return 0

    def _store_amd64(self, stat_buf, stat):
        store = lambda offset, val: self.state.memory.store(
            stat_buf + offset, val, endness="Iend_LE"
        )

        store(0x00, self.state.solver.BVS("fstat", 64))
        store(0x08, self.state.solver.BVS("fstat", 64))
        store(0x10, self.state.solver.BVS("fstat", 64))
        store(0x18, self.state.solver.BVS("fstat", 32))
        store(0x1C, self.state.solver.BVS("fstat", 32))
        store(0x20, self.state.solver.BVS("fstat", 32))
        store(0x24, self.state.solver.BVS("fstat", 32))
        store(0x28, self.state.solver.BVS("fstat", 64))
        store(0x30, self.state.solver.BVS("fstat", 64))
        store(0x38, self.state.solver.BVS("fstat", 64))
        store(0x40, self.state.solver.BVS("fstat", 64))
        store(0x48, self.state.solver.BVS("fstat", 64))
        store(0x50, self.state.solver.BVS("fstat", 64))
        store(0x58, self.state.solver.BVS("fstat", 64))
        store(0x60, self.state.solver.BVS("fstat", 64))
        store(0x68, self.state.solver.BVS("fstat", 64))
        store(0x70, self.state.solver.BVS("fstat", 64))
        store(0x78, self.state.solver.BVS("fstat", 64))
        store(0x80, self.state.solver.BVS("fstat", 64))
        store(0x88, self.state.solver.BVS("fstat", 64))


class linux_getsockname(angr.SimProcedure):
    def run(self, sockfd, addr_ptr, addrlen_ptr):
        # dereference and resolve addrlen
        addrlen = self.state.solver.eval(self.state.mem[addrlen_ptr].int32_t.resolved)
        log.debug("getsockname: addrlen = %d" % addrlen)
        if addrlen < 1:
            return -1

        # symbolize buffer pointed to by addr_ptr
        addr = self.state.solver.BVS("addr", addrlen * 8)
        self.state.memory.store(addr_ptr, addr)

        # symbolize addrlen to be between 0 and current addrlen
        new_addrlen = self.state.solver.BVS("addrlen", 32)
        c1 = self.state.solver.And(new_addrlen >= 0, new_addrlen <= addrlen)
        self.state.memory.store(addrlen_ptr, new_addrlen, endness="Iend_LE")
        self.state.add_constraints(c1)

        ret = self.state.solver.BVS("getsockname_ret", 32)
        c2 = self.state.solver.Or(ret == 0, ret == -1)
        self.state.add_constraints(c2)
        return ret


linux_hooks = {
    # Angr tends to make the result of fstat too concrete
    "fstat": linux_fstat,
    # Some missing syscall procedures we care about
    "getsockname": linux_getsockname,
    "getdents": linux_getdents,
    "epoll_ctl": linux_epoll_ctl,
    "epoll_wait": linux_epoll_wait,
    # Some syscalls aren't hooked because user space POSIX hooks are placed instead.
    # We don't want to assume progrmas won't make the syscall directly.
    "socket": P["posix"]["socket"],
}


class strlen(angr.SimProcedure):
    max_null_index = None
    max_ovf_len = 8096

    def run(self, s, wchar=False):
        # call angr's original strlen and get the result
        strlen_call = self.inline_call(angr.procedures.libc.strlen.strlen, s)
        self.max_null_index = strlen_call.max_null_index
        result = strlen_call.ret_expr

        # Due to analysis memory limits, angr does not consider strings longer than
        # 128 character (or containing more than 60 symbolic characters). This is
        # too small and can cause overflow bugs to be missed. To get around this,
        # without blowing up the constraint solver, we rescan memory and if it is
        # possible the string is greater than 128 characters, we tweak strlen's
        # result to be the original result *or* the newly discovered max length.
        orig_max = self.state.solver.max(result)
        if orig_max < self.max_ovf_len:
            if wchar:
                null_seq = self.state.solver.BVV(0, 16)
                step = 2
            else:
                null_seq = self.state.solver.BVV(0, 8)
                step = 1

            chunk_size = None
            if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
                chunk_size = 1

            r, c, i = self.state.memory.find(
                s,
                null_seq,
                self.max_ovf_len,
                max_symbolic_bytes=self.max_ovf_len,
                step=step,
                chunk_size=chunk_size,
            )

            if len(i) > 0:
                ovf_max = max(i)
                if ovf_max > orig_max:
                    ovf_result = self.state.solver.BVS("strlen", len(result))
                    ovf_con = self.state.solver.Or(
                        ovf_result == result, ovf_result == ovf_max
                    )
                    self.state.solver.add(ovf_con)
                    self.max_null_index = ovf_max
                    result = ovf_result

        return result


def apply_hooks(project):
    """Applies any hooks that seem relevant to the project."""
    for obj_name in project.loader.shared_objects:
        for name in plugins.hooks.loaded:
            try:
                module = plugins.hooks.loaded[name]
                filter, hooks_dict = module.hook_condition
                # due to how we setup the project, main objects will have a base VA prefixed
                # to their name, so we have to account for this
                if module.is_main_object:
                    filter = "[0-9a-fA-F]+-" + filter

                if re.match(filter, obj_name):
                    for hook_name in hooks_dict:
                        log.debug("Hooking %s:%s" % (obj_name, hook_name))
                        project.hook_symbol(hook_name, hooks_dict[hook_name]())
                    # we hook symbols, so even if multiple objects match a filter,
                    # the hooks only need to be applied once
                    break
            except Exception as ex:
                log.warn("Failed to hook %s: %s" % (obj_name, str(ex)))

    # allowing angr to use this simproc will cause a desync
    project.unhook_symbol("__libc_start_main")

    # angr should use our epoll simulated procedures everywhere
    project.hook_symbol("epoll_ctl", linux_epoll_ctl())
    project.hook_symbol("epoll_wait", linux_epoll_wait())

    # to help find overflows, we need to monkey-patch angr to use our strlen
    # instead of the original one, even for inline calls
    strlen_simproc = strlen()
    angr.SIM_PROCEDURES["libc"]["strlen"] = strlen
    project.hook_symbol("strlen", strlen_simproc)
