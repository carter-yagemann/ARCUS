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
import os

import angr
from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

log = logging.getLogger(name=__name__)


## Global Constants
WCHAR_BYTES = 4


class libc_clock_gettime(angr.SimProcedure):

    timespec_bits = 16 * 8

    def run(self, clockid, tp):
        if self.state.solver.is_true(tp == 0):
            return -1

        result = {
            'tv_sec': self.state.solver.BVS('tv_sec', self.arch.bits, key=('api', 'clock_gettime', 'tv_sec')),
            'tv_nsec': self.state.solver.BVS('tv_nsec', self.arch.bits, key=('api', 'clock_gettime', 'tv_nsec')),
        }

        self.state.mem[tp].struct.timespec = result
        return 0

class libc___cxa_atexit(angr.SimProcedure):
    def run(self, func):
        # we don't actually care about at_exit callbacks
        return 0


class libc_atol(angr.SimProcedure):
    def handle_symbolic(self, s):
        strtol = angr.SIM_PROCEDURES["libc"]["strtol"]
        ret = strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
        log.debug(
            "atol's return: [%#x-%#x]"
            % (self.state.solver.min(ret), self.state.solver.max(ret))
        )
        return ret

    def run(self, s):
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString())}

        if self.state.solver.symbolic(s):
            ret = self.handle_symbolic(s)
        else:
            strlen = self.state.memory.find(s, b"\x00", 256, default=s + 256)[2][0]
            if strlen == 0:
                ret = self.handle_symbolic(s)
            else:
                str = self.state.memory.load(s, strlen)
                str = self.state.solver.eval(str, cast_to=bytes).decode("utf8")
                log.debug("atol concrete string: %s" % str)
                ret = int(str, 10)
                log.debug("atol's return: [%#x]" % ret)

        return ret


class libc_strrchr(angr.SimProcedure):
    def run(self, s_addr, c_int, s_strlen=None):
        """This SimProcedure is a lot looser than angr's strchr, but that's okay
        because we have a concrete trace."""
        Or = self.state.solver.Or
        And = self.state.solver.And

        s_strlen = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)
        ret = self.state.solver.BVS("strrchr", 64)

        if self.state.solver.symbolic(s_strlen.ret_expr):
            log.debug("symbolic strlen")
            self.state.add_constraints(
                Or(And(ret >= s_addr, ret < s_addr + s_strlen.max_null_index), ret == 0)
            )
        else:
            log.debug("concrete strlen")
            max_search = self.state.solver.eval(s_strlen.ret_expr) + 1
            self.state.add_constraints(
                Or(And(ret >= s_addr, ret < s_addr + max_search), ret == 0)
            )

        return ret


class libc_gai_strerror(angr.SimProcedure):
    def run(self, errcode):
        err_buf = self.inline_call(angr.SIM_PROCEDURES["libc"]["malloc"], 256).ret_expr
        self.state.memory.store(err_buf + 255, b"\x00")

        return err_buf


class libc_getaddrinfo(angr.SimProcedure):
    def run(self, node, service, hints, res):
        ret = self.state.solver.BVS("getaddrinfo_ret", self.arch.bits)
        return ret


class libc_getenv(angr.SimProcedure):
    def run(self, name):
        Or = self.state.solver.Or
        And = self.state.solver.And

        name_strlen = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], name)
        name_str = self.state.memory.load(name, name_strlen.ret_expr)
        if self.state.solver.symbolic(name_str):
            name_sym = True
            log.debug("getenv: searching for (symbolic)")
        else:
            name_sym = False
            name_str = self.state.solver.eval(name_str, cast_to=bytes).decode("utf8")
            log.debug("getenv: searching for %s" % name_str)

        envpp = self.state.solver.eval(self.state.posix.environ)
        ret_val = self.state.solver.BVS("getenv", self.arch.bits)
        ret_expr = ret_val == 0
        while True:
            try:
                envp = self.state.solver.eval(
                    self.state.memory.load(
                        envpp,
                        self.state.arch.bytes,
                        endness=self.state.arch.memory_endness,
                    )
                )
                if envp == 0:
                    break
                envp_strlen = self.inline_call(
                    angr.SIM_PROCEDURES["libc"]["strlen"], envp
                )
                envp_str = self.state.memory.load(envp, envp_strlen.ret_expr)
                if name_sym or self.state.solver.symbolic(envp_str):
                    ret_expr = Or(
                        ret_expr,
                        And(ret_val > envp, ret_val < (envp + envp_strlen.ret_expr)),
                    )
                else:
                    # we can make the variable concrete
                    envp_str = self.state.solver.eval(envp_str, cast_to=bytes).decode(
                        "utf8"
                    )
                    key = envp_str.split("=")[0]
                    if key == name_str:
                        log.debug("getenv: Found concrete match")
                        return envp + len(key) + 1

                envpp += self.state.arch.bytes
            except Exception as ex:
                log.error("Error in getenv hook: %s" % str(ex))
                break

        self.state.add_constraints(ret_expr)
        return ret_val


class libc_getlogin(angr.SimProcedure):

    LOGIN_PTR = None

    def run(self):
        if self.LOGIN_PTR is None:
            self.LOGIN_PTR = self.inline_call(
                angr.SIM_PROCEDURES["libc"]["malloc"], 256
            ).ret_expr
            self.state.memory.store(self.LOGIN_PTR + 255, b"\x00")
        return self.LOGIN_PTR


class libc_getpwnam(angr.SimProcedure):

    PASSWD_PTR = None
    CHAR_PTRS = {
        "pw_name": None,
        "pw_paswd": None,
        "pw_gecos": None,
        "pw_dir": None,
        "pw_shell": None,
    }

    def run(self, name):
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]

        if self.PASSWD_PTR is None:
            # allocate strings
            for ptr in self.CHAR_PTRS:
                self.CHAR_PTRS[ptr] = self.inline_call(malloc, 4096).ret_expr
                self.state.memory.store(self.CHAR_PTRS[ptr] + 4095, b"\x00")

            # allocate passwd struct
            ptr_size = self.state.arch.bytes
            passwd_size = (ptr_size * len(self.CHAR_PTRS)) + 8
            self.PASSWD_PTR = self.inline_call(malloc, passwd_size).ret_expr

            # fill in struct values
            ptr = self.PASSWD_PTR
            for pw_str in ["pw_name", "pw_paswd"]:
                self.state.memory.store(
                    ptr,
                    self.CHAR_PTRS[pw_str],
                    size=ptr_size,
                    endness=self.state.arch.memory_endness,
                )
                ptr += ptr_size
            for pw_sym in ["pw_uid", "pw_gid"]:
                self.state.memory.store(ptr, self.state.solver.BVS(pw_sym, 32))
                ptr += 4
            for pw_str in ["pw_gecos", "pw_dir", "pw_shell"]:
                self.state.memory.store(
                    ptr,
                    self.CHAR_PTRS[pw_str],
                    size=ptr_size,
                    endness=self.state.arch.memory_endness,
                )
                ptr += ptr_size

        return self.PASSWD_PTR

class libc_mbsrtowcs(angr.SimProcedure):

    max_dest_size = 2048

    def run(self, dest, src, len, ps):
        # return value is number of wide characters parsed
        ret = self.state.solver.BVS("mbsrtowcs_ret", self.state.arch.bits)
        self.state.add_constraints(ret <= len)

        # pointer at src is updated to point after last parsed character
        src_base = self.state.memory.load(src, self.state.arch.bytes,
                endness=self.state.arch.memory_endness)
        src_res = self.state.solver.BVS("mbsrtowcs_src", self.state.arch.bits)
        self.state.add_constraints(src_res >= src_base)
        self.state.add_constraints(src_res <= src_base + len)
        self.state.memory.store(src, src_res, endness=self.state.arch.memory_endness)

        if not self.state.solver.is_true(dest == 0):
            # if provided, converted wide characters are written to dest
            dest_size = self.state.solver.max(len) * WCHAR_BYTES
            # limit in case len is unconstrained
            dest_size = min(dest_size, self.max_dest_size)
            for offset in range(dest_size):
                oc = self.state.solver.BVS("wchar_b%d" % offset, 8)
                self.state.memory.store(dest + offset, oc)

        return ret

class libc_realpath(angr.SimProcedure):
    MAX_PATH = 4096

    def run(self, path_ptr, resolved_path):

        resolved_path_val = self.state.solver.eval(resolved_path)
        if resolved_path_val == 0:
            buf = self.inline_call(
                angr.SIM_PROCEDURES["libc"]["malloc"], self.MAX_PATH
            ).ret_expr
        else:
            buf = resolved_path

        path_len = self.inline_call(
            angr.SIM_PROCEDURES["libc"]["strlen"], path_ptr
        ).ret_expr
        path_expr = self.state.memory.load(path_ptr, path_len)
        if self.state.solver.symbolic(path_expr):
            self.state.memory.store(
                buf, self.state.solver.BVS("realpath", self.MAX_PATH * 8)
            )
        else:
            cwd = self.state.fs.cwd.decode("utf8")
            path_str = self.state.solver.eval(path_expr, cast_to=bytes).decode("utf8")
            normpath = os.path.normpath(os.path.join(cwd, path_str))[
                : self.MAX_PATH - 1
            ]
            self.state.memory.store(buf, normpath.encode("utf8") + b"\x00")

        return buf


class libc_snprintf(FormatParser):
    """Custom snprintf simproc because angr's doesn't honor the size argument"""

    def run(self, dst_ptr, size):

        if self.state.solver.eval(size) == 0:
            return size

        # The format str is at index 2
        fmt_str = self._parse(2)
        out_str = fmt_str.replace(3, self.arg)

        # enforce size limit
        size = self.state.solver.max(size)
        if (out_str.size() // 8) > size - 1:
            out_str = out_str.get_bytes(0, size - 1)

        # store resulting string
        self.state.memory.store(dst_ptr, out_str)

        # place the terminating null byte
        self.state.memory.store(
            dst_ptr + (out_str.size() // 8), self.state.solver.BVV(0, 8)
        )

        # size_t has size arch.bits
        return self.state.solver.BVV(out_str.size() // 8, self.state.arch.bits)


class libc__fprintf_chk(FormatParser):
    def run(self, stream, flag, fmt):
        # look up stream
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[stream + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        # format str is arg index 2
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        # write to stream
        simfd.write_data(out_str, out_str.size() // 8)

        return out_str.size() // 8


class libc__snprintf_chk(FormatParser):
    """Custom __snprintf_chk simproc because angr's doesn't honor the size argument"""

    def run(self, s, maxlen, flag, slen, fmt):
        # The format str is at index 4
        fmt_str = self._parse(4)
        out_str = fmt_str.replace(5, self.arg)

        # enforce size limit
        size = self.state.solver.max(slen)
        if (out_str.size() // 8) > slen - 1:
            out_str = out_str.get_bytes(0, max(slen - 1, 1))

        # store resulting string
        self.state.memory.store(s, out_str)

        # place the terminating null byte
        self.state.memory.store(s + (out_str.size() // 8), self.state.solver.BVV(0, 8))

        # size_t has size arch.bits
        return self.state.solver.BVV(out_str.size() // 8, self.state.arch.bits)


class libc_strncat(angr.SimProcedure):
    def run(self, dst, src, num):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
        src_len = self.inline_call(strlen, src).ret_expr
        dst_len = self.inline_call(strlen, dst).ret_expr
        if (src_len > num).is_true():
            max_len = num
        else:
            max_len = src_len
        self.inline_call(strncpy, dst + dst_len, src, max_len + 1, src_len=src_len)
        return dst


class libc_setlocale(angr.SimProcedure):
    locale = None
    def run (self, category, locale):
        if self.locale is None:
            self.locale = self.inline_call(
                angr.SIM_PROCEDURES["libc"]["malloc"], 256
            ).ret_expr
            self.state.memory.store(self.locale + 255, b"\x00")
        return self.locale

class libc_bindtextdomain(angr.SimProcedure):
    domainname = None
    def run (self, domainname, dirname):
        if self.domainname is None:
            self.domainname = self.inline_call(
               angr.SIM_PROCEDURES["libc"]["malloc"], 256
            ).ret_expr
            self.state.memory.store(self.domainname + 255, b"\x00")
        return self.domainname

class libc_textdomain(angr.SimProcedure):
    domainname = None
    def run (self, domainname):
        if self.domainname is None:
            self.domainname = self.inline_call(
               angr.SIM_PROCEDURES["libc"]["malloc"], 256
            ).ret_expr
            self.state.memory.store(self.domainname + 255, b"\x00")
        return self.domainname

class libc_signal(angr.SimProcedure):
    SIG_HNDLR = {}
    def run(self, signum, handler):
        signum_int = self.state.solver.eval(signum)
        if signum_int not in self.SIG_HNDLR:
            self.SIG_HNDLR[signum_int] = self.state.solver.BVV(-1, self.state.arch.bits)
        old = self.SIG_HNDLR[signum_int]
        self.SIG_HNDLR[signum_int] = handler
        return old

class libc_sysconf(angr.SimProcedure):

    def run(self, name):
        return self.state.solver.BVS("sysconf_ret", self.state.arch.bits)

class libc_wcschr(angr.SimProcedure):

    max_null_index = 1024

    def run(self, wcs, wc):
        wcs_len = self.inline_call(libc_wcslen, wcs)

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.solver.symbolic(wcs_len.ret_expr):
            log.debug("symbolic wcslen")
            max_sym = min((self.state.solver.max_int(wcs_len.ret_expr) * WCHAR_BYTES) + WCHAR_BYTES,
                    self.state.libc.max_symbolic_strchr)
            a, c, i = self.state.memory.find(wcs, wc, self.max_null_index,
                    max_symbolic_bytes=max_sym, default=0, char_size=WCHAR_BYTES)
        else:
            log.debug("concrete wcslen")
            max_search = (self.state.solver.eval(wcs_len.ret_expr) * WCHAR_BYTES) + WCHAR_BYTES
            a, c, i = self.state.memory.find(wcs, wc, max_search, default=0, chunk_size=chunk_size,
                    char_size=WCHAR_BYTES)

        if len(i) > 1:
            a = a.annotate(MultiwriteAnnotation())
            self.state.add_constraints(*c)

        chrpos = a - wcs
        self.state.add_constraints(self.state.solver.If(a != 0,
                chrpos <= wcs_len.ret_expr * WCHAR_BYTES, True))

        return a

class libc_wcslen(angr.SimProcedure):

    def run(self, s):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        res = self.inline_call(strlen, s, wchar=True)
        return res.ret_expr

class libc_wcsncpy(angr.SimProcedure):

    def run(self, dest, src, n):
        n_val = self.state.solver.max(n)
        for offset in range(0, n_val * WCHAR_BYTES, WCHAR_BYTES):
            wchar = self.state.memory.load(src + offset, WCHAR_BYTES,
                    endness=self.state.arch.memory_endness)
            self.state.memory.store(dest + offset, wchar,
                    endness=self.state.arch.memory_endness)
            if self.state.solver.is_true(wchar == 0):
                break

        return dest

class libc_wcspbrk(angr.SimProcedure):

    def run(self, wcs, accept):
        Or = self.state.solver.Or
        And = self.state.solver.And

        len = self.inline_call(libc_wcslen, wcs).ret_expr

        ptr = self.state.solver.BVS("wcspbrk_ret", self.state.arch.bits)
        # either points to a match within the provided string or NULL
        # if no match was found
        ptr_expr = Or(ptr == 0, And(ptr >= wcs, ptr < wcs + (len * WCHAR_BYTES)))

        self.state.add_constraints(ptr_expr)
        return ptr

class libc_wcsrtombs(angr.SimProcedure):

    max_dest_size = 2048

    def run(self, dest, src, len, ps):
        # return value is number of multibyte characters parsed
        ret = self.state.solver.BVS("wcsrtombs_ret", self.state.arch.bits)
        self.state.add_constraints(ret <= len)

        # pointer at src is updated to point after last parsed character
        src_base = self.state.memory.load(src, self.state.arch.bytes,
                endness=self.state.arch.memory_endness)
        src_len = self.inline_call(libc_wcslen, src).ret_expr * WCHAR_BYTES

        src_res = self.state.solver.BVS("wcsrtombs_src", self.state.arch.bits)
        self.state.add_constraints(src_res >= src_base)
        self.state.add_constraints(src_res <= src_base + src_len)
        self.state.memory.store(src, src_res, endness=self.state.arch.memory_endness)

        if not self.state.solver.is_true(dest == 0):
            # if provided, converted multibyte characters are written to dest
            dest_size = self.state.solver.max(len)
            # limit in case len is unconstrained
            dest_size = min(dest_size, self.max_dest_size)
            for offset in range(dest_size):
                oc = self.state.solver.BVS("mbs_b%d" % offset, 8)
                self.state.memory.store(dest + offset, oc)

        return ret


libc_hooks = {
    # Additional functions that angr doesn't provide hooks for
    "atol": libc_atol,
    "clock_gettime": libc_clock_gettime,
    "__cxa_atexit": libc___cxa_atexit,
    "exit": angr.SIM_PROCEDURES["libc"]["exit"],
    "__fprintf_chk": libc__fprintf_chk,
    "gai_strerror": libc_gai_strerror,
    "getaddrinfo": libc_getaddrinfo,
    "getenv": libc_getenv,
    # kernel and libc have the same API
    "getcwd": angr.procedures.linux_kernel.cwd.getcwd,
    "getlogin": libc_getlogin,
    "getpwnam": libc_getpwnam,
    "mbsrtowcs": libc_mbsrtowcs,
    "realpath": libc_realpath,
    # secure_getenv and getenv work the same from a symbolic perspective
    "secure_getenv": libc_getenv,
    "snprintf": libc_snprintf,
    "__snprintf_chk": libc__snprintf_chk,
    "strncat": libc_strncat,
    "strrchr": libc_strrchr,
    "setlocale":libc_setlocale,
    "bindtextdomain": libc_bindtextdomain,
    "textdomain": libc_textdomain,
    "signal": libc_signal,
    "sysconf": libc_sysconf,
    "mmap": angr.procedures.posix.mmap.mmap,
    "wcschr": libc_wcschr,
    "wcslen": libc_wcslen,
    "wcsncpy": libc_wcsncpy,
    "wcspbrk": libc_wcspbrk,
    "wcsrtombs": libc_wcsrtombs,
}

hook_condition = ("libc\.so.*", libc_hooks)
is_main_object = False
