# coding: utf-8

'''
Python wrapper for ptrace.
'''

import json
import ctypes
import platform
from collections import Sequence
import functools

from pyptrace.const import *
from pyptrace.ext import os as extos

SI_KERNEL   = 0x80
SI_USER     = 0x0

class X64UserRegs(ctypes.Structure):
    '''
    x64 UserRegs structure, see /usr/include/sys/user.h.
    '''
    _fields_ = [
        ('r15',     ctypes.c_uint64),
        ('r14',     ctypes.c_uint64),
        ('r13',     ctypes.c_uint64),
        ('r12',     ctypes.c_uint64),
        ('rbp',     ctypes.c_uint64),
        ('rbx',     ctypes.c_uint64),
        ('r11',     ctypes.c_uint64),
        ('r10',     ctypes.c_uint64),
        ('r9',      ctypes.c_uint64),
        ('r8',      ctypes.c_uint64),
        ('rax',     ctypes.c_uint64),
        ('rcx',     ctypes.c_uint64),
        ('rdx',     ctypes.c_uint64),
        ('rsi',     ctypes.c_uint64),
        ('rdi',     ctypes.c_uint64),
        ('orig_rax',ctypes.c_uint64),
        ('rip',     ctypes.c_uint64),
        ('cs',      ctypes.c_uint64),
        ('eflags',  ctypes.c_uint64),
        ('rsp',     ctypes.c_uint64),
        ('ss',      ctypes.c_uint64),
        ('fs_base', ctypes.c_uint64),
        ('gs_base', ctypes.c_uint64),
        ('ds',      ctypes.c_uint64),
        ('es',      ctypes.c_uint64),
        ('fs',      ctypes.c_uint64),
        ('gs',      ctypes.c_uint64),
    ]

class X32UserRegs(ctypes.Structure):
    '''
    x32 UserRegs structure, see /usr/include/sys/user.h.
    '''

    _fields_ = [
        ("ebx",			ctypes.c_uint32),
        ("ecx",			ctypes.c_uint32),
        ("edx",			ctypes.c_uint32),
        ("esi",			ctypes.c_uint32),
        ("edi",			ctypes.c_uint32),
        ("ebp",			ctypes.c_uint32),
        ("eax",			ctypes.c_uint32),
        ("xds",			ctypes.c_uint32),
        ("xes",			ctypes.c_uint32),
        ("xfs",			ctypes.c_uint32),
        ("xgs",			ctypes.c_uint32),
        ("orig_eax",	ctypes.c_uint32),
        ("eip",			ctypes.c_uint32),
        ("xcs",			ctypes.c_uint32),
        ("eflags",		ctypes.c_uint32),
        ("esp",			ctypes.c_uint32),
        ("xss",			ctypes.c_uint32),
    ]

class UnsupportArchException(Exception):
    pass

class PtraceException(Exception):
    pass

'''
UserRegs structure, PyPtrace will choose bwtween X32UserRegs/X64UserRegs
according to the machine arch that it is running on.
'''
UserRegs = None
WORD_SIZE = None

arch = platform.machine()
if arch == 'x86_64':
    UserRegs = X64UserRegs
    WORD_SIZE = 8
    DR_BASE = 848
elif arch == 'i686':
    UserRegs = X32UserRegs
    WORD_SIZE = 4
    DR_BASE = 252
else:
    raise UnsupportArchException(arch)


BP_FLAG_EXEC         = 0x00
BP_FLAG_WRITE        = 0X01
BP_FLAG_READ_WRITE   = 0x03

BP_LEN_1 = 0x00
BP_LEN_2 = 0x01
BP_LEN_4 = 0X11

def DR7(dr_idx, bp_flag=BP_FLAG_EXEC, bp_len=BP_LEN_1):
    return (0x03 << (dr_idx * 2)) | ((bp_flag | (bp_len << 2)) << (dr_idx * 4 + 16))

def DR_OFFSET(dr_idx):
    return DR_BASE + dr_idx * WORD_SIZE

class RegsWrapper(object):
    '''
    Wrapper for UserRegs, for pretty printing of UserRegs.
    '''

    def __init__(self, regs):
        self.regs = regs

    def __str__(self):
        if not self.regs:
            return None

        def reg_val(reg_name):
            reg = getattr(self.regs, reg_name)
            val = reg.real if hasattr(reg, 'real') else None
            if val: val = '0x{:016x}'.format(val)

            return val

        # register does not starts with '_'
        reg_names = [attr for attr in dir(self.regs) if not attr.startswith('_')]
        reg_dict = {reg_name: reg_val(reg_name) for reg_name in reg_names}
        return json.dumps(reg_dict, indent=4)

def check_ret(fn):
    '''
    Decorator for ptrace requests.
    This decorator will check the resutl for ptrace request and
    throw exception if throw_exception == True.
    '''

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        throw_exception = kwargs.get('throw_exception', True)
        if 'throw_exception' in kwargs:
            del kwargs['throw_exception']

        ret = fn(*args, **kwargs)
        errno = ret[0] if isinstance(ret, Sequence) else  ret 
        if errno != 0 and throw_exception is True:
            raise PtraceException('Failed executing %s' % fn.func_name)

        return ret 

    return wrapper

@check_ret
def attach(pid):
    '''
    Attach  to  the process specified in pid, making it a tracee of the
    calling process.
    '''

    return extos.ptrace(PTRACE_ATTACH, pid, 0, 0)

@check_ret
def cont(pid, signo=0):
    '''
    Restart  the  stopped  tracee  process. If signo is nonzero, it is
    interpreted as the number of a signal to be delivered to the tracee;
    otherwise, no signal is delivered.
    '''

    return extos.ptrace(PTRACE_CONT, pid, 0, signo)

@check_ret
def traceme():
    '''
    Indicate that this process is to be traced by its parent.
    '''

    return extos.ptrace(PTRACE_TRACEME, 0, 0, 0)

@check_ret
def detach(pid, signo):
    '''
    Restart  the stopped tracee as for cont(), but first detach from it.
    '''

    return extos.ptrace(PTRACE_DETACH, pid, 0, signo)

@check_ret
def peektext(pid, addr):
    '''
    Read  a  word  at  the address addr in the tracee's text memory, returning
    the word as the result of the peektext() call.
    '''

    return extos.ptrace_peek(PTRACE_PEEKTEXT, pid, addr)

@check_ret
def peekdata(pid, addr):
    '''
    Read  a  word  at  the address addr in the tracee's data memory, returning
    the word as the result of the peektext() call.
    '''

    return extos.ptrace_peek(PTRACE_PEEKDATA, pid, addr)

@check_ret
def peekuser(pid, addr):
    '''
    Read a word at offset addr in the tracee's USER area,  which  holds  the
    registers  and  other  information  about  the  process (see <sys/user.h>).
    '''

    return extos.ptrace_peek(PTRACE_PEEKUSER, pid, addr)

# FIXME OverflowError: 'Python int too large to convert to C long'
@check_ret
def poketext(pid, addr, data):
    '''
    Copy the word data to the address addr in the tracee's text memory.
    '''

    return extos.ptrace(PTRACE_POKETEXT, pid, addr, data)

@check_ret
def pokedata(pid, addr, data):
    '''
    Copy the word data to the address addr in the tracee's data memory.
    '''

    return extos.ptrace(PTRACE_POKEDATA, pid, addr, data)

@check_ret
def pokeuser(pid, addr, data):
    '''
    Copy  the  word  data to offset addr in the tracee's USER area.
    '''

    return extos.ptrace(PTRACE_POKEUSER, pid, addr, data)

@check_ret
def singlestep(pid, signo=0):
    '''
    Restart  the  stopped  tracee  as  for cont(), but arrange for the tracee
    to be stopped at the next entry to or exit after a single instruction.
    '''

    return extos.ptrace(PTRACE_SINGLESTEP, pid, 0, signo)

@check_ret
def syscall(pid, signo=0):
    '''
    Restart  the  stopped  tracee  as  for cont(), but arrange for the tracee
    to be stopped at the next entry to or exit from a system call.
    '''

    return extos.ptrace(PTRACE_SYSCALL, pid, 0, signo)

@check_ret
def setoptions(pid, options):
    '''
    Set  ptrace  options from options.
    '''

    return extos.ptrace(PTRACE_SETOPTIONS, pid, 0, options)

_libc = ctypes.cdll.LoadLibrary('libc.so.6')

@check_ret
def getregs(pid):
    '''
    Return the tracee's general-purpose registers.
    '''

    regs = UserRegs()
    _libc_ptrace = _libc.ptrace
    _libc_ptrace.restype = ctypes.c_long
    _libc_ptrace.argtypes = (ctypes.c_long, ctypes.c_int,
                             ctypes.c_void_p, ctypes.POINTER(UserRegs))

    ret = _libc_ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
    return ret, regs

@check_ret
def setregs(pid, regs):
    '''
    Modify the tracee's general-purpose registers,  respectively,  from  the
    paramater  regs.
    '''

    _libc_ptrace = _libc.ptrace
    _libc_ptrace.restype = ctypes.c_long
    _libc_ptrace.argtypes = (ctypes.c_long, ctypes.c_int,
                             ctypes.c_void_p, ctypes.POINTER(UserRegs))

    ret = _libc_ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
    return ret

@check_ret
def getsiginfo(pid):
    '''
    Retrieve  information  about  the  signal  that  caused the stop.
    '''

    siginfo = extos.Siginfo()
    _libc_ptrace = _libc.ptrace
    _libc_ptrace.restype = ctypes.c_long
    _libc_ptrace.argtypes = (ctypes.c_long, ctypes.c_int,
                             ctypes.c_void_p, ctypes.POINTER(extos.Siginfo))

    ret = _libc_ptrace(PTRACE_GETSIGINFO, pid, None, ctypes.byref(siginfo))
    return ret, siginfo

# @check_ret
# def poketext(pid, addr, data):
#     '''
#     Copy the word data to the address addr in the tracee's text memory.
#     '''
#     _libc_ptrace = _libc.ptrace
#     _libc_ptrace.restype = ctypes.c_long
#     _libc_ptrace.argtypes = (ctypes.c_long, ctypes.c_int,
#                              ctypes.c_long, ctypes.c_long)
# 
#     # print 'pid: %d, addr: 0x%x, data: 0x%x' % (pid, addr, data)
#     # return extos.ptrace(PTRACE_POKETEXT, pid, addr, data)
#     ret = _libc_ptrace(PTRACE_POKETEXT, pid, addr, data)
#     return ret
# 
