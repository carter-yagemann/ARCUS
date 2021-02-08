import ctypes

class Siginfo(ctypes.Structure):
    _fields_ = [
        ('si_signo',    ctypes.c_int),
        ('si_errno',    ctypes.c_int),
        ('si_code',     ctypes.c_int),
        ('si_trapno',   ctypes.c_int),

        ('si_pid',      ctypes.c_uint),
        ('si_uid',      ctypes.c_uint),
        ('si_status',   ctypes.c_int),
        ('si_utime',    ctypes.c_long),
        ('si_stime',    ctypes.c_long),
        ('si_value',    ctypes.c_long),
        ('si_int',      ctypes.c_int),
        ('si_ptr',      ctypes.c_void_p),
        ('si_overrun',  ctypes.c_int),

        ('si_timerid',  ctypes.c_int),
        ('si_addr',     ctypes.c_void_p),
        ('si_band',     ctypes.c_long),

        ('si_fd',       ctypes.c_int),
        ('si_addr_lsb', ctypes.c_short),

        ('si_call_addr',ctypes.c_void_p),

        ('si_syscall',  ctypes.c_int),

        ('si_arch',     ctypes.c_uint)
    ]

__SI_FAULT      = 0

'''
SIGTRAP si_codes
'''
TRAP_BRKPT      = (__SI_FAULT|1)  # process breakpoint
TRAP_TRACE      = (__SI_FAULT|2)  # process trace trap
TRAP_BRANCH     = (__SI_FAULT|3)  # process taken branch trap
TRAP_HWBKPT     = (__SI_FAULT|4)  # hardware breakpoint/watchpoint
NSIGTRAP        = 4

_libc = ctypes.cdll.LoadLibrary('libc.so.6')
def strsignal(signo):
    _libc_strsignal = _libc.strsignal
    _libc_strsignal.restype = ctypes.c_char_p
    _libc_strsignal.argtypes = (ctypes.c_int,)

    ret = _libc_strsignal(signo)
    return ret
