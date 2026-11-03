"""Read kernel process birth time with sub-second identity, or fail closed."""
import ctypes
import os
import sys


def identity(pid):
    if sys.platform.startswith('linux'):
        with open(f'/proc/{pid}/stat', encoding='ascii') as f:
            stat = f.read()
        # The parenthesized comm may itself contain spaces or parentheses.
        fields = stat[stat.rfind(')') + 2:].split()
        return fields[19]
    if sys.platform != 'darwin':
        raise RuntimeError('unsupported process identity platform')
    class BSDInfo(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint32) for n in (
            'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid',
            'ruid', 'rgid', 'svuid', 'svgid', 'rfu1')] + [
            ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32),
        ] + [(n, ctypes.c_uint32) for n in (
            'nfiles', 'pgid', 'pjobc', 'e_tdev', 'e_tpgid')] + [
            ('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
            ('start_usec', ctypes.c_uint64)]
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    info = BSDInfo()
    result = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if result != ctypes.sizeof(info) or info.pid != pid or not info.start_sec:
        raise OSError(ctypes.get_errno(), 'proc_pidinfo identity unavailable')
    return f'{info.start_sec}.{info.start_usec:06d}'


if __name__ == '__main__':
    print(identity(int(sys.argv[1])))
