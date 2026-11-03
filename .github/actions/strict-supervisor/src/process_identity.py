"""Return a typed kernel process identity observation; failures are not absence."""
import ctypes
import errno
import json
import sys


def observe(pid):
    try:
        if sys.platform.startswith('linux'):
            try:
                with open(f'/proc/{pid}/stat', encoding='ascii') as f:
                    stat = f.read()
            except FileNotFoundError:
                # Missing procfs is not evidence that the target exited.
                with open('/proc/self/stat', encoding='ascii') as probe:
                    if not probe.read():
                        raise ValueError('procfs unavailable')
                return {'status': 'ABSENT', 'pid': pid}
            end = stat.rfind(')')
            if end < 0 or not stat.startswith(f'{pid} ('):
                raise ValueError('malformed proc stat')
            fields = stat[end + 2:].split()
            if len(fields) < 20 or len(fields[0]) != 1:
                raise ValueError('short proc stat')
            birth, ppid = fields[19], int(fields[1])
            if not birth.isdigit() or ppid < 0:
                raise ValueError('invalid proc stat identity')
            return {'status': 'LIVE', 'pid': pid, 'birth': birth,
                    'ppid': ppid, 'state': fields[0]}
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
        ctypes.set_errno(0)
        result = lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        error = ctypes.get_errno()
        if result == 0 and error == errno.ESRCH:
            return {'status': 'ABSENT', 'pid': pid}
        if result != ctypes.sizeof(info) or info.pid != pid or not info.start_sec:
            raise OSError(error, 'proc_pidinfo identity unavailable')
        # Darwin's SZOMB is 5; preserve other kernel states as their numeric value.
        state = 'Z' if info.status == 5 else str(info.status)
        return {'status': 'LIVE', 'pid': pid,
                'birth': f'{info.start_sec}.{info.start_usec:06d}',
                'ppid': info.ppid, 'state': state}
    except (OSError, ValueError, IndexError, UnicodeError, RuntimeError) as exc:
        return {'status': 'UNKNOWN', 'pid': pid, 'reason': str(exc)}


if __name__ == '__main__':
    try:
        pid = int(sys.argv[1])
        if pid <= 1:
            raise ValueError('invalid pid')
        result = observe(pid)
    except (IndexError, ValueError) as exc:
        result = {'status': 'UNKNOWN', 'reason': str(exc)}
    print(json.dumps(result, separators=(',', ':')))
