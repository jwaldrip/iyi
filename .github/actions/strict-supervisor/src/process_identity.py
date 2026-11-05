"""Typed kernel process identity observations; a failure is never absence.

Modes:
  process_identity.py PID       one observation of PID, as JSON
  process_identity.py --batch   reads {"pids": [...], "census": bool} on stdin and
                                writes one reply from this single process: the observation of
                                each requested PID, read first, then the census. One helper call
                                per observer poll keeps the cost of a poll independent of how many
                                processes it has seen.

Census rows are [pid, ppid, state, birth]. On Linux each row comes from one /proc read per process,
and a process gone at its read, or unreadable, is a null row. On Darwin the census is one kern.proc.all
read, the same kernel table ps reads: every row is one process record, in kernel order, with no nulls.
Each record carries its pid, ppid, state and microsecond start time, so no row needs a second read.
The Darwin reply also carries the timing of that read (call_start_wall_us, call_start_ns, call_end_ns).
Every Darwin census is self-checked against this process's own record and proc_pidinfo. Any failure is
a census error. Nothing is read through ps.
"""
import ctypes
import errno
import json
import os
import struct
import sys
import time

_LIBPROC = None
_LIBSYSTEM = None

# kern.proc records. The layout is checked on every Darwin census against this process's own record.
_KINFO_PROC_SIZE = 648
_KINFO_SLACK_RECORDS = 64
_KINFO_ENOMEM_RETRIES = 8
_CTL_KERN, _KERN_PROC, _KERN_PROC_ALL, _KERN_PROC_PID = 1, 14, 0, 1
_SZOMB = 5


class _BSDInfo(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid',
        'ruid', 'rgid', 'svuid', 'svgid', 'rfu1')] + [
        ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32),
    ] + [(n, ctypes.c_uint32) for n in (
        'nfiles', 'pgid', 'pjobc', 'e_tdev', 'e_tpgid')] + [
        ('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64),
        ('start_usec', ctypes.c_uint64)]


def _libproc():
    global _LIBPROC
    if _LIBPROC is None:
        _LIBPROC = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    return _LIBPROC


def _libsystem():
    global _LIBSYSTEM
    if _LIBSYSTEM is None:
        lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        lib.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                               ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        lib.sysctl.restype = ctypes.c_int
        _LIBSYSTEM = lib
    return _LIBSYSTEM


def _observe_linux(pid):
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


def _kinfo(mib):
    """Read one kern.proc table. Returns (raw records, timing of the successful read).

    The size query and the read are separate calls. The timing brackets only the successful read,
    which is the call the census edge rule reasons about. A short buffer (ENOMEM) is retried with a
    fresh size query, at most _KINFO_ENOMEM_RETRIES times.
    """
    lib = _libsystem()
    name = (ctypes.c_int * len(mib))(*mib)
    for _ in range(_KINFO_ENOMEM_RETRIES + 1):
        size = ctypes.c_size_t(0)
        if lib.sysctl(name, len(mib), None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), 'kern.proc size query failed')
        cap = ctypes.c_size_t(size.value + _KINFO_SLACK_RECORDS * _KINFO_PROC_SIZE)
        buf = ctypes.create_string_buffer(cap.value)
        wall_us = time.time_ns() // 1000
        start_ns = time.monotonic_ns()
        result = lib.sysctl(name, len(mib), buf, ctypes.byref(cap), None, 0)
        end_ns = time.monotonic_ns()
        err = ctypes.get_errno()
        if result == 0:
            return buf.raw[:cap.value], {'call_start_wall_us': wall_us,
                                         'call_start_ns': start_ns, 'call_end_ns': end_ns}
        if err != errno.ENOMEM:
            raise OSError(err, 'kern.proc read failed')
    raise OSError(errno.ENOMEM, 'kern.proc table kept outgrowing its buffer')


def _records(raw):
    if len(raw) % _KINFO_PROC_SIZE:
        raise ValueError('kern.proc reply is not a whole number of records')
    return [_record(raw[i:i + _KINFO_PROC_SIZE]) for i in range(0, len(raw), _KINFO_PROC_SIZE)]


def _record(rec):
    sec = struct.unpack_from('<q', rec, 0)[0]
    usec = struct.unpack_from('<i', rec, 8)[0]
    stat = rec[36]
    pid = struct.unpack_from('<i', rec, 40)[0]
    ppid = struct.unpack_from('<i', rec, 560)[0]
    if sec < 0 or not 0 <= usec < 1_000_000:
        raise ValueError('kern.proc record has an invalid start time')
    if not 1 <= stat <= 5:
        raise ValueError('kern.proc record has an invalid state')
    if pid < 0 or ppid < 0:
        raise ValueError('kern.proc record has a negative pid')
    # Darwin's SZOMB is 5; preserve other kernel states as their numeric value.
    return {'pid': pid, 'ppid': ppid, 'state': 'Z' if stat == _SZOMB else str(stat),
            'sec': sec, 'usec': usec}


def _birth(row):
    return f"{row['sec']}.{row['usec']:06d}"


def _own_birth():
    pid = os.getpid()
    info = _BSDInfo()
    ctypes.set_errno(0)
    result = _libproc().proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if result != ctypes.sizeof(info) or info.pid != pid or not info.start_sec:
        raise OSError(ctypes.get_errno(), 'own proc_pidinfo identity unavailable')
    return f'{info.start_sec}.{info.start_usec:06d}'


def _observe_darwin(pid):
    if pid > 0x7fffffff:
        raise ValueError('pid exceeds Darwin sysctl integer range')
    raw, _ = _kinfo((_CTL_KERN, _KERN_PROC, _KERN_PROC_PID, pid))
    rows = _records(raw)
    if not rows:
        # No record at this read: the process has been reaped, or never existed.
        return {'status': 'ABSENT', 'pid': pid}
    if len(rows) != 1 or rows[0]['pid'] != pid:
        raise ValueError('kern.proc.pid reply does not name the requested pid')
    row = rows[0]
    if not row['sec']:
        raise ValueError('proc identity has no start time')
    return {'status': 'LIVE', 'pid': pid, 'birth': _birth(row),
            'ppid': row['ppid'], 'state': row['state']}


def observe(pid):
    try:
        if sys.platform.startswith('linux'):
            return _observe_linux(pid)
        if sys.platform != 'darwin':
            raise RuntimeError('unsupported process identity platform')
        return _observe_darwin(pid)
    except (OSError, ValueError, IndexError, UnicodeError, RuntimeError, OverflowError,
            struct.error) as exc:
        return {'status': 'UNKNOWN', 'pid': pid, 'reason': str(exc)}


def _census_darwin():
    raw, timing = _kinfo((_CTL_KERN, _KERN_PROC, _KERN_PROC_ALL))
    rows = _records(raw)
    pids = [row['pid'] for row in rows]
    if len(set(pids)) != len(pids):
        raise ValueError('census lists a pid twice')
    by_pid = {row['pid']: row for row in rows}
    if 1 not in by_pid:
        raise ValueError('census lacks pid 1')
    me = by_pid.get(os.getpid())
    if me is None:
        raise ValueError('census lacks the helper own row')
    if me['ppid'] != os.getppid():
        raise ValueError('census ppid of the helper does not match getppid')
    if _birth(me) != _own_birth():
        raise ValueError('census birth of the helper does not match proc_pidinfo')
    return {'rows': [[row['pid'], row['ppid'], row['state'], _birth(row)] for row in rows],
            **timing}


def census():
    """Every listed process as {'rows': [[pid, ppid, state, birth], ...]}, in kernel order.

    Darwin also returns call_start_wall_us, call_start_ns and call_end_ns for its one kern.proc.all read.
    """
    if sys.platform.startswith('linux'):
        rows = []
        for name in os.listdir('/proc'):
            if not name.isdigit():
                continue
            pid = int(name)
            obs = observe(pid)
            if obs['status'] in ('ABSENT', 'UNKNOWN'):
                # Gone at its own read, or unreadable: no parent edge is known, so the census cannot be trusted.
                rows.append([pid, None, None, None])
            else:
                rows.append([pid, obs['ppid'], obs['state'], obs['birth']])
        return {'rows': rows}
    if sys.platform != 'darwin':
        raise RuntimeError('unsupported process census platform')
    return _census_darwin()


def batch(request):
    if not isinstance(request, dict):
        raise ValueError('invalid observation request')
    pids = request.get('pids', [])
    if not isinstance(pids, list) or any(isinstance(p, bool) or not isinstance(p, int) for p in pids):
        raise ValueError('invalid pid list')
    reply = {'identities': {}}
    # Requested identities are read before the census. A tracked process that exits after its own
    # read is absent from the census, and one the census lists was alive at its listing.
    for pid in pids:
        reply['identities'][str(pid)] = (observe(pid) if pid > 1
                                         else {'status': 'UNKNOWN', 'pid': pid, 'reason': 'invalid pid'})
    if request.get('census'):
        try:
            reply['census'] = census()
        except (OSError, ValueError, RuntimeError, struct.error, OverflowError,
                ctypes.ArgumentError) as exc:
            reply['census'] = {'error': str(exc) or type(exc).__name__}
    return reply


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--batch']:
            result = batch(json.load(sys.stdin))
        else:
            pid = int(sys.argv[1])
            if pid <= 1:
                raise ValueError('invalid pid')
            result = observe(pid)
    except (IndexError, ValueError) as exc:
        result = {'status': 'UNKNOWN', 'reason': str(exc)}
    print(json.dumps(result, separators=(',', ':')))
