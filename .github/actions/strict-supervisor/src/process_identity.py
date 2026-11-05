"""Typed kernel process identity observations; a failure is never absence.

Modes:
  process_identity.py PID       one observation of PID, as JSON
  process_identity.py --batch   reads {"pids": [...], "census": bool} on stdin and
                                writes one reply from this single process: the census
                                (every listed process as [pid, ppid, state, birth], with
                                null for an unreadable field) and the observation of each
                                requested PID. One helper call per observer poll keeps the
                                cost of a poll independent of how many processes it has seen.
"""
import ctypes
import errno
import json
import os
import re
import subprocess
import sys

_PS_ROW = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s*$')
_LIBPROC = None


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


def _observe_linux(pid):
    try:
        with open(f'/proc/{pid}/stat', encoding='ascii') as f:
            stat = f.read()
    except ProcessLookupError:
        # ESRCH: the process exited between the open and the read. That is absence, not an unknown identity.
        return {'status': 'ABSENT', 'pid': pid}
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


def _observe_darwin(pid):
    info = _BSDInfo()
    ctypes.set_errno(0)
    result = _libproc().proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
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


def observe(pid):
    try:
        if sys.platform.startswith('linux'):
            return _observe_linux(pid)
        if sys.platform != 'darwin':
            raise RuntimeError('unsupported process identity platform')
        return _observe_darwin(pid)
    except (OSError, ValueError, IndexError, UnicodeError, RuntimeError, OverflowError) as exc:
        return {'status': 'UNKNOWN', 'pid': pid, 'reason': str(exc)}


def census():
    """Every listed process as [pid, ppid, state, birth].

    On Linux the listing and the identity come from one /proc read per process, so a
    row's birth is the birth of the process it was listed as. On Darwin ps lists the
    processes; a process that exits between the listing and its identity read keeps a
    row with a null birth, so a caller that needs its identity treats it as unresolved.
    """
    if sys.platform.startswith('linux'):
        rows = []
        for name in os.listdir('/proc'):
            if not name.isdigit():
                continue
            pid = int(name)
            obs = observe(pid)
            if obs['status'] == 'ABSENT':
                continue
            if obs['status'] == 'UNKNOWN':
                rows.append([pid, None, None, None])
            else:
                rows.append([pid, obs['ppid'], obs['state'], obs['birth']])
        return rows
    if sys.platform != 'darwin':
        raise RuntimeError('unsupported process census platform')
    text = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,stat='], capture_output=True,
                          text=True, timeout=10, check=True).stdout
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _PS_ROW.match(line)
        if not match:
            raise ValueError('unparseable process census')
        pid, ppid, state = int(match.group(1)), int(match.group(2)), match.group(3)
        obs = observe(pid)
        birth = obs['birth'] if obs['status'] == 'LIVE' else None
        rows.append([pid, ppid, 'Z' if state.startswith('Z') else state, birth])
    return rows


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
            reply['census'] = {'rows': census()}
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
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
