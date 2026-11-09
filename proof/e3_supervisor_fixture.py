"""Pure E3 protocol fixtures, not a supervisor or a source of receipts.

Nothing here authenticates events, accesses a process, or proves a kernel
boundary. Inputs are synthetic and must never be used as runtime evidence.
The admission decision is intentionally always unavailable.
"""
from dataclasses import dataclass
from enum import Enum, auto
import hashlib


class Refused(ValueError):
    """Malformed or unsupported fixture sequence."""


class State(Enum):
    RUNNING = auto()
    STOPPED = auto()


@dataclass(frozen=True)
class Object:
    # Namespace-qualified mount ID and filesystem device/inode identity.
    mount: int
    device: int
    inode: int
    links: int
    regular: bool
    data: bytes

    def identity(self):
        return (self.mount, self.device, self.inode)


class Fixture:
    """Model one transaction; every event is supplied by a test, not a witness."""

    def __init__(self, *, max_tasks, max_events, max_bytes, max_descriptors):
        limits = (max_tasks, max_events, max_bytes, max_descriptors)
        if any(type(n) is not int or n <= 0 for n in limits):
            raise Refused("invalid fixture budget")
        self.max_tasks, self.max_events, self.max_bytes, self.max_descriptors = limits
        self.tasks = {}
        self.seen = set()
        self.events = 0
        self.bound = None
        self.reference = None
        self.digest = None
        self.reset = False
        self.executed = False
        self.sampled = False
        self.failed = False

    def _event(self):
        if self.failed or self.sampled:
            raise Refused("fixture closed")
        self.events += 1
        if self.events > self.max_events:
            self.failed = True
            raise Refused("event budget exceeded")

    def _reject(self, reason):
        self.failed = True
        raise Refused(reason)

    def _all_stopped(self):
        if not self.tasks or any(s is not State.STOPPED for s in self.tasks.values()):
            self._reject("all live tasks must be stopped")

    def add_root(self, task):
        self._event()
        if self.seen:
            self._reject("duplicate root")
        self._add(task)

    def _add(self, task):
        # IDs are fixture tokens, not numeric PIDs or authority to signal.
        if not isinstance(task, str) or not task or task in self.seen:
            self._reject("invalid or reused task token")
        if len(self.tasks) >= self.max_tasks:
            self._reject("task budget exceeded")
        self.seen.add(task)
        self.tasks[task] = State.STOPPED

    def fork(self, parent, child, kind):
        self._event()
        if kind not in ("fork", "vfork", "clone") or self.tasks.get(parent) is not State.STOPPED:
            self._reject("unobserved descendant")
        self._add(child)

    def resume(self, task):
        self._event()
        if self.tasks.get(task) is not State.STOPPED:
            self._reject("task is not stopped")
        self.tasks[task] = State.RUNNING

    def stop(self, task):
        self._event()
        if self.tasks.get(task) is not State.RUNNING:
            self._reject("task is not running")
        self.tasks[task] = State.STOPPED

    def exit(self, task):
        self._event()
        if self.tasks.get(task) is not State.STOPPED:
            self._reject("exit without a stop")
        del self.tasks[task]

    def bind(self, output, reference):
        self._event()
        self._all_stopped()
        if self.bound is not None or self.max_descriptors < 2:
            self._reject("duplicate binding or descriptor budget exceeded")
        if not isinstance(output, Object) or not isinstance(reference, Object):
            self._reject("missing output or reference")
        for obj in (output, reference):
            if (type(obj.regular) is not bool or not obj.regular or
                    any(type(n) is not int or n < 0 for n in obj.identity()) or
                    type(obj.links) is not int or obj.links < 2 or
                    type(obj.data) is not bytes):
                self._reject("invalid retained object")
        if output.identity() != reference.identity() or output.data != reference.data:
            self._reject("output and reference differ")
        if len(reference.data) > self.max_bytes:
            self._reject("byte budget exceeded")
        self.bound = output.identity()
        self.reference = reference
        self.digest = hashlib.sha256(reference.data).digest()

    def timestamp_reset(self, successful):
        self._event()
        self._all_stopped()
        if self.bound is None or self.reset or successful is not True:
            self._reject("reset not observed")
        self.reset = True

    def exec_stop(self, task, executable, *, successful):
        self._event()
        self._all_stopped()
        if (task not in self.tasks or successful is not True or not self.reset or
                self.executed or not isinstance(executable, Object) or
                executable.identity() != self.bound or executable.data != self.reference.data):
            self._reject("exec does not match retained object")
        self.executed = True

    def teardown_sample(self, retained):
        self._event()
        if (self.tasks or not self.executed or not isinstance(retained, Object) or
                retained.identity() != self.bound or retained.data != self.reference.data or
                hashlib.sha256(retained.data).digest() != self.digest):
            self._reject("incomplete teardown or changed object")
        self.sampled = True

    def admission(self):
        # No fixture sequence can establish channel authentication, source
        # attribution, writer exclusion, kernel coverage, or a strict receipt.
        raise Refused("UNAVAILABLE: kernel supervisor and source attribution unqualified")
