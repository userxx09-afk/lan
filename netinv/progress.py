"""Live progress of running scans, for the Scanning view. One Run per running job (or manual scan).

Collectors call progress.current() to report hosts done/total; the job thread sets it with start()/end().
Cancel sets Run.stop: the WinRM sweep drops the hosts it hasn't started and the job skips its remaining steps."""
from __future__ import annotations

import threading
import time
from collections import Counter, deque

_lock = threading.Lock()
_tls = threading.local()
RUNS: dict[str, "Run"] = {}


class Cancelled(Exception):
    pass


class Run:
    def __init__(self, key: str, name: str, job_id: int | None = None, steps: list[str] | None = None,
                 who: str | None = None, expected: int | None = None):
        self.key, self.name, self.job_id, self.who, self.expected = key, name, job_id, who, expected
        self.started = time.time()
        self.steps = steps or []
        self.step, self.step_i, self.step_started = None, 0, self.started
        self.total = self.done = self.failed = 0
        self.inflight: dict[str, float] = {}
        self.reasons: Counter = Counter()                 # why hosts failed in this step: reason -> count
        self.failures: deque = deque(maxlen=200)          # the latest (host, reason) failures, for the live view
        self.stop = threading.Event()
        self.cancelled_by: str | None = None

    def begin_step(self, step: str) -> None:
        with _lock:
            self.step = step
            self.step_i = self.steps.index(step) + 1 if step in self.steps else self.step_i + 1
            self.step_started = time.time()
            self.total = self.done = self.failed = 0
            self.inflight.clear()
            self.reasons.clear()
            self.failures.clear()

    def hosts(self, total: int) -> None:
        with _lock:
            self.total, self.done, self.failed, self.step_started = total, 0, 0, time.time()

    def host_start(self, host: str) -> None:
        with _lock:
            self.inflight[host] = time.time()

    def host_end(self, host: str, ok: bool, reason: str | None = None) -> None:
        with _lock:
            self.inflight.pop(host, None)
            self.done += 1
            self.failed += not ok
            if not ok:
                r = short_reason(reason)
                self.reasons[r] += 1
                self.failures.append((host, r, time.time()))

    def eta(self) -> int | None:
        """Seconds left: from the host rate while hosts are counted on the last step, else from the job's last run."""
        now = time.time()
        if self.total and self.done and (not self.steps or self.step_i >= len(self.steps)):
            rate = (now - self.step_started) / self.done
            return int(rate * (self.total - self.done))
        if self.expected:
            return max(0, int(self.expected - (now - self.started)))
        return None

    def out(self) -> dict:
        now = time.time()
        with _lock:
            cur = sorted(self.inflight.items(), key=lambda kv: kv[1])
            return {"key": self.key, "name": self.name, "job_id": self.job_id, "who": self.who,
                    "elapsed": int(now - self.started), "steps": self.steps, "step": self.step, "step_i": self.step_i,
                    "total": self.total, "done": self.done, "failed": self.failed,
                    "current": [h for h, _ in cur[:8]], "in_flight": len(cur), "eta": self.eta(),
                    "expected": self.expected, "cancelling": self.stop.is_set(),
                    "reasons": [{"reason": r, "count": n} for r, n in self.reasons.most_common(6)],
                    "failures": [{"host": h, "reason": r} for h, r, _ in list(self.failures)[-100:][::-1]]}


def short_reason(reason) -> str:
    """One line per failure kind, so thousands of PCs with the same problem group together."""
    import re
    if reason is None:
        return "failed"
    if isinstance(reason, BaseException):
        from .collectors.winrm import classify_error
        kind = classify_error(reason)
        msg = f"{type(reason).__name__}: {reason}"
        label = {"access_denied": "Access denied", "unreachable": "Not reachable"}.get(kind)
    else:
        msg, label = str(reason), None
    msg = msg.strip().split("\n")[0]
    # host names, addresses and ports differ per PC: take them out so the same problem groups together
    msg = re.sub(r"host='[^']*'", "host=…", msg)
    msg = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "…", msg)
    msg = re.sub(r"object at 0x[0-9a-f]+", "object", msg)
    msg = msg[:220]
    return f"{label}: {msg}" if label else msg


def start(key: str, name: str, **kw) -> Run:
    r = Run(key, name, **kw)
    with _lock:
        RUNS[key] = r
    _tls.run = r
    return r


def end(r: Run) -> None:
    with _lock:
        if RUNS.get(r.key) is r:
            RUNS.pop(r.key, None)
    if getattr(_tls, "run", None) is r:
        _tls.run = None


def current() -> Run | None:
    return getattr(_tls, "run", None)


def stopped() -> bool:
    r = current()
    return bool(r and r.stop.is_set())


def cancel(key: str, who: str) -> bool:
    with _lock:
        r = RUNS.get(key)
    if not r:
        return False
    r.cancelled_by = who
    r.stop.set()
    return True


def snapshot() -> list[dict]:
    with _lock:
        runs = list(RUNS.values())
    return [r.out() for r in sorted(runs, key=lambda r: r.started)]
