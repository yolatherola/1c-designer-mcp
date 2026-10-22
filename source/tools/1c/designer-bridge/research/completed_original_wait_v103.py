"""Bounded observation of process/lease completion; performs no commands.

The host may exit shortly before its original launcher and lease owner. Only
the supplied exact-identity predicate can establish completion; expiry does
not turn an unknown or retained process into a successful observation.
"""
import math
import time


def wait_for_original_completion(predicate, *, seconds=5.0, clock=time.monotonic, pause=time.sleep):
    """Wait up to five seconds for an exact bool, without retrying operations."""
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 5:
        raise ValueError('V103_WAIT_BUDGET_REJECTED')
    deadline = clock() + seconds
    while True:
        completed = predicate()
        if type(completed) is not bool:
            raise ValueError('V103_COMPLETION_OBSERVATION_REJECTED')
        if completed:
            return True
        remaining = deadline - clock()
        if remaining <= 0:
            return False
        pause(min(0.05, remaining))
