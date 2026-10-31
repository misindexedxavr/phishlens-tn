"""Tiny thread-safe sliding-window rate limiter.

In-process only: fine for a single worker or a demo. For several workers or
hosts, put a shared limiter (Redis, your reverse proxy) in front instead.
"""
from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from typing import Callable


class RateLimiter:
    """Allow at most ``limit`` hits per ``window`` seconds per key."""

    def __init__(self, limit: int, window: float, *, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000) -> None:
        if limit < 1 or window <= 0:
            raise ValueError("limit must be >= 1 and window > 0")
        self.limit = limit
        self.window = window
        self._clock = clock
        self._max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def hit(self, key: str) -> tuple[bool, int]:
        """Register a request. Returns ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            queue = self._hits.get(key)
            if queue is None:
                queue = self._hits[key] = deque()
            self._hits.move_to_end(key)
            while queue and queue[0] <= now - self.window:
                queue.popleft()
            if len(queue) >= self.limit:
                return False, max(1, math.ceil(queue[0] + self.window - now))
            queue.append(now)
            while len(self._hits) > self._max_keys:
                self._hits.popitem(last=False)
            return True, 0
