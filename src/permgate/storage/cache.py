"""The grant cache, and the one place this service can be wrong.

Every decision needs the project's grant set, and the grant set is the only
thing ``decide()`` has to wait for -- it is pure, so it is never the bottleneck
until its inputs are. So the set is cached per project.

Caching an *authorisation* is different from caching a page. A stale read here
does not show yesterday's price; it silently honours a grant the user revoked.
That asymmetry is why this module is small, explicit, and paranoid:

* **Every write invalidates.** The service never mutates a grant without going
  through it, and the invalidation happens after the transaction commits, not
  before -- invalidating first leaves a window where a concurrent read caches
  the pre-write set with a fresh TTL and the write never appears.
* **The TTL is a backstop, not the mechanism.** It bounds how long a *different
  process's* write can go unnoticed, which in-process invalidation cannot cover.
* **It is bounded.** An unbounded cache keyed on a client-supplied project path
  is a memory-exhaustion bug with extra steps.
* **It can be turned off.** ``PERMGATE_GRANT_CACHE_ENABLED=false`` is a supported
  configuration, not a debug flag, because "correct but slower" has to be
  available when someone is debugging a live inconsistency.

The multi-process gap, stated plainly rather than hidden: with more than one
worker, a revoke handled by worker A is invisible to worker B until its entry
expires. The honest options are a shared cache with a pub/sub invalidation
channel, or a TTL short enough to be a product decision. This project implements
the TTL and names the gap; it does not pretend the TTL is the same thing.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol

from ..domain.engine import GrantSet


@dataclass(frozen=True, slots=True)
class CacheStats:
    hits: int
    misses: int
    evictions: int
    invalidations: int
    size: int

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


class GrantCache(Protocol):
    def get(self, project_id: int) -> GrantSet | None: ...
    def put(self, project_id: int, grants: GrantSet) -> None: ...
    def invalidate(self, project_id: int) -> None: ...
    def stats(self) -> CacheStats: ...


class NullGrantCache:
    """No cache at all. Every read goes to the database.

    The default in tests, so that a cache bug can never be mistaken for a
    storage bug, and available in production for the same reason.
    """

    def get(self, project_id: int) -> GrantSet | None:
        return None

    def put(self, project_id: int, grants: GrantSet) -> None:
        return None

    def invalidate(self, project_id: int) -> None:
        return None

    def stats(self) -> CacheStats:
        return CacheStats(0, 0, 0, 0, 0)


@dataclass(slots=True)
class _Entry:
    grants: GrantSet
    expires_at: float


class InMemoryGrantCache:
    """TTL-bounded, size-bounded, thread-safe.

    Eviction is plain oldest-expiry-first rather than true LRU: the access
    pattern is one entry per active project, so the working set is small and the
    extra bookkeeping would cost more than it recovers. Saying that out loud
    matters more than the microseconds -- an LRU claim that is not an LRU is the
    kind of thing that only surfaces during an incident.
    """

    def __init__(self, *, ttl_seconds: float, max_entries: int) -> None:
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must not be negative")
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._entries: dict[int, _Entry] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._invalidations = 0

    def get(self, project_id: int) -> GrantSet | None:
        if self._ttl == 0:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(project_id)
            if entry is None:
                self._misses += 1
                return None
            if entry.expires_at <= now:
                del self._entries[project_id]
                self._misses += 1
                return None
            self._hits += 1
            return entry.grants

    def put(self, project_id: int, grants: GrantSet) -> None:
        if self._ttl == 0:
            return
        with self._lock:
            if project_id not in self._entries and len(self._entries) >= self._max_entries:
                self._evict_locked()
            self._entries[project_id] = _Entry(grants, time.monotonic() + self._ttl)

    def invalidate(self, project_id: int) -> None:
        """Drop one project's entry. Called after every commit that changes a
        grant, in the same request that made the change."""
        with self._lock:
            if self._entries.pop(project_id, None) is not None:
                self._invalidations += 1

    def invalidate_all(self) -> None:
        with self._lock:
            self._invalidations += len(self._entries)
            self._entries.clear()

    def _evict_locked(self) -> None:
        if not self._entries:
            return
        now = time.monotonic()
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        if expired:
            for key in expired:
                del self._entries[key]
                self._evictions += 1
            return
        # Evicting a live entry to make room means the cache is undersized for
        # the number of active projects. The counter is there so that shows up
        # as a number in the metrics rather than as unexplained p99 latency.
        oldest = min(self._entries.items(), key=lambda item: item[1].expires_at)[0]
        del self._entries[oldest]
        self._evictions += 1

    def stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                invalidations=self._invalidations,
                size=len(self._entries),
            )


def build_cache(*, enabled: bool, ttl_seconds: float, max_entries: int) -> GrantCache:
    if not enabled:
        return NullGrantCache()
    return InMemoryGrantCache(ttl_seconds=ttl_seconds, max_entries=max_entries)
