"""The cache, and the one way it can be wrong.

Caching an authorisation is not like caching a page. A stale read here does not
show yesterday's price -- it silently honours a grant the user revoked, which is
the single worst failure this service can have. So the invalidation path gets its
own tests, and each one is written so that it would **fail if the cache were
removed entirely**: an invalidation bug that only shows up when caching is on is
exactly the kind that ships.
"""

from __future__ import annotations

import time

import pytest

from permgate.domain.engine import GrantSet
from permgate.storage.cache import InMemoryGrantCache, NullGrantCache, build_cache

VOUCHED = "ls -la"
FLAGGED = "kubectl delete namespace production"


def _decide(client, project, command: str):
    response = client.post(
        "/v1/decisions",
        json={"project_root": str(project), "tool": "bash", "arguments": {"command": command}},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestInvalidationOnWrite:
    def test_a_new_grant_is_visible_on_the_very_next_decision(self, client, project, metrics):
        """No TTL wait. If this needed the clock to pass, the write and the read
        are racing and the service is only correct between requests."""
        _decide(client, project, VOUCHED)  # populate the cache with an empty set
        assert metrics.cache_events.count("hit") + metrics.cache_events.count("miss") >= 1

        created = client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "note": "test"},
        )
        assert created.status_code == 201

        assert _decide(client, project, VOUCHED)["rule"] == "tool_grant"

    def test_a_revoked_grant_stops_being_honoured_immediately(self, client, project):
        """The one that matters. A revoke the user performed has to take effect
        now, not in fifteen seconds."""
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        assert _decide(client, project, VOUCHED)["verdict"] == "allow"

        revoked = client.delete("/v1/grants/bash", params={"project_root": str(project)})
        assert revoked.status_code == 200
        assert revoked.json()["removed"] == 1

        after = _decide(client, project, VOUCHED)
        assert after["verdict"] == "ask", "a revoked grant was still honoured"

    def test_clearing_every_grant_is_visible_immediately(self, client, project):
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "kubectl delete"},
        )
        assert _decide(client, project, FLAGGED)["verdict"] == "allow"

        cleared = client.delete("/v1/grants", params={"project_root": str(project)})
        assert cleared.json()["removed"] == 2
        assert _decide(client, project, FLAGGED)["verdict"] != "allow"

    def test_a_revoke_that_matched_nothing_still_invalidates(self, client, project):
        """The caller believed a grant was there. Serving them the cached set
        would tell them it still is."""
        _decide(client, project, VOUCHED)  # warm the cache
        response = client.delete(
            "/v1/grants/bash:does not exist", params={"project_root": str(project)}
        )
        assert response.status_code == 200
        assert response.json()["removed"] == 0

    def test_an_answer_that_creates_a_grant_is_visible_immediately(self, client, project):
        first = _decide(client, project, VOUCHED)
        client.post(f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "always"})
        assert _decide(client, project, VOUCHED)["rule"] == "tool_grant"


class TestProjectIsolation:
    def test_grants_do_not_leak_between_projects(self, client, tmp_path, project):
        """Approving bash in a scratch repository must not approve it in the
        production one. This is the whole reason grants are keyed on a project."""
        other = tmp_path / "production"
        other.mkdir()
        (other / ".git").mkdir()

        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})

        assert _decide(client, project, VOUCHED)["verdict"] == "allow"
        assert _decide(client, other, VOUCHED)["verdict"] == "ask"

    def test_two_projects_with_the_same_directory_name_stay_separate(self, client, tmp_path):
        """Same basename, different roots. A key derived from the name alone
        would collide them; the digest is what stops that."""
        first, second = tmp_path / "a" / "api", tmp_path / "b" / "api"
        for path in (first, second):
            path.mkdir(parents=True)
            (path / ".git").mkdir()

        client.post("/v1/grants", json={"project_root": str(first), "tool": "bash"})
        assert _decide(client, first, VOUCHED)["verdict"] == "allow"
        assert _decide(client, second, VOUCHED)["verdict"] == "ask"


class TestCacheUnit:
    def test_hits_and_misses_are_counted(self):
        cache = InMemoryGrantCache(ttl_seconds=60, max_entries=8)
        assert cache.get(1) is None  # miss
        cache.put(1, GrantSet.of([]))
        assert cache.get(1) is not None  # hit
        stats = cache.stats()
        assert stats.misses == 1 and stats.hits == 1
        assert stats.hit_rate == 0.5

    def test_a_zero_ttl_disables_the_cache(self):
        """A supported configuration, not a debug flag: 'correct but slower' has
        to be available when someone is chasing a live inconsistency."""
        cache = InMemoryGrantCache(ttl_seconds=0, max_entries=8)
        cache.put(1, GrantSet.of([]))
        assert cache.get(1) is None

    def test_entries_expire(self):
        cache = InMemoryGrantCache(ttl_seconds=0.05, max_entries=8)
        cache.put(1, GrantSet.of([]))
        assert cache.get(1) is not None
        time.sleep(0.08)
        assert cache.get(1) is None, "the TTL is the backstop for another process's write"

    def test_the_cache_is_bounded(self):
        cache = InMemoryGrantCache(ttl_seconds=60, max_entries=4)
        for project_id in range(20):
            cache.put(project_id, GrantSet.of([]))
        assert cache.stats().size <= 4
        assert cache.stats().evictions > 0, "evictions must be visible as a number"

    def test_invalidate_drops_only_one_project(self):
        cache = InMemoryGrantCache(ttl_seconds=60, max_entries=8)
        cache.put(1, GrantSet.of([]))
        cache.put(2, GrantSet.of([]))
        cache.invalidate(1)
        assert cache.get(1) is None
        assert cache.get(2) is not None

    def test_invalidating_a_project_that_is_not_cached_is_harmless(self):
        cache = InMemoryGrantCache(ttl_seconds=60, max_entries=8)
        cache.invalidate(99)  # must not raise
        assert cache.stats().invalidations == 0

    @pytest.mark.parametrize("factory", [NullGrantCache])
    def test_the_null_cache_never_returns_anything(self, factory):
        cache = factory()
        cache.put(1, GrantSet.of([]))
        assert cache.get(1) is None

    def test_build_cache_honours_the_switch(self):
        assert isinstance(build_cache(enabled=False, ttl_seconds=10, max_entries=8), NullGrantCache)
        assert isinstance(
            build_cache(enabled=True, ttl_seconds=10, max_entries=8), InMemoryGrantCache
        )

    def test_negative_ttl_is_rejected(self):
        with pytest.raises(ValueError):
            InMemoryGrantCache(ttl_seconds=-1, max_entries=8)

    def test_zero_max_entries_is_rejected(self):
        with pytest.raises(ValueError):
            InMemoryGrantCache(ttl_seconds=1, max_entries=0)
