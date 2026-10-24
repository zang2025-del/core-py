"""Paging through the audit trail without losing or repeating a row.

An audit read has one failure mode that matters: a page boundary that drops a
row, or shows one twice. Both are invisible from inside a page -- the response
looks like a perfectly good page of history -- and both are fatal to the reason
the table exists, because a reader has no way to know that what they are looking
at is incomplete.

That is why this is a keyset and not an ``OFFSET``. ``OFFSET`` re-counts every
row it skips, so page N costs N times page 1, and a decision recorded between
two requests shifts every later page by one. The tests below pin the property
rather than the implementation: walk the whole trail in small pages and assert
the concatenation is exactly the set of rows, in order, once each.

The cursor is also treated as untrusted input, because it arrives in a query
string and clients do edit them. A cursor that cannot be read is a 422 with a
reason, never a 500 and never a silent restart from the beginning -- silently
starting over would make a paging client loop forever, which reads as a hang
rather than as the bad request it is.
"""

from __future__ import annotations

import pytest

from permgate.storage.repositories import decode_cursor, encode_cursor

FLAGGED = "kubectl delete namespace production"
VOUCHED = "ls -la"


def _decide(client, project, command: str):
    response = client.post(
        "/v1/decisions",
        json={"project_root": str(project), "tool": "bash", "arguments": {"command": command}},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _page(client, project, **params):
    query: dict[str, object] = {"project_root": str(project), **params}
    # httpx renders ``None`` as an empty string, and an empty string is a cursor
    # that fails to decode -- so "no cursor" has to mean the parameter is absent,
    # which is also what a real client does on its first request.
    query = {key: value for key, value in query.items() if value is not None}
    response = client.get("/v1/audit", params=query)
    assert response.status_code == 200, response.text
    return response.json()


def _walk(client, project, limit: int, **params) -> list[dict]:
    """Every entry, in order, following the cursors exactly as a client would."""
    seen: list[dict] = []
    cursor: str | None = None
    # Bounded so a broken cursor chain fails as a test rather than as a timeout.
    for _ in range(50):
        page = _page(client, project, limit=limit, cursor=cursor, **params)
        seen.extend(page["entries"])
        cursor = page["next_cursor"]
        if cursor is None:
            return seen
    raise AssertionError("the cursor chain did not terminate")


class TestCursorEncoding:
    def test_a_cursor_round_trips(self):
        from datetime import datetime, timezone

        stamp = datetime(2026, 10, 24, 8, 0, 0, 123456, tzinfo=timezone.utc)
        stamp_back, decision_id = decode_cursor(encode_cursor(stamp, "d-1"))
        assert stamp_back == stamp
        assert decision_id == "d-1"

    def test_a_cursor_needs_no_padding_in_a_query_string(self):
        """``=`` is awkward to carry: shells eat it and some clients re-encode
        it. Padding is stripped on the way out and restored on the way in."""
        from datetime import datetime, timezone

        cursor = encode_cursor(datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc), "d-1")
        assert "=" not in cursor

    @pytest.mark.parametrize(
        "bad",
        ["", "not-base64!!", "bm8tc2VwYXJhdG9y", "MjAyNi0xMC0yNFQwODowMDowMCswMDowMHw"],
    )
    def test_a_cursor_that_cannot_be_read_is_rejected(self, bad: str):
        with pytest.raises(ValueError):
            decode_cursor(bad)

    def test_a_naive_timestamp_is_rejected(self):
        """Stored timestamps are UTC. A cursor without a timezone would compare
        against them being wrong by the machine's offset, which changes *which*
        rows come back instead of raising -- an off-by-hours page boundary."""
        import base64

        raw = "2026-10-24T08:00:00|d-1"
        naive = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        with pytest.raises(ValueError, match="timezone"):
            decode_cursor(naive)


class TestPagingThroughTheTrail:
    def test_a_single_page_has_no_cursor(self, client, project):
        _decide(client, project, VOUCHED)
        page = _page(client, project, limit=10)
        assert len(page["entries"]) == 1
        assert page["next_cursor"] is None, "there is nothing after the last page"

    def test_a_full_last_page_still_reports_no_cursor(self, client, project):
        """The trap an implementation that infers "more" from a full page falls
        into: exactly ``limit`` rows is the *end*, not a promise of another
        page. The service fetches one extra row to be able to tell."""
        for _ in range(3):
            _decide(client, project, VOUCHED)
        page = _page(client, project, limit=3)
        assert len(page["entries"]) == 3
        assert page["next_cursor"] is None

    def test_every_row_is_seen_exactly_once_in_order(self, client, project):
        created = [_decide(client, project, VOUCHED)["decision_id"] for _ in range(7)]

        walked = _walk(client, project, limit=2)

        ids = [entry["decision_id"] for entry in walked]
        assert len(ids) == len(set(ids)), "a row was repeated across a page boundary"
        assert set(ids) == set(created), "a row was lost across a page boundary"
        # Newest first, and stable: the order the single-page read would give.
        assert ids == [
            _page(client, project, limit=50)["entries"][i]["decision_id"] for i in range(7)
        ]

    def test_the_walk_agrees_with_one_big_read(self, client, project):
        for command in (VOUCHED, FLAGGED, VOUCHED, FLAGGED, VOUCHED):
            _decide(client, project, command)

        paged = [entry["decision_id"] for entry in _walk(client, project, limit=2)]
        one_shot = [entry["decision_id"] for entry in _page(client, project, limit=50)["entries"]]
        assert paged == one_shot

    def test_the_verdict_filter_survives_paging(self, client, project):
        """The cursor narrows an already-filtered query. Losing the filter
        between pages would mix verdicts in a walk that asked for one."""
        # A grant is what turns an ordinary call into ``allow``: without one,
        # everything is ``ask``, and a filter test on ``allow`` would pass or
        # fail on the grant table rather than on the cursor.
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        _decide(client, project, VOUCHED)
        _decide(client, project, VOUCHED)
        _decide(client, project, VOUCHED)

        walked = _walk(client, project, limit=1, verdict="allow")
        assert len(walked) == 3, "the filter must not be applied only to the first page"
        assert [entry["verdict"] for entry in walked] == ["allow"] * 3

        assert _walk(client, project, limit=1, verdict="deny") == []

    def test_an_empty_trail_is_an_empty_page(self, client, project):
        page = _page(client, project, limit=10)
        assert page["entries"] == []
        assert page["next_cursor"] is None

    def test_replaying_a_cursor_returns_the_same_page(self, client, project):
        """A cursor names a position, not a step, so asking for it twice is the
        same question. An offset-based read would skip forward on the replay."""
        for _ in range(4):
            _decide(client, project, VOUCHED)

        first = _page(client, project, limit=2)
        again = _page(client, project, limit=2, cursor=first["next_cursor"])
        replay = _page(client, project, limit=2, cursor=first["next_cursor"])

        assert [e["decision_id"] for e in again["entries"]] == [
            e["decision_id"] for e in replay["entries"]
        ]

    def test_a_cursor_before_the_whole_trail_is_an_empty_page_not_an_error(self, client, project):
        """A client that races the end of the trail sends a position with nothing
        after it. That is an empty page, not a failure: treating it as one would
        make a correct client retry forever."""
        from datetime import datetime, timezone

        _decide(client, project, VOUCHED)
        beyond = _page(
            client,
            project,
            limit=1,
            cursor=encode_cursor(datetime(2000, 1, 1, tzinfo=timezone.utc), "z"),
        )
        assert beyond["entries"] == []
        assert beyond["next_cursor"] is None


class TestTheCursorIsUntrustedInput:
    def test_a_malformed_cursor_is_a_422_with_a_reason(self, client, project):
        response = client.get(
            "/v1/audit",
            params={"project_root": str(project), "cursor": "obviously-not-a-cursor"},
        )
        assert response.status_code == 422
        body = response.json()["error"]
        assert body["code"] == "invalid_cursor"
        assert body["details"]["reason"], "a client cannot fix a cursor it cannot understand"

    def test_a_malformed_cursor_does_not_read_as_the_beginning_of_the_trail(self, client, project):
        """The failure to design out: a cursor that quietly decoded to "start
        over" would make every paging client loop on page one forever."""
        _decide(client, project, VOUCHED)
        response = client.get(
            "/v1/audit", params={"project_root": str(project), "cursor": "garbage"}
        )
        assert response.status_code != 200
