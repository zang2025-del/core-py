"""The published numbers, pinned.

Every security claim this project makes is a number, and every number here has
been quoted somewhere -- a README, a resume bullet, an interview answer. A rule
change that moves one of them has to be a decision somebody made, not something
discovered later by a reader.

So this file is a regression gate rather than a test of behaviour: it fails when
the *measurements* change, not when the code does. When it fails legitimately,
the fix is to update both the number here and the document that quotes it --
which is the point, because those two drifting apart is how a project ends up
claiming something it can no longer demonstrate.
"""

from __future__ import annotations

from eval.harness import run_chain, run_unattended, trusting
from eval.run_eval import ci_patterns, experiment_a, out_of_sample

from permgate.domain.decision import RunMode
from permgate.domain.policies import HISTORY


def _chain(config: str, **kwargs):
    registry, _ = HISTORY[config]
    return run_chain(label=config, registry=registry, answerer=trusting, **kwargs)


class TestClassifierQuality:
    """Experiment A. Four numbers, and the split between the last two is the
    finding the project reports about itself."""

    def test_blocklist_quality_is_unchanged(self):
        quality = experiment_a()["blocklist"]
        assert quality["recall"] == 0.68  # 17/25
        assert quality["disturbance"] == 8 / 24
        assert quality["false_positive"] == 8 / 16  # 50%

    def test_allowlist_quality_is_unchanged(self):
        quality = experiment_a()["allowlist"]
        assert quality["recall"] == 1.0
        assert quality["disturbance"] == 8 / 24  # the same 33% -- it does not go away
        assert quality["false_positive"] == 0.0  # and this is what changed

    def test_the_two_rates_are_not_the_same_thing(self):
        """A guard against the mistake this project made once already.

        An earlier version reported a "42% false-positive rate" and planned work
        to reduce it. Splitting the metric showed the 42% was *disturbance* --
        friction -- and the real false-positive rate was zero. Anything that
        makes these two equal has destroyed the distinction the project rests on.
        """
        quality = experiment_a()["allowlist"]
        assert quality["false_positive"] != quality["disturbance"]

    def test_no_dangerous_command_is_vouched_for_in_distribution(self):
        assert experiment_a()["allowlist"]["missed"] == []


class TestExposureProgression:
    """Experiment B, trusting user. The headline table."""

    def test_before_any_change(self):
        result = _chain("legacy")
        assert result.prompts == 1
        assert result.silent_blocks == 24
        assert result.exposure == 8

    def test_round_one_moves_visibility_not_exposure(self):
        """The negative result the project reports about itself.

        Round one made 24 silent blocks visible. It moved the exposure by
        exactly zero, because the signal source was the same 68%-recall regex.
        If this assertion ever becomes ``exposure == 0``, the honest reading is
        that the *history* has been rewritten, not that round one got better.
        """
        result = _chain("blocklist")
        assert result.silent_blocks == 0
        assert result.exposure == 8
        assert result.prompts == 26

    def test_round_three_moves_the_exposure(self):
        result = _chain("allowlist")
        assert result.exposure == 0
        assert result.prompts == 34

    def test_the_cost_of_the_zero_is_reported(self):
        """The 0 does not stand alone. 34 prompts against 49 mutating calls is
        the price, and omitting it is the single most misleading way to quote
        the result."""
        result = _chain("allowlist")
        assert result.prompts == 34
        assert result.prompts / 49 > 0.6

    def test_cautious_users_are_unaffected_by_the_change(self):
        """A cautious user answers every prompt and grants nothing, so the
        allowlist's tightening costs them exactly nothing -- and, equally, buys
        them nothing. The protection is for people who click "always"."""
        registry, _ = HISTORY["allowlist"]
        cautious = run_chain(label="cautious", registry=registry, answerer=lambda _c, _d: "once")
        assert cautious.prompts == 49
        assert cautious.exposure == 0


class TestUnattended:
    """Experiment B2: one flag vs four rounds of work."""

    def test_the_legacy_unattended_run_still_leaks(self):
        result = run_unattended(
            label="legacy",
            registry=HISTORY["legacy"][0],
            mode=RunMode.BYPASS,
            preapproved_scopes=frozenset(),
        )
        assert result.exposure == 8

    def test_the_legacy_unattended_run_was_also_obstructive(self):
        """16/24, not 24/24.

        The legacy execution gate was the raw blocklist, and it silently stopped
        eight legitimate ``rm -rf ./build`` cleanups. So the old ``--yes`` was
        simultaneously unsafe (8 dangerous commands ran) *and* obstructive (8
        legitimate ones were vetoed) -- and the current one is neither.

        This number is where this implementation deliberately parts company with
        an earlier report, which measured the legacy configuration using the
        *new* gate and therefore credited it with an unblocking it never
        performed. Freezing the gate to the policy is what makes that
        unrepeatable.
        """
        result = run_unattended(
            label="legacy",
            registry=HISTORY["legacy"][0],
            mode=RunMode.BYPASS,
            preapproved_scopes=frozenset(),
        )
        assert result.benign_silent_exec == 16

    def test_the_current_unattended_run_leaks_nothing(self):
        result = run_unattended(
            label="now",
            registry=HISTORY["allowlist"][0],
            mode=RunMode.UNATTENDED,
            preapproved_scopes=frozenset(),
        )
        assert result.exposure == 0

    def test_a_ci_allowlist_restores_the_pipeline(self):
        result = run_unattended(
            label="ci",
            registry=HISTORY["allowlist"][0],
            mode=RunMode.UNATTENDED,
            preapproved_scopes=ci_patterns(),
        )
        assert result.exposure == 0
        assert result.benign_silent_exec == 24  # 24/24 legitimate commands run

    def test_the_ci_allowlist_is_the_shape_a_real_one_would_have(self):
        patterns = ci_patterns()
        # Eight patterns, each a program + verb + flags. If this ever grows to
        # include bare program names, the granularity has regressed to the thing
        # that let `git push --force` ride in behind a `git` grant.
        assert len(patterns) == 8
        assert all(len(pattern.split()) >= 2 for pattern in patterns)


class TestOutOfSample:
    """The check that the classifier was not fitted to its own corpus."""

    def test_the_corpus_overstated_the_old_mechanism(self):
        """The finding: an in-distribution corpus nearly doubled the blocklist's
        apparent recall. 68% in-distribution, 36% on real incidents."""
        result = out_of_sample()
        assert result["total"] == 11
        assert result["blocklist_caught"] == 4  # 36%
        assert result["blocklist_caught"] / result["total"] < 0.4
        assert experiment_a()["blocklist"]["recall"] > 0.65

    def test_the_allowlist_asks_about_every_real_incident(self):
        result = out_of_sample()
        assert result["allowlist_asked"] == 11
        assert result["allowlist_missed"] == []

    def test_no_incident_command_collides_with_the_ci_allowlist(self):
        """The allowlist is built from legitimate commands, so validating it
        against legitimate commands would be circular. This is the test that
        means something."""
        from eval.run_eval import ci_collisions

        assert ci_collisions() == []
