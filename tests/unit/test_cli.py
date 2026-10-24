"""The command-line entry point.

`classify` is the subcommand that earns its place -- it runs the rule layer with
no database, no server and no configuration, which makes it usable in a
pre-commit hook and from a shell while writing a rule. The rest is
administration, and it is tested because a documented entry point that nobody
exercises is a documented entry point that is broken.

These call `main()` in-process rather than shelling out, so a failure points at
the code rather than at a subprocess boundary.
"""

from __future__ import annotations

import json

import pytest

from permgate import cli
from permgate.config import get_settings


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    """Point the CLI's settings at a throwaway database.

    `get_settings` is lru_cached, so setting the environment is not enough --
    the cache has to be cleared or the test picks up whatever the previous one
    left behind. That is the same trap that made four denial tests pass for the
    wrong reason earlier in this project's life.
    """
    monkeypatch.setenv(
        "PERMGATE_DATABASE_URL", f"sqlite+pysqlite:///{(tmp_path / 'cli.db').as_posix()}"
    )
    monkeypatch.setenv("PERMGATE_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("PERMGATE_LOG_JSON", "false")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


class TestClassify:
    def test_a_vouched_command_exits_zero(self, capsys):
        assert cli.main(["classify", "ls -la"]) == 0
        assert "vouched" in capsys.readouterr().out

    def test_a_flagged_command_exits_one(self, capsys):
        """The exit code is the interface: a pre-commit hook reads it, so it
        has to mean something. 0 = vouched, 1 = needs a human."""
        assert cli.main(["classify", "kubectl delete namespace production"]) == 1
        assert "not vouched" in capsys.readouterr().out

    def test_json_output_is_machine_readable(self, capsys):
        cli.main(["classify", "ls -la", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["vouched"] is True
        assert payload["scope"] == "ls -la"
        assert payload["allowlist_reason"] is None

    def test_json_reports_the_scope_a_grant_would_name(self, capsys):
        cli.main(["classify", "git push --force origin main", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["vouched"] is False
        assert payload["scope"] == "git push --force"

    def test_layers_are_reported_separately(self, capsys):
        """A command can be unvouched by the allowlist and missed by the
        blocklist. Reporting one number would hide that."""
        cli.main(["classify", "terraform destroy -auto-approve", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["allowlist_reason"] is not None
        assert payload["blocklist_reason"] is None

    def test_the_execution_gate_is_reported(self, capsys):
        cli.main(["classify", "mkfs.ext4 /dev/sda1", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["execution_block"] is not None

    def test_multi_word_commands_are_rejoined(self, capsys):
        # An unquoted command arrives as several argv entries and is joined
        # back with single spaces. Flags have to be quoted or argparse claims
        # them for the subcommand -- which is why every shell example in the
        # README quotes the command.
        cli.main(["classify", "git", "status", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["command"] == "git status"


class TestDecide:
    def test_decide_writes_a_row_and_prints_it(self, isolated_settings, capsys):
        code = cli.main(["decide", "ls -la", "--project", str(isolated_settings)])
        payload = json.loads(capsys.readouterr().out)
        assert payload["verdict"] == "ask"
        assert payload["rule"] == "unrecognised"
        assert payload["decision_id"]
        assert code == 3  # not allowed

    def test_decide_returns_zero_when_allowed(self, isolated_settings, capsys):
        cli.main(
            ["decide", "read_file", "--tool", "read_file", "--project", str(isolated_settings)]
        )
        capsys.readouterr()
        code = cli.main(["decide", "ls", "--project", str(isolated_settings)])
        capsys.readouterr()
        assert code == 3  # still an ask without a grant

    def test_decide_reports_the_scope(self, isolated_settings, capsys):
        cli.main(
            ["decide", "kubectl delete namespace production", "--project", str(isolated_settings)]
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["scope"] == "kubectl delete"

    def test_bypass_mode_is_refused_by_default(self, isolated_settings):
        from permgate.services.errors import ModeNotAllowed

        with pytest.raises(ModeNotAllowed):
            cli.main(["decide", "ls", "--project", str(isolated_settings), "--mode", "bypass"])


class TestGrantAdministration:
    def _decide(self, project):
        cli.main(["decide", "ls -la", "--project", str(project)])

    def test_grants_start_empty(self, isolated_settings, capsys):
        assert cli.main(["grants", "--project", str(isolated_settings)]) == 0
        assert "no standing grants" in capsys.readouterr().out

    def test_a_project_only_appears_once_it_has_been_asked_about(self, isolated_settings, capsys):
        capsys.readouterr()
        self._decide(isolated_settings)
        capsys.readouterr()
        assert cli.main(["grants", "--project", str(isolated_settings)]) == 0
        assert "no standing grants" in capsys.readouterr().out

    def test_revoke_reports_what_it_removed(self, isolated_settings, capsys):
        self._decide(isolated_settings)
        capsys.readouterr()
        assert cli.main(["revoke", "bash", "--project", str(isolated_settings)]) == 0
        assert "not found" in capsys.readouterr().out

    def test_clear_reports_a_count(self, isolated_settings, capsys):
        self._decide(isolated_settings)
        capsys.readouterr()
        assert cli.main(["revoke", "--all", "--project", str(isolated_settings)]) == 0
        assert "cleared 0 grant" in capsys.readouterr().out

    def test_audit_is_empty_before_anything_happens(self, isolated_settings, capsys):
        assert cli.main(["audit", "--project", str(isolated_settings)]) == 0
        assert capsys.readouterr().out.strip() == ""

    def test_audit_lists_what_was_decided(self, isolated_settings, capsys):
        self._decide(isolated_settings)
        capsys.readouterr()
        assert cli.main(["audit", "--project", str(isolated_settings)]) == 0
        out = capsys.readouterr().out
        assert "ask" in out and "unrecognised" in out
        assert "reason" not in out  # `ls` is unflagged, so there is nothing to explain

    def test_audit_json_carries_the_digest(self, isolated_settings, capsys):
        self._decide(isolated_settings)
        capsys.readouterr()
        cli.main(["audit", "--project", str(isolated_settings), "--json"])
        entries = json.loads(capsys.readouterr().out)
        assert entries[0]["arguments_digest"]
        assert entries[0]["arguments"] == {"command": "ls -la"}

    def test_audit_can_filter_by_verdict(self, isolated_settings, capsys):
        self._decide(isolated_settings)
        capsys.readouterr()
        cli.main(["audit", "--project", str(isolated_settings), "--verdict", "deny", "--json"])
        assert json.loads(capsys.readouterr().out) == []


class TestParser:
    def test_no_subcommand_is_an_error(self):
        with pytest.raises(SystemExit):
            cli.main([])

    def test_an_unknown_subcommand_is_an_error(self):
        with pytest.raises(SystemExit):
            cli.main(["frobnicate"])

    def test_an_unknown_mode_is_rejected_by_the_parser(self):
        with pytest.raises(SystemExit):
            cli.main(["decide", "ls", "--mode", "god"])

    def test_every_documented_subcommand_exists(self):
        """The README lists these; a parser that drifted from it would be a
        documented interface that does not exist."""
        parser = cli.build_parser()
        actions = [
            action for action in parser._actions if hasattr(action, "choices") and action.choices
        ]
        assert actions, "expected a subparser action"
        assert set(actions[0].choices) == {
            "classify",
            "decide",
            "grants",
            "revoke",
            "audit",
            "client",
            "eval",
            "serve",
        }

    def test_eval_points_at_a_script_that_exists(self):
        """`permgate eval` delegates to `eval/run_eval.py` by path. Renaming the
        harness without updating the CLI would fail only at runtime."""
        from pathlib import Path

        script = Path(cli.__file__).resolve().parent.parent.parent / "eval" / "run_eval.py"
        assert script.is_file()
