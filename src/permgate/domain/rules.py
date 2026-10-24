"""The rule tables, as data.

Everything in this module is inert: no functions, no IO, no decisions. That is
deliberate. The rules are the part of the system a reviewer, an auditor or a
security engineer will want to read, diff and argue about, so they are kept
where they can be read without following any control flow. The code that *uses*
them is in :mod:`permgate.domain.bash_policy`.

The design stance, stated once and inherited by everything below:

    The blocklist asks "does this look dangerous?" and cannot be finished --
    ``terraform destroy -auto-approve`` and ``kubectl delete namespace
    production`` are catastrophic and no regex for "looks dangerous" catches
    them, because the danger is in what the program *does*, not in how it is
    spelled.

    So the consent layer asks the opposite question: **is this a command we can
    vouch for?** Everything else reaches the user. The blocklist stays as a
    second layer at execution time; it is just no longer the only thing
    standing between the agent and the shell.

Threat model, stated plainly: this defends against the **agent going
off-script**, not against a **hostile repository**. ``make`` and ``pytest`` run
the project's own code and they are vouched for, because a coding agent that
cannot run the test suite is a coding agent nobody will use. Commands that
reach outside the project -- installers, network clients, infra tools, anything
that reinterprets a string as code -- are not.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Layer 2: the blocklist. Last-resort stop, applied where the command runs.
# --------------------------------------------------------------------------
#
# Each entry is (compiled pattern, reason). The reason is shown to the user, so
# it has to say what is wrong, not restate the pattern.

DANGEROUS_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # recursive delete aimed at root/home (force flag optional)
    (re.compile(r"\brm\s+(-\w*)?-r\w*\s+(/|~|\$HOME)"), "recursive delete on home/root"),
    # recursive (-r/-R) and force (-f) flags together, in any order or spacing
    (re.compile(r"\brm\b(?=(?:.*\s)?-\w*[rR])(?=(?:.*\s)?-\w*f)"), "force recursive delete"),
    # the same, written with long-form flags
    (
        re.compile(r"\brm\b.*--recursive\b.*--force\b|\brm\b.*--force\b.*--recursive\b"),
        "force recursive delete",
    ),
    (re.compile(r"\bmkfs\b"), "format filesystem"),
    (re.compile(r"\bdd\s+.*of=/dev/"), "raw disk write"),
    (re.compile(r">\s*/dev/sd[a-z]"), "overwrite block device"),
    (re.compile(r"\bchmod\s+(-R\s+)?777\s+/"), "chmod 777 on root"),
    (re.compile(r":\(\)\s*\{.*:\|:.*\}"), "fork bomb"),
    (re.compile(r"\bcurl\b.*\|\s*(sudo\s+)?(ba)?sh\b"), "pipe curl to shell"),
    (re.compile(r"\bwget\b.*\|\s*(sudo\s+)?(ba)?sh\b"), "pipe wget to shell"),
)

# --------------------------------------------------------------------------
# Layer 1: the allowlist. The consent layer asks this first.
# --------------------------------------------------------------------------

# Programs whose default use inspects rather than mutates. Presence here is
# necessary but not sufficient -- several of them (git, find, python) get a
# second look at their arguments before they are vouched for.
SAFE_PROGRAMS: frozenset[str] = frozenset(
    {
        # looking around
        "ls",
        "pwd",
        "cat",
        "head",
        "tail",
        "wc",
        "file",
        "stat",
        "tree",
        "which",
        "whoami",
        "date",
        "uname",
        "df",
        "du",
        "basename",
        "dirname",
        # searching
        "grep",
        "rg",
        "ag",
        "fd",
        "find",
        "locate",
        # text shaping (none of these write in place)
        "echo",
        "sort",
        "uniq",
        "cut",
        "tr",
        "diff",
        "comm",
        "jq",
        # version control, restricted to the read-only verbs below
        "git",
        # the project's own tests and tooling
        "pytest",
        "ruff",
        "mypy",
        "black",
        "flake8",
        "coverage",
        "isort",
        "make",
        "npm",
        "yarn",
        "pnpm",
        "cargo",
        "go",
        "tox",
        "nox",
        # interpreters, restricted to ``-m <safe module>`` below
        "python",
        "python3",
    }
)

# Programs never vouched for, whatever the arguments say. Shells and interpreter
# entry points run arbitrary strings; network clients move data in and out;
# installers and infra tools reach outside the project.
NEVER_SAFE: frozenset[str] = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "fish",
        "csh",
        "ksh",
        "dash",
        "sudo",
        "su",
        "doas",
        "eval",
        "exec",
        "xargs",
        "env",
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "telnet",
        "rm",
        "rmdir",
        "mv",
        "dd",
        "mkfs",
        "shred",
        "truncate",
        "tee",
        "chmod",
        "chown",
        "chgrp",
        "ln",
        "kill",
        "pkill",
        "killall",
        "shutdown",
        "reboot",
        "halt",
        "docker",
        "podman",
        "kubectl",
        "helm",
        "terraform",
        "aws",
        "gcloud",
        "az",
        "vagrant",
        "pip",
        "pip3",
        "conda",
        "apt",
        "apt-get",
        "yum",
        "dnf",
        "brew",
        "snap",
        "gem",
        "crontab",
        "systemctl",
        "service",
        "launchctl",
        "at",
        "sed",
        "awk",
        "perl",
        "ruby",
        "node",
        "deno",
    }
)

# Mutating programs that are routine when -- and only when -- they are confined
# to relative paths inside the project. ``rm -rf ./build`` is a thing every
# developer does daily; ``rm -rf /`` and ``rm -rf ~/Documents`` are not the same
# act with a different spelling, they are a different act. Asking about the
# first one trains users to approve without reading, which costs more safety
# than it buys.
#
# The justification is NOT "a relative path cannot escape the tree". That was
# the original wording and it is wrong: ``rm -rf src/`` is just as relative as
# ``rm -rf build/``, and if ``src/`` is untracked there is nothing to restore it
# from. claude-code#23913 is exactly that -- 2,229 untracked source files
# destroyed by a relative-path ``rm``, of which only 16 had ever been committed.
#
# The real justification is narrower and true: a *recursive* delete is only
# routine when the target is build output, because build output is regenerable
# by definition. A non-recursive ``rm`` names the one file it destroys, so its
# blast radius is the file on the command line.
BOUNDED_MUTATORS: frozenset[str] = frozenset({"rm", "rmdir", "chmod"})

# Directory names that are build output. Deleting these destroys nothing that
# cannot be recreated, which is the only reason a recursive rm gets a pass.
REGENERABLE: frozenset[str] = frozenset(
    {
        "build",
        "dist",
        "out",
        "target",
        "node_modules",
        "bower_components",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".cache",
        ".parcel-cache",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        "coverage",
        ".coverage",
        "htmlcov",
        ".nyc_output",
        "venv",
        ".venv",
        ".eggs",
        ".gradle",
        ".terraform",
    }
)

# Read-only git verbs. ``git status`` is inspection; ``git push --force`` is not.
SAFE_GIT_VERBS: frozenset[str] = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "branch",
        "remote",
        "tag",
        "describe",
        "blame",
        "rev-parse",
        "ls-files",
        "shortlog",
        "whatchanged",
        "cat-file",
        "config",
    }
)

# ...but four of those are read-only only in their *listing* form. ``git branch``
# lists; ``git branch -D main`` deletes a branch. ``git config -l`` reads;
# ``git config user.email x`` writes. The verb alone cannot tell those apart, so
# these four get a second look at their arguments.
GIT_LISTING_VERBS: frozenset[str] = frozenset({"branch", "remote", "tag", "config"})

# Flags that turn a listing verb into a write, wherever they appear after it.
GIT_MUTATING_FLAGS: frozenset[str] = frozenset(
    {
        "-d",
        "-D",
        "-m",
        "-M",
        "-c",
        "-C",
        "--delete",
        "--move",
        "--copy",
        "-f",
        "--force",
        "-u",
        "--set-upstream-to",
        "--unset",
        "--unset-all",
        "--add",
        "--replace-all",
        "--rename-section",
        "--remove-section",
        "--set-url",
        "--prune",
        "--edit",
    }
)

# Global flags that take a value. Without skipping them, ``git -C /path status``
# reads its verb as ``/path`` and gets rejected as an unknown program.
GIT_VALUE_FLAGS: frozenset[str] = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
)

# ``python -m <module>`` is a shell by another name, so the module is checked too.
SAFE_PY_MODULES: frozenset[str] = frozenset(
    {
        "pytest",
        "unittest",
        "mypy",
        "ruff",
        "coverage",
        "compileall",
        "black",
        "flake8",
        "isort",
        "json.tool",
        "pydoc",
        "timeit",
        "venv",
    }
)

# --------------------------------------------------------------------------
# Lexical rules that are not tables
# --------------------------------------------------------------------------

# Credential-shaped paths: reading one is a leak even when the program is `cat`.
# Two shapes, because they sit differently in a command line. Directory-style
# names (``.ssh``, ``id_rsa``) are preceded by a separator or a space -- a bare
# ``cat .env`` has a space in front of it, not a slash. Extension-style names
# (``server.pem``) hang off a filename, so there is nothing in front of them.
SENSITIVE_PATH = re.compile(
    r"(^|[\s/\\~=])(\.ssh|\.aws|\.gnupg|\.kube|id_rsa|id_dsa|id_ecdsa|id_ed25519"
    r"|\.netrc|\.git-credentials|\.npmrc|\.pypirc|\.docker/config\.json"
    r"|\.env|credentials|secrets)([/\\]|$|\.)"
    r"|[\w.-]+\.(pem|key|p12|pfx)([/\\]|$)",
    re.IGNORECASE,
)

# ``cat .env.example`` is documentation, not a secret. Don't cry wolf on it.
SENSITIVE_EXEMPT = re.compile(r"\.(example|sample|template|dist|md|txt)$", re.IGNORECASE)

# Redirection writes a file without ever naming a tool, so it is checked on the
# raw text. The harmless descriptor dupes are stripped first.
REDIRECTION_OK = re.compile(r"\d*>&\d*|&>")

# A "relative path" is only bounded if it stays the path it looks like.
# ``$HOME`` and ``${PWD}`` expand to wherever the environment says; ``*`` and
# ``?`` glob to whatever happens to be there; ``$(...)`` and backticks run a
# command and splice in its output. ``rm -rf *`` and ``rm -rf $HOME`` both read
# as relative paths and neither is bounded by anything.
SHELL_EXPANSION = re.compile(r"[$`*?\[{]")

# Windows absolute paths, which the POSIX checks would otherwise read as
# relative.
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")

# The one absolute tree where deleting is bounded by the directory's own
# contract: things in ``/tmp`` are temporary, or they are in the wrong place.
# The target has to be strictly *inside* a temp root -- ``rm -rf /tmp`` and
# ``rm -rf /tmp/`` both stay outside it, because the directory itself is not
# scratch space.
TEMP_ROOTS: tuple[str, ...] = ("/tmp/", "/var/tmp/", "/private/tmp/")

# Read-only tools. Kept here rather than in the engine so that adding a tool is
# a data change, not a code change.
READ_ONLY_TOOLS: frozenset[str] = frozenset({"read_file", "glob", "grep", "todo_write"})

# Tools that mutate and have no finer signal available. They always reach the
# user (or are refused when there is nobody to ask).
MUTATING_TOOLS: frozenset[str] = frozenset({"bash", "write_file", "edit_file", "agent"})
