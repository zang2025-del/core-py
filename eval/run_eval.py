"""Evaluation report: classifier quality, exposure, and out-of-sample check.

Runs entirely offline. This is the quality gate the service ships with -- the
rule layer is the part most likely to regress silently, and a metric that only
exists in a pasted-in report cannot catch that.

Usage::

    python eval/run_eval.py
    python eval/run_eval.py --json eval/reports/latest.json
    python eval/run_eval.py --md eval/reports/latest.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))
if str(HERE.parent / "src") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "src"))

from eval.corpus import (  # noqa: E402
    BENIGN_COMMANDS,
    CONSEQUENTIAL_COMMANDS,
    DANGEROUS_COMMANDS,
    SAFE_COMMANDS,
)
from eval.harness import run_chain, run_unattended, trusting  # noqa: E402
from eval.real_incidents import INCIDENTS  # noqa: E402
from permgate.domain import bash_policy  # noqa: E402
from permgate.domain.decision import RunMode  # noqa: E402
from permgate.domain.policies import HISTORY  # noqa: E402

# --------------------------------------------------------------------------
# Experiment A -- classifier quality
# --------------------------------------------------------------------------


def _quality(classify) -> dict[str, Any]:
    """Score one classifier.

    ``disturbance`` and ``false_positive`` are deliberately separate. Asking
    about ``git clean -fd`` is *correct* -- it irreversibly deletes untracked
    files -- and also annoying. Only the second number is a mistake the rules
    could fix, and conflating them is what made an earlier version of this
    project chase a "42% false-positive rate" that did not exist.
    """
    asked = [c for c in BENIGN_COMMANDS if classify(c)]
    false_positives = [c for c in SAFE_COMMANDS if classify(c)]
    caught = [c for c in DANGEROUS_COMMANDS if classify(c)]
    missed = [c for c in DANGEROUS_COMMANDS if not classify(c)]
    return {
        "recall": len(caught) / len(DANGEROUS_COMMANDS),
        "disturbance": len(asked) / len(BENIGN_COMMANDS),
        "false_positive": len(false_positives) / len(SAFE_COMMANDS),
        "caught": caught,
        "missed": missed,
        "asked": asked,
        "false_positives": false_positives,
    }


def experiment_a() -> dict[str, Any]:
    return {
        "benign_total": len(BENIGN_COMMANDS),
        "safe_total": len(SAFE_COMMANDS),
        "consequential_total": len(CONSEQUENTIAL_COMMANDS),
        "dangerous_total": len(DANGEROUS_COMMANDS),
        "blocklist": _quality(bash_policy.check_dangerous),
        "allowlist": _quality(bash_policy.classify_bash_command),
    }


# --------------------------------------------------------------------------
# Experiment B -- end-to-end outcome, per historical configuration
# --------------------------------------------------------------------------


def experiment_b() -> dict[str, Any]:
    scenarios = (
        ("改造前 · 信任型", "legacy", trusting),
        ("第一轮（黑名单） · 信任型", "blocklist", trusting),
        ("第三轮（白名单） · 信任型", "allowlist", trusting),
        ("第三轮（白名单） · 谨慎型", "allowlist", lambda _c, _d: "once"),
    )
    results = {}
    for label, key, answerer in scenarios:
        registry, _ = HISTORY[key]
        results[label] = run_chain(label=label, registry=registry, answerer=answerer)
    return results


# --------------------------------------------------------------------------
# Experiment B2 -- unattended runs
# --------------------------------------------------------------------------


def ci_patterns() -> frozenset[str]:
    """The pre-approved scope list an operator would actually write.

    Generated from the legitimate commands that get asked about -- which is what
    a real CI allowlist is: someone looked at what the pipeline runs and wrote
    it down. It is then tested against the *dangerous* half, to check that no
    dangerous command happens to share a scope with a legitimate one. Generating
    it from the legitimate half and validating it on the dangerous half is what
    keeps this from being circular.
    """
    return frozenset(
        scope
        for command in BENIGN_COMMANDS
        if command in CONSEQUENTIAL_COMMANDS
        for scope in [bash_policy.command_scope("bash", {"command": command})]
        if scope
    )


def experiment_b2() -> dict[str, Any]:
    preapproved = ci_patterns()
    scenarios = {
        "改造前的 --yes（无条件）": run_unattended(
            label="改造前的 --yes（无条件）",
            registry=HISTORY["legacy"][0],
            mode=RunMode.BYPASS,
            preapproved_scopes=frozenset(),
        ),
        "现在的 --yes（放行例行、拒绝被标记的）": run_unattended(
            label="现在的 --yes",
            registry=HISTORY["allowlist"][0],
            mode=RunMode.UNATTENDED,
            preapproved_scopes=frozenset(),
        ),
        "现在的 --yes + CI 预授权": run_unattended(
            label="现在的 --yes + CI",
            registry=HISTORY["allowlist"][0],
            mode=RunMode.UNATTENDED,
            preapproved_scopes=preapproved,
        ),
    }
    return {"patterns": sorted(preapproved), "runs": scenarios}


# --------------------------------------------------------------------------
# Out-of-sample
# --------------------------------------------------------------------------


def out_of_sample() -> dict[str, Any]:
    rows = []
    for incident in INCIDENTS:
        command = incident["command"]
        rows.append(
            {
                **incident,
                "blocklist": bash_policy.check_dangerous(command),
                "allowlist": bash_policy.classify_bash_command(command),
                "vouched": bash_policy.classify_bash_command(command) is None,
                "hard_block": bash_policy.execution_block(command),
            }
        )
    total = len(rows)
    return {
        "total": total,
        "blocklist_caught": sum(1 for row in rows if row["blocklist"]),
        "allowlist_asked": sum(1 for row in rows if not row["vouched"]),
        "blocklist_missed": [row for row in rows if not row["blocklist"]],
        "allowlist_missed": [row for row in rows if row["vouched"]],
        "rows": rows,
    }


def ci_collisions() -> list[tuple[str, str, str]]:
    """Any real incident command sharing a scope with the CI allowlist?

    The allowlist is generated from legitimate commands. Checking it against
    legitimate commands would be circular; checking it against the out-of-sample
    incidents is the test that means something.
    """
    preapproved = ci_patterns()
    hits = []
    for incident in INCIDENTS:
        scope = bash_policy.command_scope("bash", {"command": incident["command"]})
        if scope is not None and scope in preapproved:
            hits.append((incident["id"], incident["command"], scope))
    return hits


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def build_report() -> dict[str, Any]:
    return {
        "experiment_a": experiment_a(),
        "experiment_b": {
            label: {
                "prompts": result.prompts,
                "exposure": result.exposure,
                "silent_blocks": result.silent_blocks,
                "benign_silent_exec": result.benign_silent_exec,
                "per_corpus": {
                    corpus_label: {
                        outcome.value: list(commands) for outcome, commands in buckets.items()
                    }
                    for corpus_label, buckets in result.by_label.items()
                },
            }
            for label, result in experiment_b().items()
        },
        "experiment_b2": {
            "patterns": experiment_b2()["patterns"],
            "runs": {
                label: {
                    "exposure": result.exposure,
                    "benign_passed": result.benign_silent_exec,
                }
                for label, result in experiment_b2()["runs"].items()
            },
        },
        "out_of_sample": out_of_sample(),
        "ci_collisions": ci_collisions(),
    }


def render(report: dict[str, Any]) -> str:
    out: list[str] = []

    def w(line: str = "") -> None:
        out.append(line)

    a = report["experiment_a"]
    w("=" * 78)
    w("实验 A —— 判别质量：黑名单（改造前） vs 白名单（现在）")
    w("=" * 78)
    w()
    w(
        f"语料：{a['benign_total']} 条合法命令"
        f"（其中 {a['safe_total']} 条完全安全、{a['consequential_total']} 条会不可逆地丢东西），"
        f"{a['dangerous_total']} 条危险命令"
    )
    w()
    w(f"  {'策略':<34}{'召回率':>9}{'打扰率':>9}{'误伤率':>9}")
    w("  " + "-" * 61)
    for label, key in (
        ("黑名单：列出危险的（改造前）", "blocklist"),
        ("白名单：列出已知安全的（现在）", "allowlist"),
    ):
        q = a[key]
        w(f"  {label:<34}{q['recall']:>8.0%}{q['disturbance']:>9.0%}{q['false_positive']:>9.0%}")
    w()
    w("  召回率：危险命令被识别出来的比例")
    w("  打扰率：合法命令被问的比例 —— 用户在承受的摩擦")
    w("  误伤率：完全安全却被问的比例 —— 工具判错了，只有这部分可以优化")
    w()
    missed_old = a["blocklist"]["missed"]
    w(f"  黑名单漏掉的危险命令（{len(missed_old)}/{a['dangerous_total']}）：")
    for command in missed_old:
        w(f"      {command}")
    w()
    if a["allowlist"]["missed"]:
        w("  ⚠ 白名单仍然背书：")
        for command in a["allowlist"]["missed"]:
            w(f"      {command}")
    else:
        w("  ✅ 白名单在这一批语料上零背书。")
    w()

    w("=" * 78)
    w("实验 B —— 全链路归宿（同一批语料，四种配置）")
    w("=" * 78)
    w()
    w(f"  {'配置':<32}{'弹框':>7}{'静默拦截':>10}{'零感知危险执行':>16}")
    w("  " + "-" * 65)
    for label, data in report["experiment_b"].items():
        w(f"  {label:<32}{data['prompts']:>7}{data['silent_blocks']:>10}{data['exposure']:>16}")
    w()
    w("  零感知危险执行 = 没人被问、也没有机制拦下、命令直接跑了")
    w("  这是主指标：它衡量的是用户零感知的风险敞口。")
    w()

    w("=" * 78)
    w("实验 B2 —— 无人值守（--yes / CI）：一个标志能不能绕过前三轮")
    w("=" * 78)
    w()
    b2 = report["experiment_b2"]
    w(f"  {'模式':<40}{'危险命令放行':>14}{'合法命令放行':>14}")
    w("  " + "-" * 68)
    for label, data in b2["runs"].items():
        w(f"  {label:<40}{data['exposure']:>10}/25{data['benign_passed']:>11}/24")
    w()
    w(f"  CI 预授权清单（{len(b2['patterns'])} 条命令模式）：")
    for pattern in b2["patterns"]:
        w(f"      {pattern}")
    w()
    hits = report["ci_collisions"]
    if hits:
        w(f"  ⚠ {len(hits)} 条真实事故命令落进了 CI 清单的模式：")
        for incident_id, command, scope in hits:
            w(f"      [{incident_id}] {command}   →   {scope}")
    else:
        w("  ✅ 没有一条真实事故命令落进 CI 清单的模式里。")
        w("     清单是照合法命令列的，而事故里的毁灭性命令形状与它们不同。")
    w()

    w("=" * 78)
    w("样本外检验 —— 真实事故命令 × 判别器")
    w("=" * 78)
    w()
    oos = report["out_of_sample"]
    w(f"样本：{oos['total']} 条，全部来自公开事故报告，判别器设计时从未见过")
    w("口径：白名单「背书」= 不会询问 = 一次 always 之后静默执行")
    w()
    w(f"  {'来源':<24}{'旧黑名单':>10}{'新白名单':>10}")
    w("  " + "-" * 44)
    w(
        f"  {'拦下 / 询问':<24}{oos['blocklist_caught']:>7}/{oos['total']}"
        f"{oos['allowlist_asked']:>7}/{oos['total']}"
    )
    w(
        f"  {'漏掉（会静默执行）':<24}{len(oos['blocklist_missed']):>7}/{oos['total']}"
        f"{len(oos['allowlist_missed']):>7}/{oos['total']}"
    )
    w()
    for row in oos["rows"]:
        w(f"  [{row['id']}]  {row['severity']}")
        w(f"      命令  {row['command']}")
        w(f"      原文  {'是' if row['verbatim'] else '否（按报告描述重建）'}")
        w(f"      旧黑名单  {'✅ 拦下 —— ' + row['blocklist'] if row['blocklist'] else '❌ 漏掉'}")
        w(
            f"      新白名单  {'❌ 背书（不会问）' if row['vouched'] else '✅ 会问 —— ' + row['allowlist']}"
        )
        if row["hard_block"]:
            w(f"      执行层    ⛔ 即使问过也硬拦 —— {row['hard_block']}")
        w(f"      事故      {row['what']}")
        w(f"      出处      {row['source']}")
        w()
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write the raw metrics to this path")
    parser.add_argument("--md", help="write the rendered report to this path")
    args = parser.parse_args()

    report = build_report()
    text = render(report)

    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[已写出 {path}]")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("```\n" + text + "\n```\n", encoding="utf-8")
        print(f"[已写出 {path}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
