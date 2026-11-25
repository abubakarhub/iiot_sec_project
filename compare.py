"""
compare.py - Before/after comparison of every attack (integration).

    python main.py --compare

What it does, step by step:
  1. builds a fresh INSECURE building, runs normal traffic, runs ALL attacks
     -> results/before.csv
  2. builds a fresh SECURE building (new database, new keys), runs the same
     traffic and the SAME attack code -> results/after.csv
  3. joins both into results/comparison.csv and results/comparison.md
  4. draws results/before_after.png (attack success rate per attack, both modes)
  5. regenerates the other graphs (trees, cipher benchmark, privacy) so one
     command reproduces every file in results/

No number is typed in by hand: every value comes from an attack that really
ran against the live system in that mode.
"""

import csv
import logging
import os

import config
from core import chart_style
from core.simulation import SmartBuilding
from module1_attacks import attack_runner, trees
from module2_crypto import benchmark
from module3_access import privacy

log = logging.getLogger("compare")

COMPARISON_COLUMNS = ["attack", "before_attempts", "before_successes", "before_rate_pct",
                      "before_outcome", "after_attempts", "after_successes", "after_rate_pct",
                      "after_outcome", "reduction_pct_points", "after_observed_defence"]


def attack_one_mode(mode, rounds=config.SIM_ROUNDS):
    """Start a fresh building in `mode`, generate traffic, run every attack, save the CSV."""
    log.info("=== %s mode: starting fresh building ===", mode.upper())
    with SmartBuilding(mode) as building:
        building.start()
        building.run_rounds(rounds)
        results = attack_runner.run_all(building)
        if mode == "secure":                         # privacy export needs the secure DB
            privacy.run(config.RESULTS_DIR, db=building.db)
    name = "before.csv" if mode == "insecure" else "after.csv"
    attack_runner.write_csv(results, os.path.join(config.RESULTS_DIR, name))
    return results


def join_results(before, after):
    """Pair the insecure and secure result of each attack into one comparison row."""
    after_by_name = {r["attack"]: r for r in after}
    rows = []
    for b in before:
        a = after_by_name[b["attack"]]
        rows.append({
            "attack": b["attack"],
            "before_attempts": b["attempts"], "before_successes": b["successes"],
            "before_rate_pct": b["success_rate_pct"], "before_outcome": b["outcome"],
            "after_attempts": a["attempts"], "after_successes": a["successes"],
            "after_rate_pct": a["success_rate_pct"], "after_outcome": a["outcome"],
            "reduction_pct_points": round(b["success_rate_pct"] - a["success_rate_pct"], 1),
            "after_observed_defence": a["observed_defence"],
        })
    return rows


def write_comparison_csv(rows, path):
    """Save the joined rows as CSV."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMPARISON_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def write_comparison_markdown(rows, path):
    """Save a Markdown table ready to paste into the report."""
    lines = ["# Before / after comparison", "",
             "Same attack code against the insecure baseline and the secured system.", "",
             "| Attack | Insecure: success | Secure: success | Outcome after | "
             "Defence observed in secure mode |",
             "|---|---|---|---|---|"]
    for r in rows:
        defence = r["after_observed_defence"].replace("|", "/")
        lines.append(f"| {r['attack']} | {r['before_successes']}/{r['before_attempts']} "
                     f"({r['before_rate_pct']}%) | {r['after_successes']}/{r['after_attempts']} "
                     f"({r['after_rate_pct']}%) | {r['after_outcome']} | {defence} |")
    lines += ["",
              "Notes:",
              "* brute_force: attempts = passwords tried; success = account taken over "
              "(1 = yes), so its rate is 100% or 0%.",
              "* flooding_*: success = flood messages / requests the system accepted. A rate "
              "limiter lets a small burst through by design, so these are PARTIAL, not 0%.",
              "* Every number comes from attacks that really ran against the live system "
              "(database rows, lock state, broker and HTTP replies)."]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def plot_before_after(rows, path):
    """Grouped bar chart: success rate of each attack, insecure (blue) vs secure (orange)."""
    fig, ax = chart_style.new_figure(width=11, height=4.8)
    names = [r["attack"].replace("_", "\n") for r in rows]
    x = list(range(len(rows)))
    before = [r["before_rate_pct"] for r in rows]
    after = [r["after_rate_pct"] for r in rows]
    width = 0.38
    bars_b = ax.bar([i - 0.2 for i in x], before, width, color=chart_style.SERIES[0],
                    label="Insecure baseline (before)")
    bars_a = ax.bar([i + 0.2 for i in x], after, width, color=chart_style.SERIES[1],
                    label="Secured system (after)")
    # Label every "after" bar (a 0% bar is invisible otherwise) and any "before" bar under 100%.
    for bar, value in list(zip(bars_a, after)) + [(b, v) for b, v in zip(bars_b, before) if v < 100]:
        ax.annotate(f"{value:g}%", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    ha="center", va="bottom", fontsize=8, color=chart_style.INK,
                    xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=9)
    ax.set_ylim(0, 115)
    ax.set_yticks(range(0, 101, 20))
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Attack success rate - same attacks, before vs after securing (lower is better)",
                 fontsize=12)
    ax.legend(frameon=False, fontsize=9, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.0))
    return chart_style.save(fig, path)


def print_table(rows):
    """Print the comparison in the console."""
    print(f"  {'attack':<22} {'insecure':>14} {'secure':>14}  {'after':<10} defence observed")
    for r in rows:
        before = f"{r['before_successes']}/{r['before_attempts']} {r['before_rate_pct']:g}%"
        after = f"{r['after_successes']}/{r['after_attempts']} {r['after_rate_pct']:g}%"
        print(f"  {r['attack']:<22} {before:>14} {after:>14}  {r['after_outcome']:<10} "
              f"{r['after_observed_defence'][:60]}")


def run_compare(rounds=config.SIM_ROUNDS):
    """Run the full before/after experiment and write every output file. Returns the rows."""
    os.makedirs(config.RESULTS_DIR, exist_ok=True)
    trees.draw_all(config.RESULTS_DIR)
    benchmark.main(config.RESULTS_DIR)

    before = attack_one_mode("insecure", rounds)
    after = attack_one_mode("secure", rounds)
    rows = join_results(before, after)

    write_comparison_csv(rows, os.path.join(config.RESULTS_DIR, "comparison.csv"))
    write_comparison_markdown(rows, os.path.join(config.RESULTS_DIR, "comparison.md"))
    plot_before_after(rows, os.path.join(config.RESULTS_DIR, "before_after.png"))
    return rows
