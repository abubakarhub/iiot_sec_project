"""
module3_access/privacy.py - Four privacy techniques for Smart Building data.

Building data can reveal people's behaviour: an energy meter shows when
someone is in the office, motion sensors show how many people are in a room,
and door-access logs show who arrives when. Before data is shared for
analytics (e.g. with a facilities contractor) we apply:

  1. PSEUDONYMISATION - replace device ids with keyed HMAC-SHA256 pseudonyms.
     Without the secret key, nobody can map "anon-3f9a..." back to "temp-01"
     (an unkeyed SHA-256 hash would NOT be safe: just hash all known ids).
  2. AGGREGATION - publish hourly averages instead of 15-minute readings, so
     short events (someone switching on a kettle) disappear. Totals are kept.
  3. DIFFERENTIAL PRIVACY (noise) - add Laplace noise to occupancy counts, so
     the presence or absence of ONE person cannot be detected (epsilon = 0.5).
  4. K-ANONYMITY - remove names/badges and generalise age and entry time, so
     every record looks like at least k-1 other records (k = 3).

    python -m module3_access.privacy
Outputs: results/privacy_before_after.png and results/analytics_export.csv
"""

import csv
import hashlib
import hmac
import math
import os
import random
from collections import Counter

from config import DEVICES
from core import chart_style
from module2_crypto.keygen import new_key

EPSILON = 0.5
K = 3
QUASI_IDENTIFIERS = ("age", "department", "entry_hour")
MAIN_METRIC = {"temperature": "temperature_c", "energy": "power_w",
               "motion": "occupancy", "door_lock": "unlock_count"}


# ====================================================================== 1. pseudonymisation
def pseudonym(identifier, key):
    """Keyed pseudonym: 'anon-' + first 10 hex chars of HMAC-SHA256(key, identifier)."""
    return "anon-" + hmac.new(key, identifier.encode(), hashlib.sha256).hexdigest()[:10]


def dictionary_attack(pseudonyms, known_ids):
    """Attacker hashes every known id with plain SHA-256 and looks for matches."""
    guesses = {"anon-" + hashlib.sha256(i.encode()).hexdigest()[:10] for i in known_ids}
    return sum(1 for p in pseudonyms if p in guesses)


# ====================================================================== 2. aggregation
def aggregate(values, window):
    """Average every `window` consecutive values (e.g. 4 x 15 min -> 1 hour)."""
    return [sum(values[i:i + window]) / len(values[i:i + window])
            for i in range(0, len(values), window)]


# ====================================================================== 3. differential privacy
def laplace_noise(scale, rng):
    """One sample of Laplace(0, scale) noise using the inverse-CDF method."""
    u = rng.random() - 0.5
    while u == -0.5:                       # avoid log(0)
        u = rng.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))


def dp_count(true_count, epsilon, rng, sensitivity=1.0):
    """Release a count with epsilon-differential privacy (Laplace mechanism)."""
    return max(0, round(true_count + laplace_noise(sensitivity / epsilon, rng)))


# ====================================================================== 4. k-anonymity
def equivalence_classes(records, quasi_ids=QUASI_IDENTIFIERS):
    """Count how many records share each combination of quasi-identifier values."""
    return Counter(tuple(r[q] for q in quasi_ids) for r in records)


def smallest_group(records, quasi_ids=QUASI_IDENTIFIERS):
    """The 'k' of a dataset: size of its smallest equivalence class."""
    classes = equivalence_classes(records, quasi_ids)
    return min(classes.values()) if classes else 0


def generalise(record):
    """Drop direct identifiers; turn exact age/hour into ranges."""
    decade = record["age"] // 10 * 10
    start = record["entry_hour"] // 4 * 4
    return {"age": f"{decade}-{decade + 9}",
            "department": record["department"],
            "entry_hour": f"{start:02d}-{start + 3:02d}h"}


def k_anonymise(records, k=K):
    """Generalise every record, then suppress groups smaller than k. Returns (kept, suppressed)."""
    general = [generalise(r) for r in records]
    classes = equivalence_classes(general)
    kept = [r for r in general if classes[tuple(r[q] for q in QUASI_IDENTIFIERS)] >= k]
    return kept, len(general) - len(kept)


# ====================================================================== sample datasets
def synthetic_access_log(n=80, seed=7):
    """A day of door-access records (made-up people) with identifiers and quasi-identifiers."""
    rng = random.Random(seed)
    departments = ["Facilities", "Finance", "IT", "Research"]
    return [{"name": f"Employee {i:03d}", "badge": f"B{1000 + i}",
             "age": rng.randint(22, 63), "department": rng.choice(departments),
             "entry_hour": rng.choice([7, 8, 8, 9, 9, 9, 10, 11, 13, 14])}
            for i in range(n)]


def synthetic_energy_day(seed=3):
    """96 readings (every 15 min for 24 h) of an office energy meter, in watts."""
    rng = random.Random(seed)
    values = []
    for step in range(96):
        hour = step / 4
        base = 450 + (1400 if 8 <= hour < 18 else 0)
        spike = rng.choice([0, 0, 0, 0, 900])          # short appliance use
        values.append(base + spike + rng.uniform(-120, 120))
    return values


def synthetic_room_counts(seed=5):
    """True number of people seen by the motion sensors in each room."""
    rng = random.Random(seed)
    rooms = ["Lobby", "Lab A", "Lab B", "Office 1", "Office 2", "Meeting"]
    return {room: rng.randint(0, 12) for room in rooms}


# ====================================================================== real data export
def export_analytics(db, key, path):
    """Write a privacy-safe summary of the REAL readings in the cloud database."""
    rows = []
    for device in db.list_devices():
        metric = MAIN_METRIC.get(device["device_type"])
        values = [r["payload"].get(metric) for r in db.get_readings(device["device_id"], 10000)]
        values = [v for v in values if isinstance(v, (int, float))]
        rows.append({"device": pseudonym(device["device_id"], key),
                     "device_type": device["device_type"], "metric": metric,
                     "readings": len(values),
                     "average": round(sum(values) / len(values), 2) if values else ""})
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return rows


# ====================================================================== graph
def plot(energy, hourly, rooms, noisy, before_sizes, after_sizes, pseudo_rows, path):
    """2 x 2 before/after figure (blue = original data, orange = privacy-protected)."""
    before_c, after_c = chart_style.SERIES[0], chart_style.SERIES[1]
    fig = chart_style.plt.figure(figsize=(13, 8.5))
    fig.patch.set_facecolor(chart_style.SURFACE)
    axes = [fig.add_subplot(2, 2, i + 1) for i in range(4)]
    for ax in axes[:3]:
        chart_style.style_axes(ax)
    ax_agg, ax_dp, ax_k, ax_tab = axes

    # (a) aggregation
    ax_agg.plot([i / 4 for i in range(len(energy))], energy, color=before_c, linewidth=1.5,
                label="Original: every 15 min")
    ax_agg.step(list(range(len(hourly) + 1)), hourly + [hourly[-1]], where="post",
                color=after_c, linewidth=2, label="Shared: hourly average")
    ax_agg.set_xlim(0, 24)
    ax_agg.set_xticks(range(0, 25, 4))
    ax_agg.set_xlabel("Hour of day")
    ax_agg.set_ylabel("Power (W)")
    ax_agg.set_title("(a) Aggregation hides short activity spikes", fontsize=11)
    ax_agg.legend(frameon=False, fontsize=8, loc="upper left")

    # (b) differential privacy
    names = list(rooms)
    x = range(len(names))
    ax_dp.bar([i - 0.2 for i in x], [rooms[n] for n in names], 0.37, color=before_c,
              label="True count")
    ax_dp.bar([i + 0.2 for i in x], [noisy[n] for n in names], 0.37, color=after_c,
              label=f"Released with Laplace noise (epsilon={EPSILON})")
    ax_dp.set_xticks(list(x))
    ax_dp.set_xticklabels(names, fontsize=8)
    ax_dp.set_ylabel("People in room")
    ax_dp.set_ylim(0, max(list(rooms.values()) + list(noisy.values())) * 1.35 + 1)
    ax_dp.set_title("(b) Differential privacy on occupancy counts", fontsize=11)
    ax_dp.legend(frameon=False, fontsize=8, loc="upper left")

    # (c) k-anonymity
    buckets = ["1 (unique)", "2", f"{K}-4", "5+"]
    ax_k.bar([i - 0.2 for i in range(4)], before_sizes, 0.37, color=before_c,
             label="Original records")
    ax_k.bar([i + 0.2 for i in range(4)], after_sizes, 0.37, color=after_c,
             label=f"After generalisation + suppression (k={K})")
    ax_k.set_xticks(range(4))
    ax_k.set_xticklabels(buckets)
    ax_k.set_xlabel("Size of the group a record hides in")
    ax_k.set_ylabel("Number of records")
    ax_k.set_title("(c) k-anonymity of door-access records", fontsize=11)
    ax_k.set_ylim(0, max(before_sizes + after_sizes) * 1.15)
    ax_k.legend(frameon=False, fontsize=8, loc="upper right")

    # (d) pseudonymisation table
    ax_tab.axis("off")
    table = ax_tab.table(cellText=pseudo_rows, colLabels=["Original id", "Shared pseudonym"],
                         loc="center", cellLoc="left", colLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.35)
    for (row, _col), cell in table.get_celld().items():
        cell.set_edgecolor(chart_style.GRID)
        if row == 0:
            cell.set_text_props(fontweight="bold", color=chart_style.INK)
    ax_tab.set_title("(d) Pseudonymisation (keyed HMAC-SHA256)", fontsize=11,
                     color=chart_style.INK)

    fig.suptitle("Privacy techniques - before vs after", fontsize=14, color=chart_style.INK)
    return chart_style.save(fig, path)


def _size_buckets(records, quasi_ids=QUASI_IDENTIFIERS):
    """Count records by the size of the group they belong to: 1, 2, 3-4, 5+."""
    classes = equivalence_classes(records, quasi_ids)
    counts = [0, 0, 0, 0]
    for r in records:
        size = classes[tuple(r[q] for q in quasi_ids)]
        counts[0 if size == 1 else 1 if size == 2 else 2 if size <= 4 else 3] += 1
    return counts


# ====================================================================== run everything
def run(out_dir, db=None, rng=None):
    """Apply all four techniques, save the graph (and export if db given). Returns a summary."""
    os.makedirs(out_dir, exist_ok=True)
    rng = rng or random.SystemRandom()              # unpredictable noise for real DP
    key = new_key()                                  # pseudonymisation secret

    ids = [d[0] for d in DEVICES]
    pseudo = [pseudonym(i, key) for i in ids]
    unkeyed = ["anon-" + hashlib.sha256(i.encode()).hexdigest()[:10] for i in ids]

    energy = synthetic_energy_day()
    hourly = aggregate(energy, 4)

    rooms = synthetic_room_counts()
    noisy = {room: dp_count(count, EPSILON, rng) for room, count in rooms.items()}

    people = synthetic_access_log()
    kept, suppressed = k_anonymise(people)

    plot(energy, hourly, rooms, noisy, _size_buckets(people), _size_buckets(kept),
         list(zip(ids, pseudo)), os.path.join(out_dir, "privacy_before_after.png"))
    if db is not None:
        export_analytics(db, key, os.path.join(out_dir, "analytics_export.csv"))

    return {
        "pseudonyms_reidentified_keyed": dictionary_attack(pseudo, ids),
        "pseudonyms_reidentified_unkeyed": dictionary_attack(unkeyed, ids),
        "devices": len(ids),
        "energy_points_before": len(energy), "energy_points_after": len(hourly),
        "energy_total_kwh_before": round(sum(energy) / 4 / 1000, 3),
        "energy_total_kwh_after": round(sum(hourly) / 1000, 3),
        "energy_max_before": round(max(energy)), "energy_max_after": round(max(hourly)),
        "dp_mean_abs_error": round(sum(abs(noisy[r] - rooms[r]) for r in rooms) / len(rooms), 2),
        "dp_total_true": sum(rooms.values()), "dp_total_noisy": sum(noisy.values()),
        "k_before": smallest_group(people), "k_after": smallest_group(kept),
        "unique_before": _size_buckets(people)[0], "records": len(people),
        "suppressed": suppressed,
    }


if __name__ == "__main__":
    from config import RESULTS_DIR
    for name, value in run(RESULTS_DIR).items():
        print(f"{name}: {value}")
