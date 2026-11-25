"""
module2_crypto/benchmark.py - Compare two authenticated ciphers: speed and size.

    AES-256-GCM        uses the CPU's AES hardware instructions (AES-NI) if present
    ChaCha20-Poly1305  pure software, designed to be fast WITHOUT AES hardware
                       (that is why many small IoT chips and phones prefer it)

For each payload size we measure encrypt+decrypt throughput, and the size of
what goes on the wire (nonce + ciphertext + tag).

    python -m module2_crypto.benchmark
Outputs: results/cipher_benchmark.csv and results/cipher_benchmark.png
"""

import csv
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from core import chart_style
from module2_crypto.keygen import new_key, new_nonce

SIZES = [64, 256, 1024, 4096, 16384, 65536]          # bytes; 64-256 = typical sensor message
CIPHERS = [("AES-256-GCM", AESGCM), ("ChaCha20-Poly1305", ChaCha20Poly1305)]
SECONDS_PER_TEST = 0.25


def measure(cipher_class, size, seconds=SECONDS_PER_TEST):
    """Encrypt+decrypt random data of one size repeatedly. Returns (MB/s, microseconds per op, wire bytes)."""
    aead = cipher_class(new_key())
    data = os.urandom(size)
    nonce = new_nonce()
    wire_bytes = len(nonce) + len(aead.encrypt(nonce, data, None))
    ops = 0
    start = time.perf_counter()
    while time.perf_counter() - start < seconds:
        nonce = new_nonce()
        aead.decrypt(nonce, aead.encrypt(nonce, data, None), None)
        ops += 1
    elapsed = time.perf_counter() - start
    mb_per_s = ops * size / elapsed / 1e6
    return mb_per_s, elapsed / ops * 1e6, wire_bytes


def run_benchmark():
    """Measure every cipher at every size. Returns a list of result rows."""
    rows = []
    for name, cls in CIPHERS:
        measure(cls, 1024, 0.05)                      # warm-up run, not recorded
        for size in SIZES:
            mbps, micros, wire = measure(cls, size)
            rows.append({"cipher": name, "payload_bytes": size,
                         "throughput_MBps": round(mbps, 2), "us_per_op": round(micros, 2),
                         "wire_bytes": wire, "overhead_bytes": wire - size})
    return rows


def save_csv(rows, path):
    """Write benchmark rows to CSV."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot(rows, path):
    """Two panels: throughput vs payload size, and bytes on the wire per message."""
    fig, (ax_speed, ax_size) = chart_style.new_figure(ncols=2, width=6.2, height=4.2)
    width = 0.38
    for i, (name, _) in enumerate(CIPHERS):
        mine = [r for r in rows if r["cipher"] == name]
        colour = chart_style.SERIES[i]
        ax_speed.plot([r["payload_bytes"] for r in mine], [r["throughput_MBps"] for r in mine],
                      marker="o", markersize=6, linewidth=2, color=colour, label=name)
        small = [r for r in mine if r["payload_bytes"] <= 1024]
        positions = [j + (i - 0.5) * width for j in range(len(small))]
        bars = ax_size.bar(positions, [r["wire_bytes"] for r in small], width * 0.92,
                           color=colour, label=name)
        for bar, r in zip(bars, small):
            ax_size.annotate(f"+{r['overhead_bytes']}", (bar.get_x() + bar.get_width() / 2,
                             bar.get_height()), ha="center", va="bottom", fontsize=8,
                             color=chart_style.INK_SECONDARY, xytext=(0, 2),
                             textcoords="offset points")

    ax_speed.set_xscale("log", base=2)
    ax_speed.set_xticks(SIZES)
    ax_speed.set_xticklabels([f"{s // 1024} KB" if s >= 1024 else f"{s} B" for s in SIZES])
    ax_speed.set_xlabel("Payload size")
    ax_speed.set_ylabel("Encrypt + decrypt throughput (MB/s)")
    ax_speed.set_title("Speed (higher is better)", fontsize=11)
    ax_speed.legend(frameon=False, fontsize=9)

    small_sizes = [s for s in SIZES if s <= 1024]
    ax_size.set_xticks(range(len(small_sizes)))
    ax_size.set_xticklabels([f"{s} B" for s in small_sizes])
    ax_size.set_xlabel("Plaintext size")
    ax_size.set_ylabel("Bytes on the wire (nonce + ciphertext + tag)")
    ax_size.set_title("Message size (labels = overhead bytes)", fontsize=11)
    ax_size.legend(frameon=False, fontsize=9)
    fig.suptitle("AES-256-GCM vs ChaCha20-Poly1305", fontsize=13, color=chart_style.INK)
    return chart_style.save(fig, path)


def main(out_dir):
    """Run the benchmark and save CSV + PNG into out_dir. Returns the rows."""
    os.makedirs(out_dir, exist_ok=True)
    rows = run_benchmark()
    save_csv(rows, os.path.join(out_dir, "cipher_benchmark.csv"))
    plot(rows, os.path.join(out_dir, "cipher_benchmark.png"))
    return rows


def print_summary(rows):
    """Print a short comparison table."""
    print(f"  {'cipher':<19} {'payload':>8} {'MB/s':>9} {'us/op':>8} {'wire bytes':>11}")
    for r in rows:
        print(f"  {r['cipher']:<19} {r['payload_bytes']:>8} {r['throughput_MBps']:>9} "
              f"{r['us_per_op']:>8} {r['wire_bytes']:>11}")


if __name__ == "__main__":
    from config import RESULTS_DIR
    print_summary(main(RESULTS_DIR))
