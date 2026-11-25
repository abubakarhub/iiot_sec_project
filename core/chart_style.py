"""
core/chart_style.py - One shared look for every graph in the project.

Colours come from a colour-blind-checked palette (slot 1 = blue, slot 2 =
orange), always assigned in the same order. Thin marks, light grid, text in
neutral ink colours (never in the series colour).
"""

import matplotlib
matplotlib.use("Agg")                    # save to files, never open a window
import matplotlib.pyplot as plt          # noqa: E402

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]   # blue, orange, aqua, yellow
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e4e3df"


def new_figure(ncols=1, width=6.5, height=4.2):
    """Create a figure with ncols side-by-side axes, already styled."""
    fig, axes = plt.subplots(1, ncols, figsize=(width * ncols, height))
    fig.patch.set_facecolor(SURFACE)
    axes_list = axes if ncols > 1 else [axes]
    for ax in axes_list:
        style_axes(ax)
    return fig, axes


def style_axes(ax):
    """Apply the shared style to one axes: recessive grid, no top/right frame."""
    ax.set_facecolor(SURFACE)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(INK_SECONDARY)
    ax.tick_params(colors=INK_SECONDARY, labelsize=9)
    ax.title.set_color(INK)
    ax.xaxis.label.set_color(INK_SECONDARY)
    ax.yaxis.label.set_color(INK_SECONDARY)


def save(fig, path):
    """Save a figure as PNG and free its memory."""
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    return path
