"""
module1_attacks/trees.py - Draws the attack tree and the fault tree as PNG images.

    python -m module1_attacks.trees      (also run automatically by main.py --mode insecure)

ATTACK TREE (security): how could an attacker reach the goal
    "Unlock door lock-01 without authorisation"?
FAULT TREE (safety/reliability): which failures, malicious or accidental,
    lead to the top event "Door access control fails"?

Both trees are written as nested Python tuples below, turned into a networkx
graph, laid out top-down by a small helper, and drawn with matplotlib.
Gates: OR = any child is enough, AND = all children are needed.
Leaves marked [A] are attacks we actually run in module1_attacks.
"""

import os
import textwrap

import matplotlib
matplotlib.use("Agg")                     # draw to files, no window needed
import matplotlib.pyplot as plt           # noqa: E402  (must come after matplotlib.use)
import networkx as nx                     # noqa: E402
from matplotlib.patches import Patch      # noqa: E402

# Each node is (label, kind, [children]). kind is one of:
#   "top"  - the goal / top event      "event" - intermediate event
#   "leaf" - basic event / attack step "demo"  - leaf we actually demonstrate [A]
#   "OR" / "AND" - gates
ATTACK_TREE = (
    "Unlock door lock-01\nwithout authorisation", "top", [
        ("OR", "OR", [
            ("Send a forged\nunlock command", "event", [
                ("OR", "OR", [
                    ("Call API with no /\nforged token [A]", "demo", []),
                    ("Publish straight to\nlock's /cmd topic [A]", "demo", []),
                ]),
            ]),
            ("Replay a captured\nunlock command", "event", [
                ("AND", "AND", [
                    ("Get on the network\npath (MITM relay)", "leaf", []),
                    ("Capture the unlock\nframe (sniffing) [A]", "demo", []),
                    ("Re-send it; no\nfreshness check [A]", "demo", []),
                ]),
            ]),
            ("Take over the\noperator account", "event", [
                ("OR", "OR", [
                    ("Brute-force weak\npassword [A]", "demo", []),
                    ("Steal password from\nplaintext DB", "leaf", []),
                ]),
            ]),
            ("Impersonate the\ncloud / gateway", "event", [
                ("AND", "AND", [
                    ("Claim a trusted id;\nno device auth [A]", "demo", []),
                    ("Lock accepts\nunsigned commands", "leaf", []),
                ]),
            ]),
        ]),
    ],
)

FAULT_TREE = (
    "Door access control fails\n(lock does not obey\ncorrect commands only)", "top", [
        ("OR", "OR", [
            ("Gateway / broker\nunavailable", "event", [
                ("OR", "OR", [
                    ("Message flood\n(DoS) [A]", "demo", []),
                    ("Broker process\ncrash", "leaf", []),
                    ("Network link\ndown", "leaf", []),
                ]),
            ]),
            ("Lock obeys a\nwrong command", "event", [
                ("OR", "OR", [
                    ("Tampered command\naccepted [A]", "demo", []),
                    ("Replayed command\naccepted [A]", "demo", []),
                    ("Forged command\naccepted [A]", "demo", []),
                ]),
            ]),
            ("Lock hardware\nfailure", "event", [
                ("AND", "AND", [
                    ("Battery\ndepleted", "leaf", []),
                    ("No low-battery\nalert sent", "leaf", []),
                ]),
            ]),
            ("Cloud cannot\nsend commands", "event", [
                ("OR", "OR", [
                    ("API overloaded\n[A]", "demo", []),
                    ("Database\ncorrupted", "leaf", []),
                    ("Valid key revoked\nby mistake", "leaf", []),
                ]),
            ]),
        ]),
    ],
)

COLOURS = {"top": "#f4b6b6", "event": "#fde7b0", "leaf": "#e8eef7", "demo": "#c9e7c3",
           "OR": "#ffffff", "AND": "#ffffff"}


def build_graph(tree):
    """Turn the nested tuple tree into a networkx DiGraph. Returns (graph, root_id)."""
    graph = nx.DiGraph()
    counter = [0]

    def add(node, parent):
        """Add one node (and its children, recursively) to the graph."""
        label, kind, children = node
        node_id = counter[0]
        counter[0] += 1
        graph.add_node(node_id, label=label, kind=kind)
        if parent is not None:
            graph.add_edge(parent, node_id)
        for child in children:
            add(child, node_id)
        return node_id

    return graph, add(tree, None)


def tree_layout(graph, root):
    """
    Simple top-down tree layout: leaves get evenly spaced x positions,
    every parent sits above the middle of its children, y = -depth.
    """
    pos = {}
    next_x = [0]

    def place(node, depth):
        """Place a node after placing all of its children."""
        children = list(graph.successors(node))
        if not children:
            x = next_x[0]
            next_x[0] += 1
        else:
            xs = [place(child, depth + 1) for child in children]
            x = sum(xs) / len(xs)
        pos[node] = (x, -depth)
        return x

    place(root, 0)
    return pos


def draw_tree(tree, title, path):
    """Draw one tree and save it as a PNG file."""
    graph, root = build_graph(tree)
    pos = tree_layout(graph, root)
    width = max(x for x, _ in pos.values()) + 1
    depth = -min(y for _, y in pos.values()) + 1

    fig, ax = plt.subplots(figsize=(max(10, width * 1.7), depth * 1.5 + 1))
    nx.draw_networkx_edges(graph, pos, ax=ax, arrows=False, edge_color="#555555", width=1.2)
    for node, (x, y) in pos.items():
        kind = graph.nodes[node]["kind"]
        label = graph.nodes[node]["label"]
        if kind in ("OR", "AND"):                     # gates: small round / square badge
            style = "circle,pad=0.35" if kind == "OR" else "square,pad=0.35"
            ax.text(x, y, kind, ha="center", va="center", fontsize=8, fontweight="bold",
                    bbox=dict(boxstyle=style, facecolor=COLOURS[kind], edgecolor="#333333"))
        else:
            text = "\n".join(textwrap.fill(line, 30) for line in label.split("\n"))
            ax.text(x, y, text, ha="center", va="center",
                    fontsize=9 if kind == "top" else 8,
                    fontweight="bold" if kind == "top" else "normal",
                    bbox=dict(boxstyle="round,pad=0.4", facecolor=COLOURS[kind],
                              edgecolor="#333333"))

    ax.legend(handles=[Patch(facecolor=COLOURS["top"], edgecolor="#333", label="Goal / top event"),
                       Patch(facecolor=COLOURS["event"], edgecolor="#333", label="Intermediate event"),
                       Patch(facecolor=COLOURS["leaf"], edgecolor="#333", label="Basic event"),
                       Patch(facecolor=COLOURS["demo"], edgecolor="#333",
                             label="[A] demonstrated by our attacks")],
              loc="lower center", bbox_to_anchor=(0.5, -0.08), ncol=4, fontsize=8, frameon=False)
    ax.set_title(title, fontsize=13, fontweight="bold")
    ax.set_xlim(-0.8, width - 0.2)
    ax.set_ylim(-depth + 0.4, 0.6)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def draw_all(out_dir):
    """Draw both trees into out_dir and return the two file paths."""
    os.makedirs(out_dir, exist_ok=True)
    return [
        draw_tree(ATTACK_TREE, "Attack tree - Smart Building door lock",
                  os.path.join(out_dir, "attack_tree.png")),
        draw_tree(FAULT_TREE, "Fault tree - Door access control failure",
                  os.path.join(out_dir, "fault_tree.png")),
    ]


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import RESULTS_DIR
    for saved in draw_all(RESULTS_DIR):
        print("saved", saved)
