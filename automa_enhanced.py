# automa_enhanced.py
"""
Enhanced AUTOMA mini-project script (simple, local, no DB).
Requirements:
  pip install requests termcolor

Features:
  - Loads or downloads a small MITRE ATT&CK KB (attack_kb_simple.json)
  - Maps a textual event to candidate techniques by keyword matching
  - Expands simple paths using heuristics + small historical sequences
  - Scores hypotheses with (matching, success_prob, criticality) and ranks them
  - Prints colored top-3 and saves JSON output
"""

import json
import os
import re
from collections import defaultdict
from termcolor import colored

KB_PATH = "attack_kb_simple.json"

# ---------------------------
# Config / small historical sequences (toy examples)
# ---------------------------
HISTORICAL_SEQUENCES = [
    # sequences are lists of technique IDs observed together in past incidents (toy examples)
    ["T1059.001", "T1059", "T1041"],  # PowerShell => command => exfil
    ["T1059.001", "T1027", "T1041"],  # PowerShell -> obfuscation -> exfil
    ["T1047", "T1059", "T1027"],      # WMI -> command -> obfuscation
]

# Some simple technique impact weights for criticality (toy)
TECH_CRITICALITY = defaultdict(lambda: 10, {
    "T1041": 90,    # exfiltration very critical
    "T1059": 40,    # command interpreter
    "T1059.001": 30,
    "T1027": 50,
    "T1047": 35,
})

# ---------------------------
# Helpers to load KB
# ---------------------------
def load_kb(path=KB_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"KB file not found: {path}. Run kb_loader.py to create it.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# ---------------------------
# Simple event -> technique mapping via keyword matching
# ---------------------------
def build_keyword_index(kb):
    """
    Build a map: keyword -> set(technique_ids)
    Uses technique name tokens (split on non-alphanumeric chars).
    """
    idx = defaultdict(set)
    for tid, meta in kb.items():
        name = meta.get("name", "")
        tokens = re.findall(r"[A-Za-z0-9]+", name.lower())
        for t in tokens:
            if len(t) >= 3:  # skip tiny tokens
                idx[t].add(tid)
    return idx

def map_event_to_techniques(event_text, keyword_index, kb, top_n=10):
    """
    Given event_text, find candidate techniques by counting keyword matches.
    Returns top_n technique IDs sorted by match count.
    """
    tokens = re.findall(r"[A-Za-z0-9]+", event_text.lower())
    score = defaultdict(int)
    for tk in tokens:
        if tk in keyword_index:
            for tid in keyword_index[tk]:
                score[tid] += 1
    # Also try matching substrings (e.g., "powershell")
    for tid, meta in kb.items():
        name = meta.get("name", "").lower()
        for tk in tokens:
            if tk in name:
                score[tid] += 1
    # return top N
    ranked = sorted(score.items(), key=lambda x: x[1], reverse=True)
    return [t for t, s in ranked[:top_n]]

# ---------------------------
# Path expansion heuristics
# ---------------------------
def expand_paths(seed_techniques, kb, max_depth=3):
    """
    Build candidate paths:
      - include historical sequences that start with any seed
      - expand by tactics: if two techniques share a tactic, allow a transition
      - up to max_depth
    Returns set of unique paths (lists)
    """
    paths = set()

    # 1) historical sequences that involve seed techniques
    for seq in HISTORICAL_SEQUENCES:
        for s in seed_techniques:
            if s in seq:
                # include a truncated subsequence that begins at first occurrence of s
                idx = seq.index(s)
                p = seq[idx: idx + max_depth]
                paths.add(tuple(p))

    # 2) tactic-sharing expansion
    # build tactic -> techniques mapping
    tactic_map = defaultdict(list)
    for tid, meta in kb.items():
        for tct in meta.get("tactics", []):
            tactic_map[tct].append(tid)

    # BFS-style expansion from each seed
    for seed in seed_techniques:
        frontier = [[seed]]
        while frontier:
            path = frontier.pop(0)
            if len(path) >= max_depth:
                paths.add(tuple(path))
                continue
            last = path[-1]
            # neighbors: those in same tactics as 'last'
            neighbors = set()
            for tct in kb.get(last, {}).get("tactics", []):
                neighbors.update(tactic_map.get(tct, []))
            # also include techniques that appeared next to 'last' in historical sequences
            for seq in HISTORICAL_SEQUENCES:
                for i, t in enumerate(seq[:-1]):
                    if t == last:
                        neighbors.add(seq[i+1])
            neighbors = list(neighbors)[:10]
            for n in neighbors:
                if n not in path:  # avoid cycles
                    newp = path + [n]
                    frontier.append(newp)
                    paths.add(tuple(newp))

    # return as list-of-lists
    return [list(p) for p in paths]
    print(f"Generated {len(paths)} candidate paths")

# ---------------------------
# Scoring
# ---------------------------
def score_matching(path, seed_techniques):
    """
    Matching score: fraction of path elements that are in seed_techniques or
    appear in historical sequences with seeds (simple heuristics).
    Returns 0..1
    """
    if not path:
        return 0.0
    common = sum(1 for t in path if t in seed_techniques)
    return common / len(path)

def score_success(path):
    """
    Heuristic success probability:
      - Longer paths are somewhat more likely
      - Presence of obfuscation or command techniques improves prob
    Returns 0..1
    """
    base = min(0.2 + 0.15 * len(path), 0.9)
    if any(t.startswith("T1059") for t in path):
        base += 0.05
    if any(t == "T1027" for t in path):
        base += 0.05
    return min(base, 1.0)

def score_criticality(path):
    """
    Combine technique criticalities (max-normalized).
    Returns 0..1
    """
    if not path:
        return 0.0
    vals = [TECH_CRITICALITY.get(t, 10) for t in path]
    maxv = max(vals)
    # normalize by 100 (since we used 0..100 weights)
    return maxv / 100.0

def combined_score(path, seed_techniques, weights=(0.4, 0.3, 0.3)):
    m = score_matching(path, seed_techniques)
    s = score_success(path)
    c = score_criticality(path)
    w1, w2, w3 = weights
    overall = w1 * m + w2 * s + w3 * c
    return {"matching": m, "success": s, "criticality": c, "overall": overall}

# ---------------------------
# Main runner
# ---------------------------
def run(event_text, kb, top_k=3):
    print(colored("Event:", "cyan"), event_text)
    # build index
    idx = build_keyword_index(kb)
    mapped = map_event_to_techniques(event_text, idx, kb, top_n=12)
    if not mapped:
        print(colored("No candidate techniques found for event (try broader event description).", "red"))
        return

    print(colored("Mapped techniques (candidates):", "cyan"), mapped)
    # build candidate paths
    paths = expand_paths(mapped, kb, max_depth=4)
    if not paths:
        print("No paths were generated.")
        return

    # score each
    scored = []
    for p in paths:
        sc = combined_score(p, set(mapped))
        scored.append({"path": p, "scores": sc})
    scored.sort(key=lambda x: x["scores"]["overall"], reverse=True)

    # show top K
    print("\n" + colored(f"Top {top_k} hypotheses:", "green"))
    for i, item in enumerate(scored[:top_k], 1):
        p = item["path"]
        sc = item["scores"]
        summary = f"{i}. {' -> '.join(p)}"
        print(colored(summary, "yellow"))
        print(f"   overall={sc['overall']:.3f} (matching={sc['matching']:.2f}, success={sc['success']:.2f}, criticality={sc['criticality']:.2f})")
        # show technique names
        for tid in p:
            name = kb.get(tid, {}).get("name", "<unknown>")
            print(f"      - {tid}: {name}")
        print("")

    # save output
    out = {
        "event": event_text,
        "mapped": mapped,
        "hypotheses": scored[:top_k]
    }
    with open("automa_output.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(colored("Results saved to automa_output.json", "cyan"))

# ---------------------------
# Example usage when run as script
# ---------------------------
if __name__ == "__main__":
    # Accept a simple event input or use default
    import sys
    if len(sys.argv) > 1:
        ev = " ".join(sys.argv[1:])
    else:
        ev = "Suspicious PowerShell command that downloaded a file and set up a C2 channel"

    kb = load_kb()
    run(ev, kb, top_k=3)
