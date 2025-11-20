# app.py
"""
AUTOMA mini-project — Flask web app (single file)

Usage:
  - Make sure attack_kb_simple.json exists in same folder (run kb_loader.py earlier)
  - Install Flask: pip install flask requests
  - Optional: pip install rapidfuzz (better fuzzy matching). If not installed, difflib fallback used.
  - Run: python app.py
  - Open http://127.0.0.1:5000/ in your browser
"""

import json
import os
import re
from collections import defaultdict
from flask import Flask, render_template_string, request, send_file, redirect, url_for
from difflib import SequenceMatcher

# Try to use rapidfuzz if available (faster + better)
try:
    from rapidfuzz import fuzz
    HAVE_RAPIDFUZZ = True
except Exception:
    HAVE_RAPIDFUZZ = False

# --- Config & toy historical sequences / criticality (same as earlier) ---
KB_PATH = "attack_kb_simple.json"

HISTORICAL_SEQUENCES = [
    ["T1059.001", "T1059", "T1041"],
    ["T1059.001", "T1027", "T1041"],
    ["T1047", "T1059", "T1027"],
]
TECH_CRITICALITY = defaultdict(lambda: 10, {
    "T1041": 90,
    "T1059": 40,
    "T1059.001": 30,
    "T1027": 50,
    "T1047": 35,
})

# --- Flask app init ---
app = Flask(__name__)

# --- Utility: load KB ---
def load_kb(path=KB_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"KB file not found: {path}. Run kb_loader.py first.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# --- Improved matching helpers ---
def tokenize(text):
    return re.findall(r"[A-Za-z0-9]+", text.lower())

def build_keyword_index(kb):
    idx = defaultdict(set)
    names = {}
    for tid, meta in kb.items():
        name = meta.get("name", "")
        names[tid] = name
        tokens = tokenize(name)
        for t in tokens:
            if len(t) >= 3:
                idx[t].add(tid)
    return idx, names

def fuzzy_score(a, b):
    # returns 0..100 similarity
    if HAVE_RAPIDFUZZ:
        # token_set_ratio works well but we use simple ratio for short strings
        return fuzz.token_sort_ratio(a, b)
    else:
        # difflib ratio -> 0..1; scale to 0..100
        return int(SequenceMatcher(None, a, b).ratio() * 100)

def map_event_to_techniques_smart(event_text, kb, top_n=12):
    """
    Combined strategy:
      - token matching (counts)
      - substring match in technique names
      - fuzzy similarity on whole name
    Returns ranked list of candidate technique IDs (top_n)
    """
    idx, names = build_keyword_index(kb)
    tokens = tokenize(event_text)
    score = defaultdict(int)

    # token matches
    for tk in tokens:
        if tk in idx:
            for tid in idx[tk]:
                score[tid] += 3  # token match weight

    # substring matches and fuzzy matches
    for tid, name in names.items():
        lname = name.lower()
        for tk in tokens:
            if tk in lname:
                score[tid] += 2
        # fuzzy match between event_text and name
        sim = fuzzy_score(event_text.lower(), lname)
        if sim > 40:  # threshold
            # add scaled score
            score[tid] += int(sim / 25)  # e.g., 60 -> +2

    # build final ranked list
    ranked = sorted(score.items(), key=lambda x: x[1], reverse=True)
    return [t for t, s in ranked[:top_n]]

# --- Path expansion with caps ---
def expand_paths(seed_techniques, kb, max_depth=4, neighbor_cap=10, global_path_cap=500):
    paths = set()

    # historical sequences
    for seq in HISTORICAL_SEQUENCES:
        for s in seed_techniques:
            if s in seq:
                idx = seq.index(s)
                p = seq[idx: idx + max_depth]
                paths.add(tuple(p))

    # tactic mapping
    tactic_map = defaultdict(list)
    for tid, meta in kb.items():
        for tct in meta.get("tactics", []):
            tactic_map[tct].append(tid)

    # BFS expansion
    frontier_limit = 10000
    for seed in seed_techniques:
        frontier = [[seed]]
        while frontier:
            if len(paths) >= global_path_cap:
                break
            path = frontier.pop(0)
            if len(path) >= max_depth:
                paths.add(tuple(path))
                continue
            last = path[-1]
            neighbors = set()
            for tct in kb.get(last, {}).get("tactics", []):
                neighbors.update(tactic_map.get(tct, []))
            for seq in HISTORICAL_SEQUENCES:
                for i, t in enumerate(seq[:-1]):
                    if t == last:
                        neighbors.add(seq[i+1])

            neighbors = list(neighbors)[:neighbor_cap]

            for n in neighbors:
                if n not in path:
                    newp = path + [n]
                    frontier.append(newp)
                    paths.add(tuple(newp))

    # fallback if nothing
    if not paths:
        paths = set(tuple([t]) for t in seed_techniques)

    # return list-of-lists
    return [list(p) for p in paths]

# --- Scoring functions ---
def score_matching(path, seed_techniques):
    if not path: return 0.0
    common = sum(1 for t in path if t in seed_techniques)
    return common / len(path)

def score_success(path):
    base = min(0.2 + 0.12 * len(path), 0.95)
    if any(t.startswith("T1059") for t in path):
        base += 0.03
    if any(t == "T1027" for t in path):
        base += 0.03
    return min(base, 1.0)

def score_criticality(path):
    if not path: return 0.0
    vals = [TECH_CRITICALITY.get(t, 10) for t in path]
    return max(vals) / 100.0

def combined_score(path, seed_techniques, weights=(0.4,0.3,0.3)):
    m = score_matching(path, seed_techniques)
    s = score_success(path)
    c = score_criticality(path)
    w1,w2,w3 = weights
    overall = w1*m + w2*s + w3*c
    return {"matching": m, "success": s, "criticality": c, "overall": overall}

# --- Save output ---
def save_output(out, path="automa_output.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    return path

# --- Flask routes + templates ---
INDEX_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AUTOMA — Mini Web UI</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background:#f7f7fb; color:#222; }
    .box { background: white; padding: 16px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.07); }
    textarea { width:100%; height:100px; }
    .row { display:flex; gap:8px; align-items:center; margin-top:8px; }
    .small { width:100px; }
    table { border-collapse: collapse; width:100%; margin-top:12px; }
    th, td { padding:8px; border-bottom:1px solid #eee; text-align:left; }
    .path { font-family: monospace; }
    .badge { display:inline-block; padding:4px 8px; border-radius:6px; background:#eef; color:#114; }
    .download { margin-top:8px; display:inline-block; padding:6px 10px; background:#2b7cff; color:white; text-decoration:none;border-radius:6px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>AUTOMA — Mini Web UI</h2>
    <form method="post" action="/">
      <label>Event description</label><br/>
      <textarea name="event_text">{{ event_text }}</textarea>
      <div class="row">
        <label>Top K</label>
        <input class="small" type="number" name="top_k" value="{{ top_k }}" min="1" max="10"/>
        <label>Neighbor cap</label>
        <input class="small" type="number" name="neighbor_cap" value="{{ neighbor_cap }}" min="1" max="50"/>
        <label>Global path cap</label>
        <input class="small" type="number" name="global_path_cap" value="{{ global_path_cap }}" min="10" max="5000"/>
      </div>
      <div style="margin-top:8px;">
        <label>Weights (matching, success, criticality) — must sum to 1.0</label><br/>
        <input class="small" name="w1" value="{{ w1 }}"/> 
        <input class="small" name="w2" value="{{ w2 }}"/> 
        <input class="small" name="w3" value="{{ w3 }}"/>
      </div>
      <div style="margin-top:12px;">
        <button type="submit">Run</button>
        <a class="download" href="/download">Download last JSON</a>
      </div>
    </form>

    {% if mapped %}
      <h3>Mapped techniques (candidates)</h3>
      <div class="box">
        {% for t in mapped %}
          <span class="badge">{{ t }}</span>&nbsp;
        {% endfor %}
      </div>
    {% endif %}

    {% if hypotheses %}
      <h3>Top {{ top_k }} hypotheses</h3>
      <table>
        <thead><tr><th>Rank</th><th>Path</th><th>Overall</th><th>Matching</th><th>Success</th><th>Criticality</th></tr></thead>
        <tbody>
        {% for h in hypotheses %}
        <tr>
            <td>{{ loop.index }}</td>
            <td class="path">{{ ' → '.join(h['path']) }}</td>
            <td>{{ '%.3f' % h['scores']['overall'] }}</td>
            <td>{{ '%.2f' % h['scores']['matching'] }}</td>
            <td>{{ '%.2f' % h['scores']['success'] }}</td>
            <td>{{ '%.2f' % h['scores']['criticality'] }}</td>
        </tr>
        <tr>
            <td></td>
            <td colspan="5">
                <strong>Details:</strong>
                <ul>
                    {% for tid in h['path'] %}
                        <li><code>{{ tid }}</code>: {{ kb.get(tid, {}).get('name','<unknown>') }}</li>
                    {% endfor %}
                </ul>
            </td>
        </tr>
{% endfor %}

        </tbody>
      </table>
    {% endif %}

  </div>
  <p style="color:#666; font-size:12px;">Note: fuzzy matching uses RapidFuzz if installed; otherwise uses difflib.</p>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    kb = load_kb()
    event_text = "Suspicious PowerShell command that downloaded a file and set up a C2 channel"
    mapped = []
    hypotheses = []
    top_k = 3
    neighbor_cap = 10
    global_path_cap = 500
    w1, w2, w3 = 0.4, 0.3, 0.3

    if request.method == "POST":
        event_text = request.form.get("event_text", event_text)
        try:
            top_k = int(request.form.get("top_k", top_k))
        except:
            top_k = 3
        try:
            neighbor_cap = int(request.form.get("neighbor_cap", neighbor_cap))
            global_path_cap = int(request.form.get("global_path_cap", global_path_cap))
        except:
            neighbor_cap, global_path_cap = 10, 500
        try:
            w1 = float(request.form.get("w1", w1))
            w2 = float(request.form.get("w2", w2))
            w3 = float(request.form.get("w3", w3))
            # normalize if they don't sum to 1
            s = max(1e-9, (w1 + w2 + w3))
            w1, w2, w3 = w1/s, w2/s, w3/s
        except:
            w1, w2, w3 = 0.4,0.3,0.3

        mapped = map_event_to_techniques_smart(event_text, kb, top_n=20)
        paths = expand_paths(mapped, kb, max_depth=4, neighbor_cap=neighbor_cap, global_path_cap=global_path_cap)

        scored = []
        for p in paths:
            sc = combined_score(p, set(mapped), weights=(w1,w2,w3))
            scored.append({"path": p, "scores": sc})
        scored.sort(key=lambda x: x["scores"]["overall"], reverse=True)
        hypotheses = scored[:top_k]

        out = {"event": event_text, "mapped": mapped, "hypotheses": hypotheses}
        save_output(out, "automa_output.json")
    return render_template_string(INDEX_HTML,
                                  event_text=event_text,
                                  mapped=mapped,
                                  hypotheses=hypotheses,
                                  kb=kb,
                                  top_k=top_k,
                                  neighbor_cap=neighbor_cap,
                                  global_path_cap=global_path_cap,
                                  w1=w1, w2=w2, w3=w3)

@app.route("/download")
def download():
    p = "automa_output.json"
    if not os.path.exists(p):
        # redirect to main with a message? simple redirect
        return redirect(url_for("index"))
    return send_file(p, as_attachment=True)

if __name__ == "__main__":
    # run dev server
    print("Starting AUTOMA Flask app on http://127.0.0.1:5000")
    if HAVE_RAPIDFUZZ:
        print("RapidFuzz detected: using it for fuzzy matching.")
    else:
        print("RapidFuzz not found: using difflib fallback for fuzzy matching.")
    app.run(debug=True)
