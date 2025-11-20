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
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AUTOMA — Cyber Threat Analysis</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
            animation: slideDown 0.6s ease-out;
        }

        header h1 {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            animation: fadeIn 0.6s ease-out;
        }

        .card h2 {
            font-size: 1.3em;
            color: #333;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .icon {
            font-size: 1.5em;
        }

        .form-group {
            margin-bottom: 18px;
        }

        label {
            display: block;
            font-weight: 600;
            color: #444;
            margin-bottom: 8px;
            font-size: 0.95em;
        }

        textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.95em;
            resize: vertical;
            transition: all 0.3s ease;
        }

        textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .input-row {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
        }

        input[type="number"] {
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 0.9em;
            transition: all 0.3s ease;
        }

        input[type="number"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .weights-section {
            background: #f9f9f9;
            padding: 16px;
            border-radius: 8px;
            margin: 20px 0;
        }

        .weights-section label {
            margin-bottom: 12px;
        }

        .weight-inputs {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 10px;
        }

        .weight-inputs input {
            padding: 8px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 0.9em;
        }

        .button-group {
            display: flex;
            gap: 12px;
            margin-top: 24px;
        }

        button {
            flex: 1;
            padding: 12px 20px;
            font-size: 1em;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }

        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }

        .btn-secondary:hover {
            background: #f0f4ff;
        }

        .results-section {
            margin-top: 30px;
            animation: fadeIn 0.6s ease-out;
        }

        .results-card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }

        .results-card h3 {
            font-size: 1.2em;
            color: #333;
            margin-bottom: 15px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }

        .technique-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 20px;
        }

        .badge {
            display: inline-block;
            padding: 8px 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .hypotheses-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }

        .hypotheses-table th {
            background: #f5f5f5;
            padding: 14px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #667eea;
            font-size: 0.9em;
        }

        .hypotheses-table td {
            padding: 14px;
            border-bottom: 1px solid #eee;
            font-size: 0.9em;
        }

        .hypotheses-table tr:hover {
            background: #f9f9f9;
        }

        .path-code {
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 8px 12px;
            border-radius: 6px;
            color: #667eea;
            font-weight: 600;
        }

        .score {
            font-weight: 600;
            color: #667eea;
        }

        .details-row {
            background: #fafafa;
        }

        .details-row ul {
            list-style: none;
            padding: 0;
        }

        .details-row li {
            padding: 6px 0;
            color: #555;
            font-size: 0.9em;
        }

        .details-row code {
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 4px;
            color: #667eea;
            font-weight: 600;
        }

        .no-data {
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }

            .input-row {
                grid-template-columns: 1fr;
            }

            .weight-inputs {
                grid-template-columns: 1fr;
            }

            header h1 {
                font-size: 1.8em;
            }

            .button-group {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ AUTOMA</h1>
            <p>Intelligent Cyber Threat Analysis & Mapping</p>
        </header>

        <div class="main-content">
            <!-- Input Panel -->
            <div class="card">
                <h2><span class="icon"></span> Threat Event</h2>
                <form method="post" action="/">
                    <div class="form-group">
                        <label for="event_text">Describe the security event:</label>
                        <textarea id="event_text" name="event_text" placeholder="e.g., Suspicious PowerShell command that downloaded a file and set up a C2 channel" rows="6">{{ event_text }}</textarea>
                    </div>

                    <h2 style="font-size: 1.1em; margin-top: 24px;"><span class="icon">⚙️</span> Configuration</h2>

                    <div class="input-row">
                        <div class="form-group">
                            <label for="top_k">Top K Results</label>
                            <input type="number" id="top_k" name="top_k" value="{{ top_k }}" min="1" max="10">
                        </div>
                        <div class="form-group">
                            <label for="neighbor_cap">Neighbor Cap</label>
                            <input type="number" id="neighbor_cap" name="neighbor_cap" value="{{ neighbor_cap }}" min="1" max="50">
                        </div>
                        <div class="form-group">
                            <label for="global_path_cap">Path Cap</label>
                            <input type="number" id="global_path_cap" name="global_path_cap" value="{{ global_path_cap }}" min="10" max="5000">
                        </div>
                    </div>

                    <div class="weights-section">
                        <label>Scoring Weights (must sum to 1.0)</label>
                        <div class="weight-inputs">
                            <div>
                                <label style="font-size: 0.85em; margin-bottom: 6px;">Matching</label>
                                <input type="number" name="w1" value="{{ w1 }}" step="0.1" min="0" max="1">
                            </div>
                            <div>
                                <label style="font-size: 0.85em; margin-bottom: 6px;">Success</label>
                                <input type="number" name="w2" value="{{ w2 }}" step="0.1" min="0" max="1">
                            </div>
                            <div>
                                <label style="font-size: 0.85em; margin-bottom: 6px;">Criticality</label>
                                <input type="number" name="w3" value="{{ w3 }}" step="0.1" min="0" max="1">
                            </div>
                        </div>
                    </div>

                    <div class="button-group">
                        <button type="submit" class="btn-primary">🚀 Analyze</button>
                        <a href="/download" class="btn-secondary" style="text-decoration: none; display: flex; align-items: center; justify-content: center;">⬇Download JSON</a>
                    </div>
                </form>
            </div>

            <!-- Info Panel -->
            <div class="card">
                <h2><span class="icon"></span> About AUTOMA</h2>
                <p style="color: #666; line-height: 1.6; margin-bottom: 16px;">
                    AUTOMA uses advanced threat mapping to analyze security events and identify potential attack chains using MITRE ATT&CK techniques.
                </p>
                <div style="background: #f0f4ff; padding: 14px; border-radius: 8px; margin-bottom: 16px;">
                    <strong style="color: #667eea;">How it works:</strong>
                    <ul style="margin-top: 8px; margin-left: 16px; color: #555; font-size: 0.9em;">
                        <li>Analyzes your threat description</li>
                        <li>Maps to relevant MITRE ATT&CK techniques</li>
                        <li>Generates attack hypothesis chains</li>
                        <li>Scores by matching, success rate & criticality</li>
                    </ul>
                </div>
                <p style="color: #999; font-size: 0.85em;">
                 <strong>Tip:</strong> Provide detailed descriptions for better analysis results. Include observables, behaviors, and context.
                </p>
            </div>
        </div>

        <!-- Results Section -->
        {% if mapped %}
        <div class="results-card">
            <h3> Mapped Techniques</h3>
            <div class="technique-badges">
                {% for t in mapped %}
                <span class="badge">{{ t }}</span>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        {% if hypotheses %}
        <div class="results-card">
            <h3> Top {{ top_k }} Attack Hypotheses</h3>
            <table class="hypotheses-table">
                <thead>
                    <tr>
                        <th style="width: 60px;">Rank</th>
                        <th>Attack Path</th>
                        <th style="width: 80px;">Overall</th>
                        <th style="width: 80px;">Match</th>
                        <th style="width: 80px;">Success</th>
                        <th style="width: 100px;">Criticality</th>
                    </tr>
                </thead>
                <tbody>
                    {% for h in hypotheses %}
                    <tr>
                        <td style="font-weight: 700; color: #667eea;">{{ loop.index }}</td>
                        <td><span class="path-code">{{ ' → '.join(h['path']) }}</span></td>
                        <td class="score">{{ '%.3f' % h['scores']['overall'] }}</td>
                        <td>{{ '%.2f' % h['scores']['matching'] }}</td>
                        <td>{{ '%.2f' % h['scores']['success'] }}</td>
                        <td>{{ '%.2f' % h['scores']['criticality'] }}</td>
                    </tr>
                    <tr class="details-row">
                        <td colspan="6" style="padding: 12px;">
                            <strong>Technique Details:</strong>
                            <ul>
                                {% for tid in h['path'] %}
                                <li><code>{{ tid }}</code>: {{ kb.get(tid, {}).get('name', '<unknown>') }}</li>
                                {% endfor %}
                            </ul>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        {% if not hypotheses and request.method == 'POST' %}
        <div class="results-card">
            <div class="no-data">
                <p style="font-size: 1.1em; margin-bottom: 10px;">No results found</p>
                <p>Try adjusting your parameters or providing more detail about the threat event.</p>
            </div>
        </div>
        {% endif %}
        {% endif %}
    </div>
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
    import os
    # run dev server
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    print(f"Starting AUTOMA Flask app on http://{host}:{port}")
    if HAVE_RAPIDFUZZ:
        print("RapidFuzz detected: using it for fuzzy matching.")
    else:
        print("RapidFuzz not found: using difflib fallback for fuzzy matching.")
    app.run(host=host, port=port, debug=False)