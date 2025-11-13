# AUTOMA mini project (simple version)

# 1. Small MITRE ATT&CK-like knowledge base
ATTACK_KB = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "related_to": ["T1059.001", "T1047"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "related_to": ["T1059", "T1041"],
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "related_to": ["T1059", "T1027"],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "related_to": ["T1041"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "related_to": [],
    },
}

# 2. Fake system event
event = {
    "id": "E001",
    "description": "Suspicious PowerShell command executed",
    "related_technique": "T1059.001"
}

# 3. Generate possible attack paths (very simple)

def generate_paths(start_id, depth=3):
    paths = []

    def dfs(current, path, depth_left):
        path.append(current)
        if depth_left == 0 or not ATTACK_KB[current]["related_to"]:
            paths.append(path.copy())
            return
        for next_t in ATTACK_KB[current]["related_to"]:
            dfs(next_t, path, depth_left - 1)
            path.pop()

    dfs(start_id, [], depth)
    return paths

# 4. Score each path

def score_path(path):
    score = len(path) * 10
    if "T1041" in path:  # data exfiltration technique
        score += 30
    return score

# 5. Run and display top hypotheses

paths = generate_paths(event["related_technique"], depth=3)

scored_paths = []
for p in paths:
    s = score_path(p)
    scored_paths.append({"path": p, "score": s})

# Sort by score (descending)
scored_paths.sort(key=lambda x: x["score"], reverse=True)

# Show top 3
print("Input event:", event["description"])
print("\nTop 3 hypotheses:")
for i, hp in enumerate(scored_paths[:3], 1):
    print(f"\n{i}. Path: {' -> '.join(hp['path'])}")
    print(f"   Score: {hp['score']}")
