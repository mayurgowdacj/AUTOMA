# kb_loader.py
"""
Simple loader for MITRE ATT&CK Enterprise technique list.
Downloads the enterprise-attack JSON (MITRE CTI repo) and extracts a mapping:
  technique_id -> { "name": ..., "description": ..., "tactics": [...] }

This is a lightweight parser: it looks for STIX objects of type 'attack-pattern'
and extracts the external_id (e.g. "T1059") and name & kill_chain_phases.
"""

import requests
import json
from typing import Dict, Any

MITRE_ENTERPRISE_JSON = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# Note: older references use raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json.
# The attack-stix-data repo is the recommended place to fetch STIX collections. See MITRE ATT&CK docs. :contentReference[oaicite:1]{index=1}

def download_attack_json(url: str = MITRE_ENTERPRISE_JSON, save_path: str | None = None) -> Dict[str, Any]:
    print(f"Downloading ATT&CK data from: {url}")
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    if save_path:
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    return data

def build_technique_kb(stix_collection: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Parse the STIX collection JSON and return a map:
      { "T1059": {"name": "Command and Scripting Interpreter", "description": "...", "tactics": ["execution", ...]} }
    """
    kb = {}
    for item in stix_collection.get("objects", []):
        if item.get("type") == "attack-pattern":
            # External id (like "T1059") is usually under external_references
            ext_refs = item.get("external_references", []) or []
            technique_id = None
            for er in ext_refs:
                if er.get("source_name") == "mitre-attack" and er.get("external_id"):
                    technique_id = er.get("external_id")
                    break
            if not technique_id:
                # fallback: sometimes the 'id' contains it or use name (less reliable)
                continue

            name = item.get("name", "")
            descr = item.get("description", "") or ""
            tactics = []
            for kcp in item.get("kill_chain_phases", []) or []:
                phase = kcp.get("phase_name")
                if phase:
                    tactics.append(phase)
            kb[technique_id] = {"name": name, "description": descr, "tactics": tactics}
    return kb

def save_kb(kb: Dict[str, Dict[str, Any]], path: str = "attack_kb_simple.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=2, ensure_ascii=False)
    print(f"KB saved to {path} ({len(kb)} techniques)")

if __name__ == "__main__":
    stix = download_attack_json()
    kb = build_technique_kb(stix)
    save_kb(kb)
