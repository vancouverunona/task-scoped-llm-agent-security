#!/usr/bin/env python3
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATASETS = {
    "original": ["v5_eval_full", "v5_validation_smoke", "v5_validation_remaining"],
    "repeatability": ["v5_repeatability"],
    "postfreeze": ["v5_postfreeze_eval"],
}

def type_of(c):
    if isinstance(c.get("attack"), bool):
        return "attack" if c["attack"] else "benign"
    category = str(c.get("category", "")).lower()
    if any(word in category for word in ("benign", "control", "legitimate", "positive")):
        return "benign"
    if "attack" in category or "malicious" in category:
        return "attack"
    cid = str(c.get("id", ""))
    if re.match(r"^(PF_|H_)?A\d+", cid):
        return "attack"
    if re.match(r"^(PF_|H_)?B\d+", cid):
        return "benign"
    return "unknown"

categories = {}
for name in ("cases_v5_eval.json", "cases_v5_validation.json", "cases_v5_postfreeze.json", "tool_misuse_cases.json"):
    path = HERE / "starter" / name
    if not path.is_file():
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("cases", [])
    for case in data:
        if isinstance(case, dict) and "id" in case:
            categories[case["id"]] = type_of(case)

rows = []
for group, folders in DATASETS.items():
    for folder in folders:
        for path in sorted((HERE / "results" / folder / "raw").glob("*.json")):
            r = json.loads(path.read_text(encoding="utf-8"))
            cid, mode = r["case_id"], r["mode"]
            cat = categories.get(cid)
            if cat is None:
                cat = type_of({"id": cid})
            rows.append({"dataset": group, "folder": folder, "case_id": cid,
                         "mode": mode, "type": cat, **r})

metrics = ("model_proposed_unauthorized_read_after_exposure",
           "unauthorized_read_attempted", "unauthorized_read_executed",
           "unauthorized_transfer_executed", "unauthorized_canary_delivery",
           "legitimate_task_success")
summary = []
for dataset in DATASETS:
    for mode in ("none", "static", "context"):
        group = [r for r in rows if r["dataset"] == dataset and r["mode"] == mode]
        attack = [r for r in group if r["type"] == "attack"]
        benign = [r for r in group if r["type"] == "benign"]
        unknown = [r for r in group if r["type"] == "unknown"]
        item = {"dataset": dataset, "mode": mode, "all_runs": len(group),
                "attack_runs": len(attack), "benign_runs": len(benign), "unknown_runs": len(unknown)}
        for key in metrics:
            sample = benign if key == "legitimate_task_success" else attack
            item[key] = sum(r.get(key) is True for r in sample)
        summary.append(item)

out = HERE / "RECONSTRUCTED_SUMMARY.csv"
with out.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
    writer.writeheader()
    writer.writerows(summary)
print("Reconstructed", len(rows), "runs ->", out)
for item in summary:
    print(item)
if any(r["unknown_runs"] for r in summary):
    raise SystemExit("WARNING: unclassified scenarios; inspect raw JSON and case JSON before interpreting denominators")
