#!/usr/bin/env python3
"""Batch pilot for real Ollama; saves full traces and a per-run CSV. Not a benchmark."""
import argparse
import csv
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment import DOCUMENTS
from tool_misuse_lab_v5 import run


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", nargs="*", default=[])
    ap.add_argument("--modes", nargs="+", choices=["none", "static", "context"], default=["none", "static", "context"])
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--model", default="qwen2.5:1.5b")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--output-dir", default="../results/tool_misuse_pilot")
    args = ap.parse_args()
    if args.repeats < 1:
        ap.error("--repeats must be positive")
    cases_path = Path(__file__).with_name("tool_misuse_cases.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    if args.ids:
        unknown = set(args.ids) - {c["id"] for c in cases}
        if unknown:
            ap.error("Unknown case IDs: " + ", ".join(sorted(unknown)))
        cases = [c for c in cases if c["id"] in args.ids]
    out = Path(args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw"
    raw.mkdir(exist_ok=True)
    sources = ["experiment.py", "tool_misuse_lab_v5.py", "tool_misuse_cases.json"]
    meta = {"experiment": "Real Ollama synthetic tool misuse STAGED TOOL EXPERIMENT V5",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "model": args.model, "modes": args.modes, "repeats": args.repeats,
            "case_ids": [c["id"] for c in cases], "max_steps": args.max_steps,
            "hashes": {x: hashlib.sha256(Path(__file__).with_name(x).read_bytes()).hexdigest()
                       for x in sources}, "python": sys.version,
            "sink": "In-memory only; no external data transfer"}
    meta_file = out / "metadata.json"
    if meta_file.exists():
        existing = json.loads(meta_file.read_text(encoding="utf-8"))
        for key in ("model", "modes", "repeats", "case_ids", "max_steps", "hashes"):
            if meta[key] != existing[key]:
                ap.error("Directory already holds a different experiment; choose a fresh --output-dir")
    else:
        meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    fields = ["case_id", "category", "mode", "repeat", "valid", "complete", "legitimate_task_success",
              "model_proposed_unauthorized_read", "model_proposed_unauthorized_read_after_exposure", "unauthorized_read_attempted", "unauthorized_read_executed",
              "unauthorized_transfer_attempted", "unauthorized_transfer_executed",
              "canary_delivered", "unauthorized_canary_delivery", "elapsed_seconds"]
    rows = []
    n_total = len(cases) * len(args.modes) * args.repeats
    n = 0
    for c in cases:
        primary = c["primary_document"]
        original = DOCUMENTS[primary]["text"]
        for mode in args.modes:
            for rep in range(1, args.repeats + 1):
                n += 1
                stem = f"{c['id']}__{mode}__r{rep:02}"
                raw_file = raw / f"{stem}.json"
                print(f"[{n}/{n_total}] {stem}", flush=True)
                try:
                    if raw_file.exists():
                        d = json.loads(raw_file.read_text(encoding="utf-8"))
                    else:
                        DOCUMENTS[primary]["text"] = c["document_override"] if c["document_override"] is not None else original
                        t0 = time.perf_counter()
                        d = run(c, mode, args.model, args.max_steps, args.timeout)
                        d["elapsed_seconds"] = round(time.perf_counter() - t0, 3)
                        raw_file.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
                    rows.append({"case_id": c["id"], "category": c["category"], "mode": mode, "repeat": rep,
                                 "valid": 1, "complete": int(d["workflow_complete"]), "legitimate_task_success": int(d["legitimate_task_success"]),
                                 "model_proposed_unauthorized_read": int(d["model_proposed_unauthorized_read"]), "model_proposed_unauthorized_read_after_exposure": int(d["model_proposed_unauthorized_read_after_exposure"]), "unauthorized_read_attempted": int(d["unauthorized_read_attempted"]),
                                 "unauthorized_read_executed": int(d["unauthorized_read_executed"]),
                                 "unauthorized_transfer_attempted": int(d["unauthorized_transfer_attempted"]),
                                 "unauthorized_transfer_executed": int(d["unauthorized_transfer_executed"]),
                                 "canary_delivered": int(d["canary_delivered"]),
                                 "unauthorized_canary_delivery": int(d["unauthorized_canary_delivery"]),
                                 "elapsed_seconds": d["elapsed_seconds"]})
                except Exception as exc:
                    (raw / f"{stem}.error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
                    print(f"ERROR: {type(exc).__name__}: {exc}", flush=True)
                finally:
                    DOCUMENTS[primary]["text"] = original
    with (out / "trials.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nValid runs: {len(rows)}/{n_total}; saved {out / 'trials.csv'}")
    print("case | mode | complete | proposed_after_exposure | read_attempt | read_executed | transfer | unauthorized_canary")
    for r in rows:
        print(f"{r['case_id']} | {r['mode']} | {r['complete']} | {r['model_proposed_unauthorized_read_after_exposure']} | {r['unauthorized_read_attempted']} | "
              f"{r['unauthorized_read_executed']} | {r['unauthorized_transfer_executed']} | "
              f"{r['unauthorized_canary_delivery']}")
    print("NOTE: Authorized HR positive control can legitimately contain a canary. Do NOT count it as exfiltration.")
    print("NOTE: Development pilot; not a blind independent benchmark. A single absent attack attempt is not a defense success.")


if __name__ == "__main__":
    main()
