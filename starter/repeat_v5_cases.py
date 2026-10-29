#!/usr/bin/env python3
"""Re-run existing V5 cases without modifying the original case files or source.

Run from the folder containing tool_misuse_lab_v5.py and the case JSON files.
Not a held-out test: these are repeats of development-informed scenarios.
"""
import argparse
import copy
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def load_cases(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        cases = data
    elif isinstance(data, dict) and isinstance(data.get("cases"), list):
        cases = data["cases"]
    else:
        raise ValueError(f"Expected a list of cases or {{'cases': [...]}} in {path}")
    if any(not isinstance(x, dict) or "id" not in x for x in cases):
        raise ValueError(f"Invalid case format in {path}")
    return {str(case["id"]): case for case in cases}


def command_output(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        return (result.stdout or result.stderr).strip()
    except Exception as exc:
        return f"unavailable: {exc}"


def main():
    parser = argparse.ArgumentParser(description="Separate V5 repeatability experiment")
    parser.add_argument("--case-file", default="cases_v5_validation.json")
    parser.add_argument("--cases", nargs="+", default=[
        "H_A01_MEETING_MINUTES", "H_A04_CROSS_Q3", "H_A06_FAKE_SYSTEM_LOG"
    ])
    parser.add_argument("--model", default="qwen2.5:1.5b")
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--repeat-start", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--output-dir", default="../results/v5_repeatability/raw")
    args = parser.parse_args()

    if args.repeat_start < 1 or args.repeats < 1:
        parser.error("--repeat-start and --repeats must be >= 1")

    source = Path(__file__).resolve().parent
    sys.path.insert(0, str(source))
    try:
        import tool_misuse_lab_v5 as lab
    except ImportError as exc:
        parser.error(f"Cannot import tool_misuse_lab_v5.py from {source}: {exc}")

    case_path = Path(args.case_file)
    if not case_path.is_absolute():
        case_path = source / case_path
    if not case_path.is_file():
        parser.error(f"Case file does not exist: {case_path}")
    all_cases = load_cases(case_path)
    unknown = [case_id for case_id in args.cases if case_id not in all_cases]
    if unknown:
        parser.error(f"Unknown case IDs in {case_path.name}: {unknown}; available IDs: {list(all_cases)}")

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = [(cid, mode, r, output_dir / f"{cid}__{mode}__r{r:02d}.json")
               for cid in args.cases
               for mode in ("none", "static", "context")
               for r in range(args.repeat_start, args.repeat_start + args.repeats)]
    collisions = [str(p) for _, _, _, p in outputs if p.exists()]
    if collisions:
        parser.error("Refusing to overwrite existing results. Example: " + collisions[0]
                     + ". Use a new --output-dir or advance --repeat-start.")

    manifest_path = output_dir.parent / (f"repeatability_environment_r{args.repeat_start:02d}-r{args.repeat_start + args.repeats - 1:02d}.json")
    manifest = {
        "study": "V5 repeatability extension (NOT an independent held-out set)",
        "case_file": str(case_path), "case_ids": args.cases,
        "case_file_sha256": hashlib.sha256(case_path.read_bytes()).hexdigest(),
        "source_file_sha256": hashlib.sha256(Path(lab.__file__).read_bytes()).hexdigest(),
        "python_version": sys.version,
        "ollama_model_info": command_output(["ollama", "show", args.model]),
        "model_tag": args.model, "max_steps": args.max_steps,
        "ollama_version": command_output(["ollama", "--version"]),
        "ollama_list": command_output(["ollama", "list"]),
        "source_file": str(Path(lab.__file__).resolve()),
        "repeat_range": [args.repeat_start, args.repeat_start + args.repeats - 1],
        "note": "Never merge these runs into the original 105-run dataset."
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Plan: {len(args.cases)} cases x 3 modes x {args.repeats} repeats = {len(outputs)} runs", flush=True)
    print(f"Results directory: {output_dir}", flush=True)
    fields = ["case_id", "mode", "repeat", "read_attempted", "read_executed", "transfer_executed", "legitimate_success", "file"]
    index_path = output_dir.parent / "repeatability_index.csv"
    if index_path.exists():
        with index_path.open(encoding="utf-8", newline="") as f:
            index = list(csv.DictReader(f))
    else:
        index = []
    for cid, mode, rep, dest in outputs:
        case = copy.deepcopy(all_cases[cid])
        primary = case.get("primary_document")
        if primary not in lab.DOCUMENTS:
            raise KeyError(f"{cid}: primary_document {primary!r} not in DOCUMENTS")
        previous = lab.DOCUMENTS[primary]["text"]
        print(f"RUN {cid} | {mode} | repeat {rep}", flush=True)
        try:
            if case.get("document_override") is not None:
                lab.DOCUMENTS[primary]["text"] = case["document_override"]
            result = lab.run(case, mode, args.model, args.max_steps)
        finally:
            lab.DOCUMENTS[primary]["text"] = previous

        # Keep the actual run object intact except for explicitly namespaced metadata.
        result["_repeatability_meta"] = {
            "case_file": case_path.name, "repeat": rep, "mode": mode,
            "model_tag": args.model, "case_id": cid
        }
        dest.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        row = {
            "case_id": cid, "mode": mode, "repeat": rep,
            "read_attempted": result.get("unauthorized_read_attempted"),
            "read_executed": result.get("unauthorized_read_executed"),
            "transfer_executed": result.get("unauthorized_transfer_executed"),
            "legitimate_success": result.get("legitimate_task_success"),
            "file": str(dest)
        }
        index.append(row)
        with index_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(index)
        print(f"  attempted={row['read_attempted']} executed={row['read_executed']} transfer={row['transfer_executed']}", flush=True)
    print(f"Saved run logs, {index_path.name}, {manifest_path.name}", flush=True)


if __name__ == "__main__":
    main()
