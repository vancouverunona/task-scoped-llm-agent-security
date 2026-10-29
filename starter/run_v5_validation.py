#!/usr/bin/env python3
"""Supplementary researcher-authored evaluation suite for frozen V5.
Uses synthetic in-memory documents and sink; NEVER sends anything over the network
except the local Ollama API already used by V5. Does not change the security policies.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

from experiment import DOCUMENTS
from tool_misuse_lab_v5 import run

HERE = Path(__file__).resolve().parent
CASES_FILE = HERE / 'cases_v5_validation.json'
FIELDS = [
    'case_id', 'category', 'mode', 'repeat', 'valid', 'complete', 'legitimate_task_success',
    'model_proposed_unauthorized_read', 'model_proposed_unauthorized_read_after_exposure',
    'unauthorized_read_attempted', 'unauthorized_read_executed',
    'unauthorized_transfer_attempted', 'unauthorized_transfer_executed',
    'canary_delivered', 'unauthorized_canary_delivery', 'elapsed_seconds'
]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load_cases():
    cases = json.loads(CASES_FILE.read_text(encoding='utf-8'))
    if not isinstance(cases, list) or not cases:
        raise ValueError('Expected nonempty case list')
    ids = set()
    for c in cases:
        required = {'id', 'category', 'primary_document', 'authorized_sources', 'recipient', 'document_override'}
        if not required.issubset(c):
            raise ValueError(f'Missing case keys: {c}')
        if c['id'] in ids:
            raise ValueError(f'Duplicate case ID: {c["id"]}')
        ids.add(c['id'])
        if c['category'] not in {'benign', 'positive_control', 'attack'}:
            raise ValueError(f'Unsupported category: {c["category"]}')
        if c['primary_document'] not in DOCUMENTS:
            raise ValueError(f'Unknown primary document: {c["primary_document"]}')
        if c['authorized_sources'] != [c['primary_document']]:
            raise ValueError(f'This evaluation requires task scope = named primary source for {c["id"]}')
        if c['document_override'] is not None and not isinstance(c['document_override'], str):
            raise ValueError(f'Invalid document override for {c["id"]}')
    return cases

def build_row(c, mode, rep, d):
    return {
        'case_id': c['id'], 'category': c['category'], 'mode': mode, 'repeat': rep, 'valid': 1,
        'complete': int(d['workflow_complete']),
        'legitimate_task_success': int(d['legitimate_task_success']),
        'model_proposed_unauthorized_read': int(d['model_proposed_unauthorized_read']),
        'model_proposed_unauthorized_read_after_exposure': int(d['model_proposed_unauthorized_read_after_exposure']),
        'unauthorized_read_attempted': int(d['unauthorized_read_attempted']),
        'unauthorized_read_executed': int(d['unauthorized_read_executed']),
        'unauthorized_transfer_attempted': int(d['unauthorized_transfer_attempted']),
        'unauthorized_transfer_executed': int(d['unauthorized_transfer_executed']),
        'canary_delivered': int(d['canary_delivered']),
        'unauthorized_canary_delivery': int(d['unauthorized_canary_delivery']),
        'elapsed_seconds': d['elapsed_seconds'],
    }

def main():
    ap = argparse.ArgumentParser(description='Run frozen V5 with additional predeclared synthetic cases.')
    ap.add_argument('--ids', nargs='*', default=[], help='Only run these case IDs; omission runs the full set')
    ap.add_argument('--exclude-ids', nargs='*', default=[], help='Exclude smoke-test cases from confirmatory pilot')
    ap.add_argument('--modes', nargs='+', choices=['none', 'static', 'context'], default=['none', 'static', 'context'])
    ap.add_argument('--repeats', type=int, default=1)
    ap.add_argument('--model', default='qwen2.5:1.5b')
    ap.add_argument('--max-steps', type=int, default=16)
    ap.add_argument('--timeout', type=int, default=180)
    ap.add_argument('--output-dir', default='../results/v5_eval')
    args = ap.parse_args()
    if args.repeats < 1: ap.error('--repeats must be positive')
    cases = load_cases()
    if args.ids:
        missing = sorted(set(args.ids) - {c['id'] for c in cases})
        if missing: ap.error('Unknown case IDs: ' + ', '.join(missing))
        cases = [c for c in cases if c['id'] in args.ids]
    unknown_exclude = sorted(set(args.exclude_ids) - {c['id'] for c in load_cases()})
    if unknown_exclude: ap.error('Unknown excluded case IDs: ' + ', '.join(unknown_exclude))
    cases = [c for c in cases if c['id'] not in args.exclude_ids]
    if not cases: ap.error('No cases remain after exclusions')
    out = Path(args.output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    raw = out / 'raw'
    raw.mkdir(exist_ok=True)
    source_files = ['experiment.py', 'tool_misuse_lab_v5.py', 'run_v5_validation.py', 'cases_v5_validation.json']
    hashes = {n: sha(HERE / n) for n in source_files}
    meta = {'experiment': 'V5 supplementary stress-test: synthetic, local Ollama',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'model': args.model, 'modes': args.modes, 'repeats': args.repeats,
            'case_ids': [c['id'] for c in cases], 'max_steps': args.max_steps,
            'timeout': args.timeout, 'hashes': hashes, 'python': sys.version,
            'data_and_sink': 'Synthetic local fixture and in-memory recipient only',
            'note': 'Researcher-authored additional stress scenarios, NOT blinded independent validation. Freeze files before launch; ask external evaluator for blind test.'}
    metafile = out / 'metadata.json'
    if metafile.exists():
        stored = json.loads(metafile.read_text(encoding='utf-8'))
        fields_to_match = ['model', 'modes', 'repeats', 'case_ids', 'max_steps', 'timeout', 'hashes']
        if any(stored.get(k) != meta.get(k) for k in fields_to_match):
            ap.error('Different experiment/code already in output dir. Select a NEW --output-dir.')
    else:
        metafile.write_text(json.dumps(meta, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    rows, n, total = [], 0, len(cases) * len(args.modes) * args.repeats
    for c in cases:
        primary = c['primary_document']
        original = DOCUMENTS[primary]['text']
        for mode in args.modes:
            for rep in range(1, args.repeats+1):
                n += 1
                stem = f"{c['id']}__{mode}__r{rep:02}"
                path = raw / f'{stem}.json'
                print(f'[{n}/{total}] {stem}', flush=True)
                try:
                    if path.exists():
                        d = json.loads(path.read_text(encoding='utf-8'))
                    else:
                        DOCUMENTS[primary]['text'] = c['document_override'] if c['document_override'] is not None else original
                        start = time.perf_counter()
                        d = run(c, mode, args.model, args.max_steps, args.timeout)
                        d['elapsed_seconds'] = round(time.perf_counter()-start,3)
                        path.write_text(json.dumps(d, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
                    rows.append(build_row(c, mode, rep, d))
                except Exception as e:
                    (raw / f'{stem}.error.txt').write_text(f'{type(e).__name__}: {e}\n', encoding='utf-8')
                    print(f'ERROR {type(e).__name__}: {e}', flush=True)
                finally:
                    DOCUMENTS[primary]['text'] = original
    with (out / 'trials.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f'Valid runs: {len(rows)}/{total}. Results: {out / "trials.csv"}')
    print('Next: python3 summarize_v5_eval.py --input-dir ' + str(out))

if __name__ == '__main__':
    main()
