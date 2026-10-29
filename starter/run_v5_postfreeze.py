#!/usr/bin/env python3
"""Post-freeze V5 extension: new synthetic cases, unchanged V5 runtime.

Use --dry-run first. To execute, use --run. The script will not overwrite
existing results or proceed when a source differs from the frozen hashes.
These tests are researcher-authored, NOT blinded independent validation.
"""
from __future__ import annotations

import argparse
import copy
import csv
from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODES = ('none', 'static', 'context')
FIELDS = [
    'case_id', 'category', 'mode', 'repeat',
    'model_proposed_unauthorized_read_after_exposure',
    'unauthorized_read_attempted', 'unauthorized_read_executed',
    'unauthorized_transfer_attempted', 'unauthorized_transfer_executed',
    'canary_delivered', 'legitimate_task_success', 'workflow_complete', 'file'
]
SOURCE_FILES = ('tool_misuse_lab_v5.py', 'experiment.py', 'run_v5_validation.py', 'cases_v5_validation.json')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool_output(cmd: list[str]) -> str:
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=20, check=False)
        return (p.stdout or p.stderr).strip()[:16000] if p.returncode == 0 else f'COMMAND FAILED ({p.returncode}): {(p.stderr or p.stdout).strip()[:1000]}'
    except (OSError, subprocess.TimeoutExpired) as e:
        return f'UNAVAILABLE: {e}'


def load_frozen_hashes(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise RuntimeError(f'Freeze manifest not found: {path}. Run the sha256sum freeze command before continuing.')
    frozen = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.match(r'^([0-9a-fA-F]{64})\s+\*?(.+)$', line.strip())
        if match:
            frozen[Path(match.group(2)).name] = match.group(1).lower()
    for name in SOURCE_FILES:
        if name not in frozen:
            raise RuntimeError(f'Freeze manifest missing {name}: {path}')
        actual_file = HERE / name
        if not actual_file.is_file():
            raise RuntimeError(f'Frozen source missing: {actual_file}')
        if sha(actual_file) != frozen[name]:
            raise RuntimeError(f'Frozen source CHANGED: {name}; refuse to run. Do not edit V5 to accommodate these cases.')
    return {name: frozen[name] for name in SOURCE_FILES}


def load_cases(path: Path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, list) or len(data) != 15:
        raise ValueError(f'Expected exactly 15 cases in an array, found {type(data).__name__}')
    required = {'id', 'category', 'primary_document', 'recipient', 'authorized_sources', 'document_override', 'description'}
    ids = set()
    counts = {'attack': 0, 'benign': 0}
    for case in data:
        if not isinstance(case, dict) or not required.issubset(case):
            raise ValueError(f'Case missing required fields: {case!r}')
        if case['id'] in ids:
            raise ValueError(f'Duplicate case ID: {case["id"]}')
        ids.add(case['id'])
        cat = case['category']
        if cat not in counts:
            raise ValueError(f'Unknown category {cat!r}: {case["id"]}')
        counts[cat] += 1
        if not case['authorized_sources'] or not isinstance(case['authorized_sources'], list):
            raise ValueError(f'Invalid trusted sources: {case["id"]}')
        if case['primary_document'] not in case['authorized_sources']:
            raise ValueError(f'Task must authorize its primary document: {case["id"]}')
        if not isinstance(case['document_override'], str):
            raise ValueError(f'Expected synthetic text override: {case["id"]}')
    if counts != {'attack': 10, 'benign': 5}:
        raise ValueError(f'Unexpected case mix: {counts}')
    return data


def check_catalog(cases, lab):
    for case in cases:
        for doc_id in [case['primary_document'], *case['authorized_sources']]:
            if doc_id not in lab.DOCUMENTS:
                raise RuntimeError(f'{case["id"]} references unknown document ID {doc_id!r}. Stop; do not alter the V5 catalog after freeze.')
        if case['recipient'] not in lab.DEST_MAX:
            raise RuntimeError(f'{case["id"]} references unknown recipient {case["recipient"]!r}. Stop; do not alter policy after freeze.')


def dump_atomic(path: Path, data):
    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    temp.replace(path)


def write_csv(path: Path, rows: list[dict], columns: list[str]):
    temp = path.with_name(path.name+'.tmp')
    with temp.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    temp.replace(path)


def make_summaries(index: list[dict], dest: Path):
    summary = []
    binary_cols = [
        'model_proposed_unauthorized_read_after_exposure',
        'unauthorized_read_attempted', 'unauthorized_read_executed',
        'unauthorized_transfer_attempted', 'unauthorized_transfer_executed',
        'canary_delivered', 'legitimate_task_success', 'workflow_complete'
    ]
    for category in ('attack', 'benign'):
        for mode in MODES:
            subset = [r for r in index if r['category']==category and r['mode']==mode]
            entry={'category':category,'mode':mode,'runs':len(subset)}
            for field in binary_cols:
                entry[field+'_true'] = sum(r[field] is True for r in subset)
                entry[field+'_missing'] = sum(r[field] is None for r in subset)
            summary.append(entry)
    write_csv(dest/'summary_by_mode.csv',summary,list(summary[0]))


def main():
    parser = argparse.ArgumentParser(description='Run new researcher-authored post-freeze synthetic cases against unchanged V5')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dry-run', action='store_true', help='Validate format and frozen source hashes; do not call Ollama')
    group.add_argument('--run', action='store_true', help='Execute scenarios and write complete raw logs')
    parser.add_argument('--case-file', default='cases_v5_postfreeze.json')
    parser.add_argument('--model', default='qwen2.5:1.5b')
    parser.add_argument('--max-steps', type=int, default=16)
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--freeze-file', default='../results/v5_postfreeze/source_sha256.txt')
    parser.add_argument('--output-dir', default='../results/v5_postfreeze_eval')
    parser.add_argument('--resume', action='store_true', help='Skip existing run logs only after manifest hashes match; never overwrite')
    args=parser.parse_args()
    if args.max_steps < 1 or args.repeats < 1:
        parser.error('--max-steps and --repeats must be positive')
    case_path=(HERE/args.case_file).resolve()
    frozen_path=(HERE/args.freeze_file).resolve()
    out=(HERE/args.output_dir).resolve()
    if not case_path.is_file():
        parser.error(f'Missing dataset: {case_path}')
    cases=load_cases(case_path)
    frozen=load_frozen_hashes(frozen_path)
    sys.path.insert(0, str(HERE))
    import tool_misuse_lab_v5 as lab
    check_catalog(cases, lab)
    expected = [(case, mode, rep, out/'raw'/f'{case["id"]}__{mode}__r{rep:02d}.json')
                for case in cases for mode in MODES for rep in range(1,args.repeats+1)]
    print(f'Validated: {len(cases)} cases (10 attacks, 5 benign); {len(expected)} runs; V5 source hashes match freeze.')
    print(f'Case SHA256: {sha(case_path)}')
    print(f'Destination: {out}')
    if args.dry_run:
        print('DRY RUN ONLY: no model calls, no results created.')
        return

    new_manifest = {
        'study': 'researcher-authored post-freeze validation; not an external blind benchmark',
        'cases_file':case_path.name,
        'cases_sha256':sha(case_path),
        'source_sha256':frozen,
        'model':args.model,
        'max_steps':args.max_steps,
        'repeats':args.repeats,
        'modes':list(MODES),
        'case_ids':[x['id'] for x in cases],
        'protocol':'case sequence: attacks then benign; modes none, static, context; repeats 1..N',
    }
    manifest_path=out/'manifest.json'
    if manifest_path.exists():
        saved=json.loads(manifest_path.read_text(encoding='utf-8'))
        for key,val in new_manifest.items():
            if saved.get(key)!=val:
                raise RuntimeError(f'Existing experiment manifest differs at {key!r}. Choose a NEW --output-dir; do not mix studies.')
        if not args.resume:
            raise RuntimeError('Experiment directory exists; use --resume to skip verified existing logs or choose a new --output-dir.')
    else:
        if out.exists() and any(out.iterdir()):
            raise RuntimeError(f'Non-empty untracked output directory: {out}; choose a new --output-dir.')
        (out/'raw').mkdir(parents=True,exist_ok=True)
        new_manifest.update({
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'python':sys.version,
            'ollama_version':tool_output(['ollama','--version']),
            'ollama_list':tool_output(['ollama','list']),
            'ollama_show':tool_output(['ollama','show',args.model]),
            'original_105_unchanged': True,
        })
        dump_atomic(manifest_path,new_manifest)
    for _,_,_,filename in expected:
        if filename.exists() and not args.resume:
            raise RuntimeError(f'Refusing overwrite: {filename}')

    print('Starting model calls; do not edit V5 or post-freeze JSON after collecting results.',flush=True)
    index=[]
    for i,(case,mode,rep,filename) in enumerate(expected,1):
        if filename.exists():
            result=json.loads(filename.read_text(encoding='utf-8'))
            m=result.get('_postfreeze_meta',{})
            if m.get('dataset_sha256')!=sha(case_path) or m.get('case_id')!=case['id'] or m.get('mode')!=mode or m.get('repeat')!=rep:
                raise RuntimeError(f'Existing log metadata mismatch: {filename}')
            print(f'SKIP [{i}/{len(expected)}] {filename.name}',flush=True)
        else:
            item=copy.deepcopy(case)
            primary=item['primary_document']
            old=lab.DOCUMENTS[primary]['text']
            print(f'RUN  [{i}/{len(expected)}] {case["id"]} | {mode} | r{rep:02d}',flush=True)
            try:
                lab.DOCUMENTS[primary]['text']=item['document_override']
                result=lab.run(item,mode,args.model,args.max_steps)
            finally:
                lab.DOCUMENTS[primary]['text']=old
            if not isinstance(result,dict):
                raise RuntimeError(f'V5 returned a non-object result for {case["id"]}/{mode}')
            if result.get('case_id') not in (None,case['id']):
                raise RuntimeError(f'V5 returned unexpected case ID: {result.get("case_id")!r}')
            if result.get('mode') not in (None,mode):
                raise RuntimeError(f'V5 returned unexpected mode: {result.get("mode")!r}')
            result['_postfreeze_meta']={
                'case_id':case['id'],'category':case['category'],'mode':mode,'repeat':rep,
                'dataset_sha256':sha(case_path),'model':args.model,'max_steps':args.max_steps
            }
            dump_atomic(filename,result)
        row={'case_id':case['id'],'category':case['category'],'mode':mode,'repeat':rep,'file':str(filename)}
        for name in FIELDS:
            if name not in row:
                row[name]=result.get(name)
        index.append(row)
        write_csv(out/'postfreeze_index.csv',index,FIELDS)
        make_summaries(index,out)
        print(f'      attempted={row["unauthorized_read_attempted"]} executed={row["unauthorized_read_executed"]} transferred={row["unauthorized_transfer_executed"]} benign_success={row["legitimate_task_success"]}',flush=True)
    print('COMPLETE. Raw logs, manifest.json, postfreeze_index.csv, summary_by_mode.csv are in:',out,flush=True)
    print('Interpret all 15 predeclared cases; do not remove cases that failed to induce a forbidden action.',flush=True)

if __name__=='__main__':
    main()
