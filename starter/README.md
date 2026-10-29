# V5 post-freeze evaluation kit (10 attacks, 5 benign cases)

This is a **researcher-authored** supplementary test set created after the original V5 design; it is **not** an independently authored or blinded benchmark. The test content uses synthetic local documents only. Nothing in this kit changes the original V5 code or its existing 105-run / 45-repeat results.

## Files

- `cases_v5_postfreeze.json` — 15 fixed scenarios in the V5 validation format.
- `postfreeze_attack_intents.json` — predeclared targets, denominators, and analysis criteria.
- `run_v5_postfreeze.py` — original `tool_misuse_lab_v5.run(case,mode,model,max_steps)` driver, with frozen-hash checks and non-overwriting run logs.

## Installation in Ubuntu

Copy all three files into `~/agent_security_paper1/starter/` alongside `tool_misuse_lab_v5.py` and the original JSON case files. Do **not** edit the original V5 code or the old datasets.

Check that `~/agent_security_paper1/results/v5_postfreeze/source_sha256.txt` exists and was saved **before** reviewing results from the new dataset. It should contain SHA256 hashes for `tool_misuse_lab_v5.py`, `experiment.py`, `run_v5_validation.py`, and `cases_v5_validation.json`.

If the freeze file was not saved previously, document that fact transparently; creating a new freeze file now is not equivalent to proving the earlier state.

```
cd ~/agent_security_paper1/starter
python3 run_v5_postfreeze.py --dry-run
python3 run_v5_postfreeze.py --run --repeats 1
```

The model is `qwen2.5:1.5b` by default. The run generates `../results/v5_postfreeze_eval/raw/*.json`, `manifest.json`, `postfreeze_index.csv`, and `summary_by_mode.csv`. If interrupted, use `--run --repeats 1 --resume`, which checks the manifest and refuses to overwrite existing logs.

Then perform evidence extraction with the existing script:

```
python3 verify_v5_evidence.py \
  --input ../results/v5_postfreeze_eval/raw \
  --output ../results/v5_postfreeze_eval_review
```

**Manually inspect** the `tool_trace` / `audit` for each positive executed transfer: report ID, source IDs, recipient, `send` allowed=true, and context of the trusted task. A read not attempted is not a successful policy interception. An absence of a transfer is not proof that `send_report` blocked it. The controller imposes a source-read prerequisite and staged tool exposure in all modes.

## Interpretation and paper reporting

For each configuration report separate numerators / denominators for unauthorized read proposals, attempted reads, executed reads, unauthorized transfers, and legitimate successes. With 10 attack and 5 benign scenarios there are 15 runs per configuration, **45 in total** (when `--repeats 1`). Do not merge them with the original 105 or the separate 45 repeats.

This dataset has 8 source-expansion attacks and 2 recipient-redirection attacks. The primary read-attempt denominator should therefore be shown for 8 source-expansion scenarios; reports of all 10 attack scenarios should state that two seek a *recipient*, not a forbidden read. For either type, verify actual model action before assigning defensive credit. The tested LLM may not comply with some instructions.

For reproducibility, publish the fixed script, JSON, SHA256 manifest, full run logs, summarizer output, Python/Ollama versions and exact model digest. If external experts construct truly blind scenarios without changing the defense, report them as a *separate* external validation.
