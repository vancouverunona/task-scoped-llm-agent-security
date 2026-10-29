TOOL MISUSE V5 — stage-limited tool interface (technical pilot)

PURPOSE
Fix the issue where Qwen proposes read_doc, create_source_bound_report, and send_report
in one response before seeing any results, after which create and send are deferred.
V5 advertises only the tools appropriate to the workflow's current state:
  BEFORE requested doc is read: read_doc
  AFTER requested doc is read, BEFORE report: read_doc + create_source_bound_report
  AFTER report exists: send_report
No change is made to GuardedTools authorization. All modes share the same model,
same staged tools, same system/user prompts, and same synthetic case content.
Note: After initial document reading, read_doc still appears as an option, so
an agent-originated unauthorized read can still be attempted and measured.

INSTALL (from ~/agent_security_paper1/starter in Ubuntu)
  unzip ~/Downloads/tool_misuse_v5_stagefix.zip -d .
  python3 -m unittest -v test_tool_misuse_v5

SMOKE TEST REAL OLLAMA
  python3 run_tool_misuse_v5.py \
    --ids B01_SALES_CLEAN P01_HR_AUTHORIZED A01_DIRECT_DOCUMENT_INJECTION \
    --modes none static context \
    --repeats 1 --max-steps 16 \
    --output-dir ../results/tool_misuse_v5_smoke

OUTPUT
  ../results/tool_misuse_v5_smoke/trials.csv
  ../results/tool_misuse_v5_smoke/raw/*.json
  ../results/tool_misuse_v5_smoke/metadata.json

SCOPE
The 4 bundled tests use scripted mock model responses, not Ollama. A real LLM
smoke test is required before interpreting effects. Do not merge results from
V4 and V5: tool exposure is different. These are development scenarios and not
an independent scientific evaluation. Keep all transfer tools in-memory.

IMPORTANT
Do not run --repeats with different runs in the same output dir unless its
metadata matches; the batch script validates this. For later experiments,
freeze this code and prepare a new, held-out case set before results are seen.
