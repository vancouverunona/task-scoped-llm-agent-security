LIVE AGENT BATCH PILOT - NO MODIFICATIONS TO YOUR AGENT

1) Download live_agent_batch_pilot.zip into Ubuntu ~/Downloads.
2) cd ~/agent_security_paper1/starter
3) unzip ~/Downloads/live_agent_batch_pilot.zip -d .
4) python3 -m py_compile run_live_batch.py summarize_live_batch.py
5) Run a SHORT SMOKE TEST (2 scenarios x 2 modes = 4 real LLM runs):
   python3 run_live_batch.py --modes none context_v3 --samples clean injection --repeats 1 --output-dir ../results/batch_smoke
   python3 summarize_live_batch.py --input-dir ../results/batch_smoke
6) If healthy, run pilot (2 samples x 5 modes x 3 repeats = 30 live LLM runs):
   python3 run_live_batch.py --repeats 3 --output-dir ../results/live_batch_pilot
   python3 summarize_live_batch.py --input-dir ../results/live_batch_pilot

The runner saves each run JSON, stdout, stderr; batch_metadata.json contains
source hashes and conditions. Existing completed JSONs are skipped (resume).
If changing the agent or policies, use a NEW --output-dir. Avoid --overwrite
for original results.

IMPORTANT SCIENTIFIC LIMITATIONS
* The agent exposes only two sample types, clean and injection; scenarios.json
  is a separate deterministic policy-replay dataset, NOT 24 live LLM prompts.
* Ollama temperature is 0. Repetitions are reliability diagnostics, not 30
  independent attacks. Do NOT claim effectiveness against general attacks.
* When the unprotected agent does not attempt exfiltration, a zero-leak rate
  for the defended agent does not demonstrate prevention of exfiltration.
* Contamination is an exact-marker diagnostic; the V3 sender uses a restricted
  output schema and prevents arbitrary raw text from being forwarded, which
  changes utility/generalizability. The full paper needs independent, held-out
  benign and malicious samples, controls, and confidence intervals.
* All simulated recipients are local; no real data should be used.
