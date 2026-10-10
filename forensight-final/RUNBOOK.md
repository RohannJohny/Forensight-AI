# Fast demo checklist

## Before demo

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. python -m app.cli tools
```

## Show routing

```bash
PYTHONPATH=. python -m app.cli route suspect.E01
PYTHONPATH=. python -m app.cli route Security.evtx
PYTHONPATH=. python -m app.cli route capture.pcapng
PYTHONPATH=. python -m app.cli route memory.mem
```

## Run

```bash
PYTHONPATH=. python -m app.cli process suspect.E01 --output output/demo-disk
```

Expected:

```text
Autopsy       REQUIRED
Plaso         REQUIRED
Volatility 3  SKIPPED_NOT_APPLICABLE
```

Then inspect:

```text
output/demo-disk/tool_runs/
output/demo-disk/normalized_events.json
output/demo-disk/normalized_events.jsonl
output/demo-disk/processing_manifest.json
```

## Important demo rule

Do not call synthetic output "Autopsy results" or "Volatility results". Synthetic files are for parser testing only. A real forensic demo must show the real command, exit code, tool output folder, and resulting normalized events.
