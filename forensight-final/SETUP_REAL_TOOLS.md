# Real-tool setup

The router is now correct, but real extraction still requires the external forensic tools to be installed on the forensic workstation.

## Autopsy (disk images)

Use a Windows forensic workstation with Autopsy installed. Autopsy's command-line ingest flow requires creating/opening a case, adding the data source and optionally running ingest. This project does exactly that. Set `AUTOPSY_BIN` when the executable is not found automatically.

Example PowerShell:

```powershell
$env:AUTOPSY_BIN='C:\Program Files\Autopsy-<version>\bin\autopsy64.exe'
```

Then:

```powershell
python -m app.cli tools
python -m app.cli route .\evidence.E01
python -m app.cli process .\evidence.E01 --output .\output\case-001
```

## Plaso (timeline)

Install Plaso so `psteal.py`/`psteal` is available. Plaso documents `psteal` as the frontend that extracts events from a source and produces timeline output; this project parses that output into the shared event schema.

Check:

```bash
psteal.py --help
```

Then:

```bash
PYTHONPATH=. python -m app.cli process /path/to/evidence.E01 --output output/case-001
```

For a standalone event/timeline artifact:

```bash
PYTHONPATH=. python -m app.cli process /path/to/Security.evtx --output output/timeline-001
```

## Volatility 3 (memory images)

Install `volatility3` or expose `vol`/`vol.py`. The adapter requests JSONL output from memory plugins and parses the resulting process/network/command-line records.

Check:

```bash
vol.py -h
```

Then:

```bash
PYTHONPATH=. python -m app.cli process /path/to/memory.mem --output output/memory-001
```

For an ambiguous `.raw` memory image:

```bash
PYTHONPATH=. python -m app.cli process /path/to/memory.raw --kind memory --output output/memory-001
```

## What a successful run looks like

For a disk image:

```text
Route:
  disk
  Autopsy + Plaso

Tool runs:
  Autopsy       SUCCESS
  Plaso         SUCCESS
  Volatility 3  SKIPPED_NOT_APPLICABLE

Output:
  output/case-001/normalized_events.json
  output/case-001/normalized_events.jsonl
```

For memory:

```text
Route:
  memory
  Volatility 3

Tool runs:
  Autopsy       SKIPPED_NOT_APPLICABLE
  Plaso         SKIPPED_NOT_APPLICABLE
  Volatility 3  SUCCESS
```

For timeline artifacts:

```text
Route:
  timeline
  Plaso
```

If a required tool is absent, the result is `NOT_INSTALLED`; the system does not label unrelated tools as unavailable and does not fabricate extraction.
