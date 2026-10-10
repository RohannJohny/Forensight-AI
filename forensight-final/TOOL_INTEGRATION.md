# Tool integration runbook

## Expected behavior

### Disk image

`evidence.E01` or similar:

1. Router classifies it as `disk`.
2. Autopsy is the primary filesystem/artifact extractor.
3. Plaso runs by default to create a timestamped timeline.
4. Volatility 3 is marked `SKIPPED_NOT_APPLICABLE`.

### Memory image

`memory.mem` or similar:

1. Router classifies it as `memory`.
2. Volatility 3 runs the selected Windows memory plugins.
3. Autopsy and Plaso are marked `SKIPPED_NOT_APPLICABLE`.

### Timeline/event artifact

`Security.evtx`, event logs, supported databases/files:

1. Router classifies it as `timeline`.
2. Plaso runs.
3. Raw timeline output is parsed.
4. Events are normalized.

### Packet capture

`capture.pcap` / `pcapng`:

1. Router classifies it as `packet`.
2. Plaso is attempted as the requested timeline/event extraction engine.
3. If the installed parser set does not support the capture, the run is marked failed and the failure is stored.

## Why the tool status changed

Old behavior:

```text
Autopsy   unavailable
Plaso     unavailable
Volatility unavailable
```

New behavior is input-aware:

```text
INPUT: evidence.E01

Autopsy       REQUIRED → SUCCESS / NOT_INSTALLED / FAILED
Plaso         REQUIRED → SUCCESS / NOT_INSTALLED / FAILED
Volatility 3  SKIPPED_NOT_APPLICABLE
```

and:

```text
INPUT: memory.mem

Autopsy       SKIPPED_NOT_APPLICABLE
Plaso         SKIPPED_NOT_APPLICABLE
Volatility 3  REQUIRED → SUCCESS / NOT_INSTALLED / FAILED
```

This makes the execution state truthful and directly demonstrates which external forensic tool handled the evidence.
