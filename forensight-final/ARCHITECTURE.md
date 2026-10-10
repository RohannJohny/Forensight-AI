# Forensight AI Target Architecture

```text
                    USER UPLOADS EVIDENCE
                            │
                            ▼
                  Evidence Intake Layer
                            │
                            ▼
                 Evidence Type Identifier
                            │
            ┌───────────────┼────────────────┐
            │               │                │
            ▼               ▼                ▼
        Disk Image       Memory Dump     Individual
        / Forensic       / Memory File    Artifacts
        Container             │                │
            │                 │                │
            ▼                 ▼                ▼
        Autopsy /          Volatility 3     Artifact-
        Sleuth Kit                         specific
            │                                  parsers
            └───────────────┬──────────────────┘
                            │
                            ▼
                    Plaso / Timeline
                    where applicable
                            │
                            ▼
                 Extraction / Parsing
                            │
                            ▼
                     Normalization
                            │
                            ▼
                Common Event Schema
                            │
                            ▼
                  normalized_events
                            │
                            ▼
              Downstream Forensight AI
```

## Architectural Principles

1. **Classification Before Processing**: Uploaded evidence is first inspected using magic bytes, file headers, container signatures, and structure. Only then is the appropriate forensic pipeline selected.
2. **Real Forensic Tools**: Autopsy/Sleuth Kit, Plaso, and Volatility 3 are invoked as real forensic executables with validated outputs.
3. **Common Event Schema**: Normalizes all extracted events into a strict 17-field schema with original provenance retained in `metadata`.
4. **Isolated Case Storage**: Cases are stored with clear segregation of raw tool runs, evidence hashes, and normalized events.
5. **No AI/LLM in this Layer**: This module's single responsibility is robust evidence intake, extraction, parsing, and normalization. Downstream layers consume `normalized_events.json`.
