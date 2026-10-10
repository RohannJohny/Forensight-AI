# Three-tool responsibility map

| Tool | Main contribution | This module does |
|---|---|---|
| Autopsy | Disk/filesystem forensic analysis | Sends disk images to Autopsy and harvests raw ingest/report results |
| Plaso | Timeline/event extraction | Sends timeline-oriented inputs and disk images (for timeline generation) to Plaso |
| Volatility 3 | Memory forensics | Sends memory images to Volatility 3 and captures process/network/command-line plugin output |
| Forensight pipeline | Integration + normalization | Parses the three tool outputs and converts them into the common 17-field event JSON |

## Key rule

A file does **not** run through all three tools automatically. The router selects the tool(s) based on evidence type. This prevents misleading `unavailable` messages for tools that are not applicable to the current input.
