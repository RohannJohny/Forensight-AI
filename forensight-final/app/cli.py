from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evidence_identifier import identify_evidence
from app.input_router import classify_input
from app.pipeline import process_file
from app.tools.detector import tool_status


def main():
    parser = argparse.ArgumentParser(
        description="Forensight AI - Evidence Classification, Tool-Routed Extraction & Normalization"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. Tools command
    sub.add_parser("tools", help="Show detected forensic tools, versions, and paths")

    # 2. Identify command (Section 3)
    ident = sub.add_parser("identify", help="Perform reliable evidence classification on uploaded file")
    ident.add_argument("input", help="Path to evidence file")
    ident.add_argument("--kind", choices=["auto", "disk", "memory", "timeline", "packet"], default="auto")

    # 3. Route command
    route = sub.add_parser("route", help="Show which tool(s) will process the evidence")
    route.add_argument("input", help="Path to evidence file")
    route.add_argument("--kind", choices=["auto", "disk", "memory", "timeline", "packet"], default="auto")

    # 4. Process command
    proc = sub.add_parser("process", help="Route evidence to correct forensic tool(s), parse, and normalize")
    proc.add_argument("input", help="Path to evidence file")
    proc.add_argument("--output", default="cases/case-001", help="Destination case output directory")
    proc.add_argument("--kind", choices=["auto", "disk", "memory", "timeline", "packet"], default="auto")
    proc.add_argument("--no-timeline", action="store_true", help="For disk evidence, disable Plaso timeline extraction")

    args = parser.parse_args()

    if args.command == "tools":
        print(json.dumps(tool_status(), indent=2))
        return

    if args.command == "identify":
        res = identify_evidence(args.input, requested_kind=args.kind)
        print(json.dumps(res.to_dict(), indent=2))
        return

    if args.command == "route":
        r = classify_input(args.input, requested_kind=args.kind)
        payload = {
            "kind": r.kind,
            "primary_tools": list(r.primary_tools),
            "description": r.description,
            "reason": r.reason,
            "classification": r.classification.to_dict() if r.classification else None,
        }
        print(json.dumps(payload, indent=2))
        return

    if args.command == "process":
        result = process_file(
            path=args.input,
            output_dir=args.output,
            kind=args.kind,
            timeline=not args.no_timeline,
        )
        summary = {
            "case_id": result.get("case_id"),
            "evidence_id": result.get("evidence_id"),
            "detected_type": result.get("detected_type"),
            "event_count": result.get("event_count"),
            "normalization": result.get("normalization"),
            "processors": result.get("processors"),
            "output_json": result.get("output_json"),
            "manifest_path": result.get("manifest_path"),
        }
        print(json.dumps(summary, indent=2))
        return


if __name__ == "__main__":
    main()
