"""Evidence-grounded investigation assistant for Member 2.

The current implementation is a deterministic retrieval + grounded narrative
layer. It intentionally does not pretend to be an external LLM. Every factual
claim is generated from records retrieved from the case database and carries
an event/artifact/evidence citation where available.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence, Tuple

from app.ai.retriever import retrieve_events
from app.models.models import Case, Event, Finding


_TEMPORAL_PHRASES = (
    "what happened before",
    "activity before",
    "events before",
    "preceding activity",
    "leading up to",
)

_TEMPORAL_WORDS = (
    "preceded",
    "preceding",
    "before",
    "prior",
    "previous",
)


def _has_temporal_intent(query: str) -> bool:
    """Detect whether a query requests preceding or temporal context."""
    q_lower = query.lower()
    if any(phrase in q_lower for phrase in _TEMPORAL_PHRASES):
        return True

    q_words = re.findall(r"\b[a-z]+\b", q_lower)
    return any(word in q_words for word in _TEMPORAL_WORDS)


class EvidenceGroundedAssistant:
    """Evidence-only investigation assistant with ranked retrieval."""

    @classmethod
    def query(
        cls,
        case: Case,
        events: List[Event],
        findings: List[Finding],
        user_query: str,
    ) -> Dict[str, Any]:
        ranked = retrieve_events(events, user_query, top_k=8)

        # A case-summary request is a retrieval mode, not a free-form
        # generation mode: use the case's explicitly flagged anomalous
        # events when lexical retrieval alone cannot express "summarize".
        summary_request = any(term in user_query.lower() for term in (
            "summar", "overview", "what happened", "incident timeline", "attack sequence"
        ))
        if summary_request:
            existing_ids = {event.event_id for event, _score in ranked}
            anomaly_events = sorted(
                (ev for ev in events if getattr(ev, "is_anomalous", 0) and ev.event_id not in existing_ids),
                key=lambda ev: (getattr(ev, "anomaly_score", 0.0), ev.timestamp),
                reverse=True,
            )
            ranked.extend((ev, min(0.95, 0.60 + 0.25 * float(getattr(ev, "anomaly_score", 0.0)))) for ev in anomaly_events[:8])
            ranked = sorted(ranked, key=lambda item: item[1], reverse=True)[:8]

        # Temporal Context Expansion
        temporal_intent = _has_temporal_intent(user_query)
        temporal_context_note = None

        if temporal_intent and ranked:
            primary_events = [event for event, _score in ranked]
            preceding = cls._find_preceding_events(primary_events, events)
            if preceding:
                existing_ids = {event.event_id for event, _score in ranked}
                for prev_ev in preceding:
                    if prev_ev.event_id not in existing_ids:
                        base_score = ranked[0][1] if ranked else 0.18
                        ranked.append((prev_ev, max(0.08, base_score)))
                        existing_ids.add(prev_ev.event_id)

                temporal_context_note = cls._build_temporal_explanation(primary_events, preceding)
                # Preserve chronological ordering for temporal-context responses
                ranked = sorted(
                    ranked,
                    key=lambda item: getattr(item[0], "timestamp", None),
                )

        matched_events = [event for event, _score in ranked]
        scores = [score for _event, score in ranked]

        citations = [cls._citation(ev) for ev in matched_events]

        if not matched_events:
            return {
                "case_id": case.case_id,
                "query": user_query,
                "response": (
                    f"No sufficiently relevant forensic records were retrieved for '{user_query}' "
                    f"in Case {case.case_number}. No unsupported forensic conclusion is generated."
                ),
                "citations": [],
                "confidence_score": 0.0,
                "analysis_type": "Evidence-Grounded Retrieval",
            }

        response = cls._build_narrative(user_query.lower(), matched_events, findings, case, temporal_context_note)
        confidence = cls._confidence(scores, len(matched_events))

        return {
            "case_id": case.case_id,
            "query": user_query,
            "response": response,
            "citations": citations,
            "confidence_score": confidence,
            "analysis_type": "Evidence-Grounded Retrieval",
        }

    @classmethod
    def _find_preceding_events(
        cls,
        primary_events: List[Event],
        all_events: List[Event],
        max_preceding: int = 1,
    ) -> List[Event]:
        """Find behaviorally relevant events that occurred shortly before primary events."""
        if not primary_events or not all_events:
            return []

        primary_ids = {ev.event_id for ev in primary_events}
        valid_primaries = [ev for ev in primary_events if getattr(ev, "timestamp", None)]
        if not valid_primaries:
            return []

        anchor_time = min(ev.timestamp for ev in valid_primaries)

        candidates = [
            ev for ev in all_events
            if getattr(ev, "timestamp", None)
            and ev.timestamp < anchor_time
            and ev.event_id not in primary_ids
        ]

        if not candidates:
            return []

        scored_candidates: List[Tuple[Event, float]] = []
        for cand in candidates:
            delta_sec = (anchor_time - cand.timestamp).total_seconds()
            if delta_sec <= 0 or delta_sec > 3600:
                continue

            proximity = 1.0 / (1.0 + delta_sec / 60.0)
            relevance = proximity

            if getattr(cand, "is_anomalous", 0):
                relevance += 0.25

            c_details_str = str(getattr(cand, "details", {}) or "").lower()
            c_type = str(getattr(cand, "event_type", "")).upper()

            if any(term in c_details_str for term in ("7z", ".zip", ".tar", ".rar", "archive", "staging", "compress")):
                relevance += 0.50
            elif c_type in ("PROCESS_CREATE", "FILE_DROP"):
                relevance += 0.20

            scored_candidates.append((cand, relevance))

        if not scored_candidates:
            return []

        scored_candidates.sort(key=lambda item: item[1], reverse=True)
        return [cand for cand, _rel in scored_candidates[:max_preceding]]

    @classmethod
    def _build_temporal_explanation(
        cls,
        primary_events: List[Event],
        preceding_events: List[Event],
    ) -> str | None:
        """Build a concise, evidence-grounded explanation of temporal sequence."""
        if not primary_events or not preceding_events:
            return None

        preceding = sorted(preceding_events, key=lambda ev: ev.timestamp)[0]
        after_primaries = [p for p in primary_events if p.timestamp and p.timestamp > preceding.timestamp]
        if not after_primaries:
            return None
        primary = sorted(after_primaries, key=lambda ev: ev.timestamp)[0]

        delta_sec = int((primary.timestamp - preceding.timestamp).total_seconds())
        if delta_sec < 0:
            return None

        delta_min = max(1, round(delta_sec / 60))
        if delta_min == 1:
            time_phrase = "approximately one minute"
        elif delta_min == 2:
            time_phrase = "approximately two minutes"
        else:
            time_phrase = f"approximately {delta_min} minutes"

        p_details_str = str(getattr(preceding, "details", {}) or "").lower()
        has_archive = any(t in p_details_str for t in ("7z", ".zip", ".tar", ".rar", "archive", "staging"))
        primary_type = str(getattr(primary, "event_type", "")).upper()
        primary_details = getattr(primary, "details", {}) or {}
        is_net_transfer = (
            primary_type in ("NETWORK_CONNECTION", "NETWORK", "NETWORK_FLOW")
            and (primary_details.get("bytes_transferred", 0) > 1_000_000 or "external-relay" in str(primary_details).lower())
        )

        if has_archive and is_net_transfer:
            return (
                f"The retrieved evidence shows archive/staging activity {time_phrase} before "
                "the high-volume outbound HTTPS transfer. This temporal sequence is consistent "
                "with staging preceding the transfer, but the retrieved records do not independently "
                "prove that the archive itself was the transferred payload."
            )
        elif has_archive:
            return (
                f"The retrieved evidence shows archive/staging activity {time_phrase} before "
                f"the subsequent {primary.event_type} event."
            )
        else:
            return (
                f"The retrieved evidence shows {preceding.event_type} activity {time_phrase} before "
                f"the subsequent {primary.event_type} event."
            )

    @staticmethod
    def _confidence(scores: List[float], count: int) -> float:
        """Estimate retrieval support, not probability of guilt/maliciousness."""
        if not scores or count == 0:
            return 0.0
        top = scores[0]
        support = min(0.15, max(0, count - 1) * 0.02)
        return round(min(0.99, max(0.05, 0.45 + 0.45 * top + support)), 2)

    @staticmethod
    def _citation(ev: Event) -> Dict[str, Any]:
        artifact = None
        evidence = None
        try:
            artifact = getattr(ev, "artifact", None)
            if artifact:
                evidence = getattr(artifact, "evidence", None)
        except Exception:
            pass

        return {
            "event_id": ev.event_id,
            "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if getattr(ev, "timestamp", None) else "",
            "source_entity": ev.source_entity,
            "artifact_id": getattr(artifact, "artifact_id", None) or getattr(ev, "artifact_id", None),
            "evidence_id": getattr(evidence, "evidence_id", None),
            "summary": f"[{ev.event_type}] {EvidenceGroundedAssistant._format_event_brief(ev)}",
        }

    @classmethod
    def _build_narrative(
        cls,
        q_lower: str,
        events: List[Event],
        findings: List[Finding],
        case: Case,
        temporal_context_note: str | None = None,
    ) -> str:
        lines = [f"### Evidence Analysis for Case {case.case_number}"]
        lines.append(f"Retrieved {len(events)} relevant forensic event(s) from the case evidence.")

        for idx, ev in enumerate(events[:6], 1):
            citation = f"[Event ID: {ev.event_id} | Artifact: {getattr(ev, 'artifact_id', 'N/A')}]"
            lines.append(
                f"{idx}. **{ev.event_type}** at {ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} — "
                f"{cls._format_event_brief(ev)} `{citation}`"
            )

        if temporal_context_note:
            lines.append(f"\n**Temporal Context:**\n{temporal_context_note}")

        # Only describe findings that are linked to retrieved evidence.
        retrieved_ids = {ev.event_id for ev in events}
        linked_findings = [f for f in findings if f.event_id in retrieved_ids]
        if linked_findings:
            lines.append("\n**Linked investigative findings:**")
            for finding in linked_findings[:5]:
                lines.append(
                    f"- {finding.finding_title} — confidence {finding.confidence_score:.2f}; "
                    f"validation status: {finding.validation_status}; event `{finding.event_id}`"
                )

        lines.append(
            "\n**Grounding note:** This response is limited to retrieved case records. "
            "It does not infer facts that are absent from the evidence."
        )
        return "\n".join(lines)

    @staticmethod
    def _format_event_brief(ev: Event) -> str:
        d = ev.details or {}
        if ev.event_type == "PROCESS_CREATE":
            cmd = d.get("command_line") or d.get("CommandLine") or d.get("image") or "N/A"
            return f"Process execution: `{str(cmd)[:160]}`"
        if ev.event_type == "NETWORK_CONNECTION":
            dst = d.get("dst_ip") or d.get("DestinationIp") or "N/A"
            port = d.get("dst_port") or d.get("DestinationPort") or "N/A"
            bytes_n = d.get("bytes_transferred") or d.get("bytes") or 0
            proto = d.get("protocol")
            sni = d.get("ssl_sni") or d.get("sni") or d.get("target_host")
            extra_parts = []
            if proto:
                extra_parts.append(proto)
            if sni:
                extra_parts.append(f"SNI: `{sni}`")
            if bytes_n:
                extra_parts.append(f"{bytes_n} bytes")
            extra_str = f" ({', '.join(extra_parts)})" if extra_parts else ""
            return f"Network connection to `{dst}:{port}`{extra_str}"
        if "REGISTRY" in ev.event_type:
            key = d.get("key_path") or d.get("TargetObject") or "N/A"
            return f"Registry activity: `{key}`"
        if "LOGON" in ev.event_type:
            return f"Logon activity for `{ev.user_account or 'unknown user'}` from `{ev.host_ip or 'unknown host'}`"
        return f"Activity recorded by `{ev.source_entity}`"
