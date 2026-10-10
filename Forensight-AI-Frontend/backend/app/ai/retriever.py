"""Evidence retrieval for the Member 2 AI layer.

This module implements a dependency-free TF-IDF-style lexical retriever with
forensic indicator boosts.

The retriever is evidence-only:
- it ranks events already stored in the case database
- it never creates or invents evidence
- generic words such as "execution" do not independently make an event relevant
- specific forensic indicators receive stronger query-aware weighting
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any, Dict, List, Sequence, Tuple


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{2,}")

_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "that",
    "this",
    "what",
    "show",
    "does",
    "have",
    "been",
    "were",
    "was",
    "are",
    "into",
    "about",
    "case",
    "event",
    "events",
    "activity",
    "activities",
    "evidence",
    "please",
    "give",
    "tell",
    "me",
    "any",
    "related",
    "to",
}

# Generic investigation words should not independently determine relevance.
# They can still contribute to normal TF-IDF similarity.
_GENERIC_QUERY_TERMS = {
    "execution",
    "executions",
    "activity",
    "activities",
    "event",
    "events",
    "investigation",
    "investigative",
    "finding",
    "findings",
    "incident",
    "suspicious",
    "malicious",
    "attack",
    "overview",
    "summary",
    "happened",
}

# Query concepts commonly used in forensic investigation.
# These are retrieval hints only; they do not prove malicious activity.
_CONCEPTS = {
    "powershell": {
        "powershell",
        "powershell.exe",
        "encodedcommand",
        "-enc",
        "iex",
        "downloadstring",
        "DownloadString",
    },
    "persistence": {
        "registry",
        "run",
        "runonce",
        "userinit",
        "persistence",
    },
    "credential": {
        "lsass",
        "mimikatz",
        "sekurlsa",
        "credential",
        "credentials",
        "credential-access",
        "credential_access",
        "sam",
        "procdump",
    },
    "network": {
        "network",
        "connection",
        "connections",
        "dst_ip",
        "destinationip",
        "traffic",
    },
    "exfiltration": {
        "exfiltration",
        "exfiltrat",
        "exfiltrate",
        "exfiltrated",
        "exfiltrating",
        "data_exfiltration",
        "upload",
        "uploaded",
        "outbound_transfer",
    },
    "logon": {
        "logon",
        "login",
        "authentication",
        "4624",
        "4625",
    },
    "execution": {
        "process_create",
        "command_line",
        "4688",
    }
}


def tokenize(value: Any) -> List[str]:
    """Convert a value into normalized retrieval tokens."""
    text = str(value or "").lower()

    return [token for token in _TOKEN_RE.findall(text) if token not in _STOPWORDS]


def _event_text(event: Any) -> str:
    """Build the searchable text representation of one forensic event."""
    details = event.details or {}

    return " ".join(
        [
            str(event.event_type or ""),
            str(event.source_entity or ""),
            str(event.user_account or ""),
            str(event.host_ip or ""),
            str(event.event_id or ""),
            str(details),
        ]
    )


def _tf(tokens: Sequence[str]) -> Dict[str, float]:
    """Calculate normalized term frequency."""
    counts = Counter(tokens)
    total = max(len(tokens), 1)

    return {term: count / total for term, count in counts.items()}


def _query_concepts(q_tokens: Sequence[str]) -> set[str]:
    """Identify forensic concepts explicitly requested by the query."""
    query_tokens = set(q_tokens)
    concepts: set[str] = set()

    for concept, terms in _CONCEPTS.items():
        # A concept is activated only by an actual concept-specific term.
        if query_tokens.intersection(terms):
            concepts.add(concept)

    return concepts


def _strong_query_terms(q_tokens: Sequence[str]) -> set[str]:
    """Return query terms that are specific enough to establish relevance."""
    return {token for token in q_tokens if token not in _GENERIC_QUERY_TERMS}


def _term_variant_match(query_term: str, event_tokens: Sequence[str]) -> bool:
    """Check whether a query indicator matches a forensic token variant.

    Forensic evidence frequently stores executable or field variants such as
    powershell.exe instead of the plain-language term PowerShell.
    """

    query_term = query_term.lower()

    for token in event_tokens:
        token = token.lower()

        if token == query_term:
            return True

        # Executable/file variants:
        if token == f"{query_term}.exe":
            return True

        # Namespace/path variants such as windowspowershell:
        if query_term in token and len(query_term) >= 5:
            return True

    return False

def _matches_exfiltration(event: Any, tokens: Sequence[str] | set[str]) -> bool:
    """Check whether a normalized event matches exfiltration behavioral indicators.

    Combines multiple evidence indicators (e.g. high-volume outbound transfer
    or external/cloud relay destination on a network connection) rather than
    relying on a single generic word.
    Does not treat indicators as proof of malicious exfiltration.
    """
    token_set = set(tokens) if not isinstance(tokens, set) else tokens

    # Explicit exfiltration terminology in event tokens
    if any(
        term in token
        for token in token_set
        for term in ("exfiltration", "exfiltrat", "data_exfil")
    ):
        return True

    details = getattr(event, "details", {})
    if not isinstance(details, dict):
        return False

    event_type = str(getattr(event, "event_type", "")).upper()

    # Extract transferred bytes safely from normalized fields
    bytes_val = (
        details.get("bytes_transferred")
        or details.get("bytes")
        or details.get("bytes_sent")
        or details.get("BytesSent")
        or details.get("size")
        or 0
    )
    try:
        transferred = int(bytes_val)
    except (TypeError, ValueError):
        transferred = 0

    # Combination 1: Network connection with high-volume outbound transfer (> 5MB)
    if event_type in ("NETWORK_CONNECTION", "NETWORK", "NETWORK_FLOW") and transferred > 5_000_000:
        return True

    # Combination 2: External relay / cloud storage channel with outbound data
    sni = str(
        details.get("ssl_sni")
        or details.get("sni")
        or details.get("target_host")
        or ""
    ).lower()
    has_external_channel = any(
        kw in sni
        for kw in (
            "external-relay",
            "cloud-storage",
            "upload",
            "dropbox",
            "mega",
            "transfer.sh",
        )
    )
    if (
        event_type in ("NETWORK_CONNECTION", "NETWORK", "NETWORK_FLOW")
        and has_external_channel
        and transferred > 0
    ):
        return True

    return False


def retrieve_events(
    events: Sequence[Any],
    query: str,
    top_k: int = 8,
) -> List[Tuple[Any, float]]:
    """Return the highest-scoring evidence events for *query*.

    Ranking combines:
    1. TF-IDF cosine similarity
    2. exact strong-query-term matching
    3. forensic concept matching
    4. a small anomaly preference

    Generic investigation words such as "execution" do not independently
    qualify an event as relevant.

    The function only returns events that already exist in the database.
    """

    if not events or not query.strip():
        return []

    documents = [tokenize(_event_text(event)) for event in events]

    q_tokens = tokenize(query)

    if not q_tokens:
        return []

    df = Counter()

    for tokens in documents:
        df.update(set(tokens))

    n_docs = len(documents)

    def vector(tokens: Sequence[str]) -> Dict[str, float]:
        tf = _tf(tokens)

        return {
            term: value * math.log((1 + n_docs) / (1 + df[term])) + 1.0
            for term, value in tf.items()
        }

    q_vec = vector(q_tokens)
    q_norm = math.sqrt(sum(value * value for value in q_vec.values())) or 1.0

    query_concepts = _query_concepts(q_tokens)
    strong_terms = _strong_query_terms(q_tokens)

    ranked: List[Tuple[Any, float]] = []

    for event, tokens in zip(events, documents):
        token_set = set(tokens)

        # -------------------------------------------------------------
        # 1. TF-IDF cosine similarity
        # -------------------------------------------------------------
        d_vec = vector(tokens)

        dot = sum(q_vec.get(term, 0.0) * value for term, value in d_vec.items())

        d_norm = math.sqrt(sum(value * value for value in d_vec.values())) or 1.0

        cosine = dot / (q_norm * d_norm)

        # -------------------------------------------------------------
        # 2. Strong query-term matching
        # -------------------------------------------------------------
        strong_hits = {
            term for term in strong_terms if _term_variant_match(term, tokens)
        }

        # If query specifically asks for exfiltration and this event exhibits exfiltration indicators:
        if (
            any(t in strong_terms for t in ("exfiltration", "exfiltrate", "exfiltrated"))
            and _matches_exfiltration(event, token_set)
        ):
            strong_hits.add("exfiltration")

        # Specific query terms are much more important than generic
        # words such as "execution".
        exact_boost = min(
            0.25,
            len(strong_hits) * 0.10,
        )

        # -------------------------------------------------------------
        # 3. Forensic concept matching
        # -------------------------------------------------------------
        concept_hits = 0

        for concept in query_concepts:
            if concept == "exfiltration":
                if _matches_exfiltration(event, token_set) or token_set.intersection(_CONCEPTS["exfiltration"]):
                    concept_hits += 1
            elif token_set.intersection(_CONCEPTS[concept]):
                concept_hits += 1

        concept_boost = min(
            0.15,
            concept_hits * 0.05,
        )

        # -------------------------------------------------------------
        # 4. Small anomaly preference
        # -------------------------------------------------------------
        anomaly_boost = 0.03 if getattr(event, "is_anomalous", 0) else 0.0

        # -------------------------------------------------------------
        # 5. Precision gate
        # -------------------------------------------------------------
        has_strong_match = bool(strong_hits)
        has_concept_match = False

        for concept in query_concepts:
            if concept == "exfiltration":
                if _matches_exfiltration(event, token_set) or token_set.intersection(_CONCEPTS["exfiltration"]):
                    has_concept_match = True
                    break
            elif token_set.intersection(_CONCEPTS[concept]):
                has_concept_match = True
                break

        # A specific forensic concept match is also considered a valid
        # relevance signal. This handles cases such as:
        # query: "PowerShell"
        # evidence: "powershell.exe"
        if strong_terms and not has_strong_match and not has_concept_match:
            continue

        score = min(
            1.0,
            cosine + exact_boost + concept_boost + anomaly_boost,
        )

        if score >= 0.08:
            ranked.append((event, score))

    ranked.sort(
        key=lambda item: (
            item[1],
            getattr(item[0], "timestamp", None),
        ),
        reverse=True,
    )

    # -----------------------------------------------------------------
    # Broad forensic questions
    # -----------------------------------------------------------------
    #
    # Queries such as:
    #   "What suspicious activities were found?"
    #   "What happened in the investigation?"
    #
    # contain no specific evidence indicator. For those, fall back to
    # explicitly anomalous events already stored in the database.
    #
    # This remains evidence-only.
    # -----------------------------------------------------------------

    broad_terms = {
        "suspicious",
        "malicious",
        "threat",
        "incident",
        "investigation",
        "investigative",
        "activities",
        "activity",
        "findings",
        "finding",
        "overview",
        "summary",
        "happened",
        "attack",
        "compromise",
    }

    if not ranked and set(q_tokens).intersection(broad_terms):
        fallback = [event for event in events if getattr(event, "is_anomalous", 0)]

        fallback.sort(
            key=lambda event: (
                float(
                    getattr(
                        event,
                        "anomaly_score",
                        0.0,
                    )
                ),
                getattr(event, "timestamp", None),
            ),
            reverse=True,
        )

        return [
            (
                event,
                min(
                    0.90,
                    0.55
                    + 0.30
                    * float(
                        getattr(
                            event,
                            "anomaly_score",
                            0.0,
                        )
                    ),
                ),
            )
            for event in fallback[:top_k]
        ]

    return ranked[:top_k]
