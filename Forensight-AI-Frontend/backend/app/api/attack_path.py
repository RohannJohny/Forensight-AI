from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.models import Case, AttackNode, Finding, Event

router = APIRouter(tags=["Attack-Path Reconstruction (Module 5)"])


@router.get("/cases/{case_id}/attack-path", response_model=Dict[str, Any])
def get_reconstructed_attack_path(case_id: str, db: Session = Depends(get_db)):
    """
    Reconstructs the multi-stage attack path mapped to the MITRE ATT&CK kill chain.
    Binds each stage directly to underlying validated forensic events and evidence records.
    """
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    nodes = db.query(AttackNode).filter(AttackNode.case_id == case_id).order_by(AttackNode.stage_order.asc()).all()

    stages = []
    graph_nodes = []
    graph_edges = []

    prev_node_id = None

    for n in nodes:
        finding_data = None
        event_data = None

        if n.finding:
            f = n.finding
            finding_data = {
                "finding_id": f.finding_id,
                "title": f.finding_title,
                "type": f.finding_type,
                "confidence": f.confidence_score,
                "validation_status": f.validation_status,
                "notes": f.investigator_notes
            }
            if f.event:
                ev = f.event
                event_data = {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "source": ev.source_entity,
                    "type": ev.event_type,
                    "user": ev.user_account,
                    "host": ev.host_ip,
                    "details": ev.details
                }

        stage_item = {
            "node_id": n.node_id,
            "stage_order": n.stage_order,
            "stage_name": n.stage_name,
            "mitre_technique": n.mitre_technique,
            "description": n.description,
            "finding": finding_data,
            "evidence_link": event_data
        }
        stages.append(stage_item)

        # Graph node representation
        graph_nodes.append({
            "id": n.node_id,
            "label": f"{n.stage_name}\n({n.mitre_technique.split(':')[0]})",
            "technique": n.mitre_technique,
            "order": n.stage_order,
            "status": finding_data["validation_status"] if finding_data else "Pending"
        })

        # Connect sequential stages
        if prev_node_id:
            graph_edges.append({
                "from": prev_node_id,
                "to": n.node_id,
                "label": "Next Stage"
            })
        prev_node_id = n.node_id

    return {
        "case_id": case_id,
        "case_number": case.case_number,
        "total_stages": len(stages),
        "stages": stages,
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges
        }
    }
