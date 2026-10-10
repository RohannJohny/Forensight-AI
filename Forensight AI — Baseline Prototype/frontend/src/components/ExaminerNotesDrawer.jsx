import React, { useState } from "react";
import { Edit3, Plus, X, Trash2 } from "lucide-react";

export default function ExaminerNotesDrawer({ isOpen, onClose, activeCase }) {
  const caseId = activeCase?.case_id || "default_case";
  const storageKey = `forensight_notes_${caseId}`;

  const [notes, setNotes] = useState(() => {
    const saved = localStorage.getItem(`forensight_notes_${activeCase?.case_id || "default_case"}`);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return [];
      }
    }
    return [
      {
        id: "note-1",
        tag: "Hypothesis",
        text: "Spearphishing document delivered via external email gateway around 09:14 UTC. Office spawned PowerShell with hidden execution flags.",
        timestamp: "2026-09-02 10:15 UTC",
        author: "Lead Forensic Examiner"
      },
      {
        id: "note-2",
        tag: "Persistence",
        text: "Registry autorun key created under HKCU\\...\\Run\\WindowsUpdate pointing to staged updater.ps1 in C:\\Users\\Public.",
        timestamp: "2026-09-02 11:30 UTC",
        author: "Lead Forensic Examiner"
      }
    ];
  });
  const [newNoteText, setNewNoteText] = useState("");
  const [noteTag, setNoteTag] = useState("Observation");

  const saveNotes = (updated) => {
    setNotes(updated);
    localStorage.setItem(storageKey, JSON.stringify(updated));
  };

  const handleAddNote = () => {
    if (!newNoteText.trim()) return;
    const newEntry = {
      id: `note-${Date.now()}`,
      tag: noteTag,
      text: newNoteText.trim(),
      timestamp: new Date().toUTCString().replace("GMT", "UTC"),
      author: "Rohan Johny"
    };
    saveNotes([newEntry, ...notes]);
    setNewNoteText("");
  };

  const handleDeleteNote = (id) => {
    saveNotes(notes.filter((n) => n.id !== id));
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        style={{
          position: "fixed",
          right: 0,
          top: 0,
          bottom: 0,
          width: "440px",
          maxWidth: "100%",
          height: "100vh",
          maxHeight: "100vh",
          borderRadius: 0,
          boxShadow: "var(--shadow-xl)",
          display: "flex",
          flexDirection: "column",
          gap: "14px",
          padding: "20px"
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border)", paddingBottom: "12px" }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <Edit3 size={17} color="var(--primary)" />
              <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)" }}>
                Examiner Investigative Notes
              </h3>
            </div>
            <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px" }}>
              Case: {activeCase?.case_number || "FS-2026-001"} • Notes stored persistently
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
            <X size={18} />
          </button>
        </div>

        {/* New Note Form */}
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{ display: "flex", gap: "8px" }}>
            <select
              className="input-control"
              style={{ fontSize: "11.5px", padding: "4px 8px" }}
              value={noteTag}
              onChange={(e) => setNoteTag(e.target.value)}
            >
              <option value="Observation">Observation</option>
              <option value="Hypothesis">Hypothesis</option>
              <option value="Persistence">Persistence Lead</option>
              <option value="Exfiltration">Exfiltration</option>
              <option value="Legal Question">Legal / Custody</option>
            </select>
          </div>

          <textarea
            className="input-control"
            rows={3}
            style={{ width: "100%", resize: "vertical", fontSize: "12.5px" }}
            placeholder="Document investigative observation, reasoning, or anomaly lead..."
            value={newNoteText}
            onChange={(e) => setNewNoteText(e.target.value)}
          />

          <button
            className="btn btn-primary"
            style={{ fontSize: "12px", padding: "6px 12px", alignSelf: "flex-end" }}
            onClick={handleAddNote}
            disabled={!newNoteText.trim()}
          >
            <Plus size={13} /> Add Note
          </button>
        </div>

        {/* Notes Stream */}
        <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "10px" }}>
          {notes.length === 0 ? (
            <div style={{ textAlign: "center", padding: "40px 0", color: "var(--text-muted)", fontSize: "12.5px" }}>
              No notes recorded for this case yet. Use the input above to document observations.
            </div>
          ) : (
            notes.map((n) => (
              <div
                key={n.id}
                style={{
                  backgroundColor: "var(--bg-card-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 12px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="badge-tag badge-cyan" style={{ fontSize: "9.5px" }}>
                    {n.tag}
                  </span>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span className="mono" style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                      {n.timestamp}
                    </span>
                    <button
                      onClick={() => handleDeleteNote(n.id)}
                      style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", padding: "2px" }}
                      title="Delete note"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>

                <div style={{ fontSize: "12.5px", color: "var(--text-main)", lineHeight: "1.5", whiteSpace: "pre-wrap" }}>
                  {n.text}
                </div>

                <div style={{ fontSize: "10.5px", color: "var(--text-muted)", textAlign: "right" }}>
                  Examiner: {n.author}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
