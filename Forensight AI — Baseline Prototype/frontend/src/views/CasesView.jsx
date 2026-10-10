import React, { useState } from "react";
import {
  FolderCheck,
  Plus,
  Search,
  Clock,
  ArrowRight,
  X,
  HardDrive
} from "lucide-react";
import { createCase } from "../services/api";

export default function CasesView({ cases, activeCase, onSelectCase, onRefreshCases, onNavigate }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);

  // New Case Wizard Form State
  const [caseNumber, setCaseNumber] = useState("FS-2026-002");
  const [caseName, setCaseName] = useState("");
  const [description, setDescription] = useState("");
  const [investigatorName, setInvestigatorName] = useState("Rohan Johny");
  const [priority, setPriority] = useState("High");
  const [classification, setClassification] = useState("Malware");
  const [targetScope, setTargetScope] = useState("Workstations, Domain Controller, Boundary Firewall");

  const classificationOptions = [
    { id: "Malware", label: "Malware Intrusion", desc: "Ransomware, rootkits, trojans, backdoors" },
    { id: "Phishing", label: "Phishing & Spearphishing", desc: "Credential harvesting, weaponized documents" },
    { id: "Data Breach", label: "Data Breach & Exfiltration", desc: "Unauthorized IP access, large archive exfiltration" },
    { id: "Insider Threat", label: "Insider Threat", desc: "Privilege abuse, data destruction, unauthorized copying" },
    { id: "Network Investigation", label: "Network Investigation", desc: "C2 beacons, unauthorized lateral movement, DNS tunneling" },
    { id: "Cybercrime", label: "Financial / Cybercrime", desc: "Wire fraud, BEC, unauthorized ledger transactions" },
    { id: "Data Recovery", label: "Forensic Data Recovery", desc: "Deleted volume carving, corrupted partition reconstruction" }
  ];

  const handleCreateCase = async () => {
    if (!caseNumber.trim() || !caseName.trim()) {
      alert("Please enter a case number and case name.");
      return;
    }

    setSubmitting(true);
    try {
      const fullDescription = `[Classification: ${classification}] [Priority: ${priority}] [Lead Examiner: ${investigatorName}] [Scope: ${targetScope}] ${description}`;
      const newCase = await createCase({
        case_number: caseNumber,
        case_name: caseName,
        description: fullDescription,
        status: "Active"
      });

      await onRefreshCases();
      if (newCase && newCase.case_id) {
        onSelectCase(newCase);
      }
      setShowWizard(false);
      setWizardStep(1);
      // Navigate to Evidence Upload for the newly created case
      if (onNavigate) {
        onNavigate("evidence_upload");
      }
    } catch (err) {
      alert("Failed to initialize case: " + err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const filteredCases = cases?.filter((c) => {
    const matchSearch =
      c.case_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.case_number?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.description?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchStatus = statusFilter === "ALL" || c.status?.toUpperCase() === statusFilter.toUpperCase();
    return matchSearch && matchStatus;
  }) || [];

  return (
    <div style={{ padding: "24px 28px", maxWidth: "1400px", margin: "0 auto", width: "100%" }}>
      {/* Header */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "20px",
        flexWrap: "wrap",
        gap: "12px"
      }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <FolderCheck size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Case Management & Investigations
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Create, classify, search, and manage forensic investigation case containers.
          </p>
        </div>

        <button className="btn btn-primary" onClick={() => setShowWizard(true)}>
          <Plus size={15} />
          New Investigation Case
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="forensic-card" style={{ padding: "14px 18px", marginBottom: "20px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "12px", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ position: "relative", flex: "1 1 320px" }}>
            <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "10px" }} />
            <input
              type="text"
              className="input-control"
              style={{ width: "100%", paddingLeft: "34px" }}
              placeholder="Search by case number, title, or keywords..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <span style={{ fontSize: "12px", color: "var(--text-muted)", fontWeight: "600" }}>STATUS:</span>
            {["ALL", "Active", "Under Investigation", "Closed"].map((st) => (
              <button
                key={st}
                className={`btn ${statusFilter === st ? "btn-primary" : "btn-secondary"}`}
                style={{ fontSize: "11.5px", padding: "4px 10px" }}
                onClick={() => setStatusFilter(st)}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Cases Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: "16px" }}>
        {filteredCases.map((c) => {
          const isActive = activeCase?.case_id === c.case_id;

          return (
            <div
              key={c.case_id}
              className="forensic-card"
              style={{
                borderColor: isActive ? "var(--primary)" : "var(--border)",
                borderLeftWidth: "4px",
                borderLeftColor: isActive ? "var(--primary)" : "var(--border-strong)",
                display: "flex",
                flexDirection: "column",
                justifyContent: "space-between"
              }}
            >
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <span className="mono" style={{ fontSize: "12px", fontWeight: "700", color: "var(--primary-text)" }}>
                      {c.case_number}
                    </span>
                    {isActive && (
                      <span className="badge-tag badge-cyan" style={{ fontSize: "10px", padding: "1px 6px" }}>
                        Active Case
                      </span>
                    )}
                  </div>
                  <span className="badge-tag badge-rose" style={{ fontSize: "10px" }}>
                    {c.status}
                  </span>
                </div>

                <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", marginBottom: "6px" }}>
                  {c.case_name}
                </h3>

                <p style={{
                  fontSize: "12.5px",
                  color: "var(--text-dim)",
                  lineHeight: "1.5",
                  marginBottom: "14px",
                  display: "-webkit-box",
                  WebkitLineClamp: 3,
                  WebkitBoxOrient: "vertical",
                  overflow: "hidden"
                }}>
                  {c.description || "No description provided."}
                </p>
              </div>

              <div>
                <div style={{
                  display: "flex",
                  justifyContent: "space-between",
                  padding: "8px 0",
                  borderTop: "1px solid var(--border-subtle)",
                  fontSize: "11.5px",
                  color: "var(--text-muted)",
                  marginBottom: "12px"
                }}>
                  <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <HardDrive size={13} /> {c.evidence_count || 0} Evidence Items
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                    <Clock size={13} /> {c.event_count || 0} Events
                  </span>
                </div>

                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    className={`btn ${isActive ? "btn-emerald" : "btn-secondary"}`}
                    style={{ flex: 1, fontSize: "12px" }}
                    onClick={() => {
                      onSelectCase(c);
                    }}
                  >
                    {isActive ? "Currently Active" : "Open Case"}
                  </button>
                  <button
                    className="btn btn-primary"
                    style={{ fontSize: "12px", padding: "0 10px" }}
                    onClick={() => {
                      onSelectCase(c);
                      if (onNavigate) onNavigate("dashboard");
                    }}
                    title="Open Dashboard"
                  >
                    <ArrowRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Structured New Case Wizard Modal */}
      {showWizard && (
        <div className="modal-overlay" onClick={() => setShowWizard(false)}>
          <div className="modal-content" style={{ maxWidth: "700px" }} onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid var(--border)",
              paddingBottom: "10px"
            }}>
              <div>
                <h3 style={{ fontSize: "17px", fontWeight: "700", color: "var(--text-main)" }}>
                  New Case Wizard: Step {wizardStep} of 2
                </h3>
                <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  {wizardStep === 1 ? "Case Identification & Priority" : "Case Classification & Investigation Scope"}
                </div>
              </div>
              <button
                onClick={() => setShowWizard(false)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            {wizardStep === 1 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "20px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <div>
                    <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                      CASE NUMBER (ID)
                    </label>
                    <input
                      type="text"
                      className="input-control mono"
                      style={{ width: "100%" }}
                      value={caseNumber}
                      onChange={(e) => setCaseNumber(e.target.value)}
                      placeholder="FS-2026-XXX"
                      required
                    />
                  </div>

                  <div>
                    <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                      INVESTIGATION PRIORITY
                    </label>
                    <select
                      className="input-control"
                      style={{ width: "100%" }}
                      value={priority}
                      onChange={(e) => setPriority(e.target.value)}
                    >
                      <option value="Critical">Critical (Active Intrusion / Ransomware)</option>
                      <option value="High">High (Suspected Data Exfiltration)</option>
                      <option value="Medium">Medium (Internal Compliance / Policy)</option>
                      <option value="Low">Low (Routine Verification)</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                    CASE TITLE / OPERATION NAME
                  </label>
                  <input
                    type="text"
                    className="input-control"
                    style={{ width: "100%" }}
                    value={caseName}
                    onChange={(e) => setCaseName(e.target.value)}
                    placeholder="e.g., Operation Blackout: APT Spearphishing & Data Exfiltration"
                    required
                  />
                </div>

                <div>
                  <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                    LEAD FORENSIC EXAMINER
                  </label>
                  <input
                    type="text"
                    className="input-control"
                    style={{ width: "100%" }}
                    value={investigatorName}
                    onChange={(e) => setInvestigatorName(e.target.value)}
                  />
                </div>

                <div>
                  <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                    EXECUTIVE SUMMARY & BRIEF
                  </label>
                  <textarea
                    className="input-control"
                    rows={3}
                    style={{ width: "100%", resize: "vertical" }}
                    placeholder="Incident summary, victim systems, initial discovery timeline..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginBottom: "20px" }}>
                <div>
                  <label style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-main)", display: "block", marginBottom: "8px" }}>
                    SELECT CASE CLASSIFICATION CATEGORY
                  </label>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                    {classificationOptions.map((opt) => {
                      const isSelected = classification === opt.id;
                      return (
                        <div
                          key={opt.id}
                          onClick={() => setClassification(opt.id)}
                          style={{
                            padding: "10px 12px",
                            borderRadius: "var(--radius-sm)",
                            border: `1px solid ${isSelected ? "var(--primary)" : "var(--border)"}`,
                            backgroundColor: isSelected ? "var(--primary-subtle)" : "var(--bg-card-subtle)",
                            cursor: "pointer",
                            transition: "all 0.15s ease"
                          }}
                        >
                          <div style={{
                            fontSize: "12.5px",
                            fontWeight: "700",
                            color: isSelected ? "var(--primary-text)" : "var(--text-main)"
                          }}>
                            {opt.label}
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                            {opt.desc}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted)", display: "block", marginBottom: "5px" }}>
                    INVESTIGATION SCOPE & TARGET ASSETS
                  </label>
                  <input
                    type="text"
                    className="input-control"
                    style={{ width: "100%" }}
                    value={targetScope}
                    onChange={(e) => setTargetScope(e.target.value)}
                    placeholder="Workstations, file servers, external subnets..."
                  />
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  if (wizardStep === 2) setWizardStep(1);
                  else setShowWizard(false);
                }}
              >
                {wizardStep === 2 ? "Back" : "Cancel"}
              </button>

              <div style={{ display: "flex", gap: "8px" }}>
                {wizardStep === 1 ? (
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      if (!caseName.trim()) {
                        alert("Please enter a case name.");
                        return;
                      }
                      setWizardStep(2);
                    }}
                  >
                    Proceed to Classification <ArrowRight size={14} />
                  </button>
                ) : (
                  <button
                    className="btn btn-primary"
                    onClick={handleCreateCase}
                    disabled={submitting}
                  >
                    {submitting ? "Initializing Case..." : "Create Case & Upload Evidence"}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
