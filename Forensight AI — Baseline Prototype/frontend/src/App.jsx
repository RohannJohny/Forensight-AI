import React, { useState, useEffect } from "react";
import Sidebar from "./components/Sidebar";
import TopBar from "./components/TopBar";
import GlobalSearchModal from "./components/GlobalSearchModal";
import ExaminerNotesDrawer from "./components/ExaminerNotesDrawer";

// Views across complete investigation lifecycle
import LoginView from "./views/LoginView";
import DashboardView from "./views/DashboardView";
import CasesView from "./views/CasesView";
import EvidenceUploadView from "./views/EvidenceUploadView";
import EvidenceView from "./views/EvidenceView";
import ProcessingStatusView from "./views/ProcessingStatusView";
import ArtifactExplorerView from "./views/ArtifactExplorerView";
import NormalizationView from "./views/NormalizationView";
import TimelineView from "./views/TimelineView";
import AnomalyDetectionView from "./views/AnomalyDetectionView";
import AIAssistantView from "./views/AIAssistantView";
import CorrelationGraphView from "./views/CorrelationGraphView";
import AttackPathView from "./views/AttackPathView";
import ValidationGateView from "./views/ValidationGateView";
import FindingsView from "./views/FindingsView";
import ReportsView from "./views/ReportsView";
import AuditLogView from "./views/AuditLogView";

import {
  getCases,
  getCaseStats,
  getEvidence,
  getTimeline,
  getAttackPath,
  getFindings,
  getReports,
  getAuditLogs,
  runCorrelation,
  reseedDatabase
} from "./services/api";

export default function App() {
  // Session Authentication: Check localStorage or require login
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem("forensight_user");
    return saved ? JSON.parse(saved) : null;
  });

  const [currentTab, setCurrentTab] = useState("dashboard");
  const [cases, setCases] = useState([]);
  const [activeCase, setActiveCase] = useState(null);
  const [stats, setStats] = useState(null);

  const [evidenceList, setEvidenceList] = useState([]);
  const [events, setEvents] = useState([]);
  const [filterParams, setFilterParams] = useState({ search: "", event_type: "", only_anomalous: false });
  const [attackPathData, setAttackPathData] = useState(null);
  const [findings, setFindings] = useState([]);
  const [reports, setReports] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  const [loading, setLoading] = useState(true);
  const [isCorrelating, setIsCorrelating] = useState(false);

  // Global utilities
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [isNotesOpen, setIsNotesOpen] = useState(false);

  // Theme Management: Default to light mode
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem("forensight_theme");
    return saved ? saved : "light";
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("forensight_theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "light" ? "dark" : "light"));
  };

  const handleLoginSuccess = (userData, token) => {
    setUser(userData);
    localStorage.setItem("forensight_user", JSON.stringify(userData));
    localStorage.setItem("forensight_token", token);
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem("forensight_user");
    localStorage.removeItem("forensight_token");
  };

  // Load telemetry for a specific case
  const loadCaseData = async (caseId) => {
    try {
      const [
        statsData,
        evidenceData,
        timelineData,
        attackData,
        findingsData,
        reportsData,
        logsData
      ] = await Promise.all([
        getCaseStats(caseId),
        getEvidence(caseId),
        getTimeline(caseId, filterParams),
        getAttackPath(caseId),
        getFindings(caseId),
        getReports(caseId),
        getAuditLogs(caseId)
      ]);

      setStats(statsData);
      setEvidenceList(evidenceData);
      setEvents(timelineData);
      setAttackPathData(attackData);
      setFindings(findingsData);
      setReports(reportsData);
      setAuditLogs(logsData);
    } catch (err) {
      console.error("Error loading case telemetry:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadAllCases = async () => {
    try {
      const caseList = await getCases();
      setCases(caseList || []);
      return caseList;
    } catch (err) {
      console.error("Error loading case list:", err);
      return [];
    }
  };

  useEffect(() => {
    async function init() {
      try {
        const caseList = await loadAllCases();
        if (caseList && caseList.length > 0) {
          const firstCase = caseList[0];
          setActiveCase(firstCase);
          await loadCaseData(firstCase.case_id);
        } else {
          setLoading(false);
        }
      } catch (err) {
        console.error("Initialization error:", err);
        setLoading(false);
      }
    }
    init();
  }, []);

  const handleSelectCase = async (c) => {
    setActiveCase(c);
    setLoading(true);
    await loadCaseData(c.case_id);
  };

  // Handle timeline filter change
  const handleTimelineFilter = async (newFilters) => {
    setFilterParams(newFilters);
    if (!activeCase) return;
    try {
      const filtered = await getTimeline(activeCase.case_id, newFilters);
      setEvents(filtered);
    } catch (err) {
      console.error("Timeline filtering error:", err);
    }
  };

  // Run AI Correlation
  const handleCorrelate = async () => {
    if (!activeCase) return;
    setIsCorrelating(true);
    try {
      const res = await runCorrelation(activeCase.case_id);
      alert(`Pipeline Correlation Complete! Scanned ${res.events_scanned} events, updated ${res.anomalous_events_flagged} anomalies.`);
      await loadCaseData(activeCase.case_id);
    } catch (err) {
      alert("Correlation failed: " + err.message);
    } finally {
      setIsCorrelating(false);
    }
  };

  // Reset Demo Case
  const handleReseed = async () => {
    if (!confirm("Reset Operation Blackout demo dataset to initial state?")) return;
    setLoading(true);
    try {
      await reseedDatabase();
      const caseList = await loadAllCases();
      if (caseList.length > 0) {
        setActiveCase(caseList[0]);
        await loadCaseData(caseList[0].case_id);
      }
      alert("Demo case dataset successfully reset.");
    } catch (err) {
      alert("Reset failed: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const refreshActiveCase = () => {
    if (activeCase) {
      loadCaseData(activeCase.case_id);
    }
  };

  // If unauthenticated, show secure Login View
  if (!user) {
    return <LoginView onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="app-container">
      {/* Complete Lifecycle Sidebar */}
      <Sidebar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        stats={stats}
        stagesCount={attackPathData?.stages?.length}
        user={user}
        onLogout={handleLogout}
      />

      <div className="main-content">
        {/* Top Header with Case Selector, Search, Notes & Controls */}
        <TopBar
          activeCase={activeCase}
          cases={cases}
          onSelectCase={handleSelectCase}
          onReseed={handleReseed}
          onCorrelate={handleCorrelate}
          isCorrelating={isCorrelating}
          theme={theme}
          toggleTheme={toggleTheme}
          onOpenSearch={() => setIsSearchOpen(true)}
          onOpenNotes={() => setIsNotesOpen(true)}
          currentTab={currentTab}
        />

        {loading ? (
          <div style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            height: "70vh",
            gap: "14px",
            color: "var(--text-muted)"
          }}>
            <div style={{
              width: "36px",
              height: "36px",
              border: "3px solid var(--border)",
              borderTopColor: "var(--primary)",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite"
            }} />
            <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
            <span style={{ fontSize: "14px", fontWeight: "500", color: "var(--text-dim)" }}>
              Loading forensic case telemetry...
            </span>
          </div>
        ) : (
          <>
            {currentTab === "dashboard" && (
              <DashboardView
                stats={stats}
                activeCase={activeCase}
                attackPathData={attackPathData}
                cases={cases}
                setCurrentTab={setCurrentTab}
              />
            )}

            {currentTab === "cases" && (
              <CasesView
                cases={cases}
                activeCase={activeCase}
                onSelectCase={handleSelectCase}
                onRefreshCases={loadAllCases}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "evidence_upload" && (
              <EvidenceUploadView
                activeCase={activeCase}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "evidence" && (
              <EvidenceView
                evidenceList={evidenceList}
                activeCase={activeCase}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "processing" && (
              <ProcessingStatusView
                activeCase={activeCase}
                evidenceList={evidenceList}
                stats={stats}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "artifacts" && (
              <ArtifactExplorerView
                activeCase={activeCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "normalization" && (
              <NormalizationView
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "timeline" && (
              <TimelineView
                events={events}
                activeCase={activeCase}
                onFilterChange={handleTimelineFilter}
                filterParams={filterParams}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "anomaly_detection" && (
              <AnomalyDetectionView
                events={events}
                activeCase={activeCase}
                findings={findings}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "ai_assistant" && (
              <AIAssistantView
                activeCase={activeCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "correlation_graph" && (
              <CorrelationGraphView
                activeCase={activeCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "attack_path" && (
              <AttackPathView
                attackPathData={attackPathData}
                activeCase={activeCase}
                setCurrentTab={setCurrentTab}
              />
            )}

            {currentTab === "validation" && (
              <ValidationGateView
                findings={findings}
                activeCase={activeCase}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "findings" && (
              <FindingsView
                findings={findings}
                activeCase={activeCase}
                attackPathData={attackPathData}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "reports" && (
              <ReportsView
                reports={reports}
                activeCase={activeCase}
                onRefresh={refreshActiveCase}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === "audit_log" && (
              <AuditLogView
                auditLogs={auditLogs}
                activeCase={activeCase}
                onNavigate={setCurrentTab}
              />
            )}
          </>
        )}
      </div>

      {/* Case-Wide Global Search Modal */}
      <GlobalSearchModal
        isOpen={isSearchOpen}
        onClose={() => setIsSearchOpen(false)}
        cases={cases}
        evidenceList={evidenceList}
        events={events}
        findings={findings}
        reports={reports}
        onNavigateToItem={(tab, item) => {
          if (tab === "cases" && item?.case_id) {
            handleSelectCase(item);
          }
          setCurrentTab(tab);
        }}
      />

      {/* Examiner Notes Drawer */}
      <ExaminerNotesDrawer
        isOpen={isNotesOpen}
        onClose={() => setIsNotesOpen(false)}
        activeCase={activeCase}
      />
    </div>
  );
}
