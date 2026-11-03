import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar.jsx';
import OverviewPage from './pages/OverviewPage.jsx';
import TopologyPage from './pages/TopologyPage.jsx';
import TrafficMonitoringPage from './pages/TrafficMonitoringPage.jsx';
import SecurityMonitoringPage from './pages/SecurityMonitoringPage.jsx';
import ThreatMitigationPage from './pages/ThreatMitigationPage.jsx';
import AnalyticsPage from './pages/AnalyticsPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';
import { fetchDashboardState, triggerScenario, manualUnblockRule, updateGuardianSettings } from './services/api.js';

const PAGE_TITLES = {
  overview: 'Page 1: Network Operations & Security Overview',
  topology: 'Page 2: Live OpenFlow 1.3 Network Topology',
  traffic: 'Page 3: Real-Time Flow & Bandwidth Monitoring',
  security: 'Page 4: Intrusion & Anomaly Security Monitoring',
  mitigation: 'Page 5: Automated OpenFlow Threat Mitigation',
  analytics: 'Page 6: ML Classification & Performance Analytics',
  settings: 'Page 7: Detection Thresholds & Controller Settings',
};

export default function App() {
  const [activePage, setActivePage] = useState('overview');
  const [state, setState] = useState(null);
  const [isBusy, setIsBusy] = useState(false);
  const [toast, setToast] = useState(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3200);
  };

  const refresh = async () => {
    try {
      const data = await fetchDashboardState();
      setState(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 2500);
    return () => clearInterval(timer);
  }, []);

  const handleScenario = async (code) => {
    setIsBusy(true);
    try {
      const res = await triggerScenario(code);
      if (res && res.state) {
        setState(res.state);
        showToast(`Triggered Scenario ${code} (${res.state.scenario_state})`);
      }
    } finally {
      setIsBusy(false);
    }
  };

  const handleUnblock = async (ruleId) => {
    setIsBusy(true);
    try {
      await manualUnblockRule(ruleId);
      await refresh();
      showToast(`Removed OpenFlow rule ${ruleId} and restored host forwarding`);
    } finally {
      setIsBusy(false);
    }
  };

  const handleSaveSettings = async (updates) => {
    setIsBusy(true);
    try {
      await updateGuardianSettings(updates);
      await refresh();
      showToast('Controller thresholds & AI detection settings updated');
    } finally {
      setIsBusy(false);
    }
  };

  const ov = state?.overview || {};
  const activeMitCount = state?.active_mitigations?.length ?? ov.active_mitigations ?? 0;

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 overflow-hidden">
      <Sidebar
        activePage={activePage}
        onSelectPage={setActivePage}
        scenarioState={state?.scenario_state || 'SCENARIO_C_AUTO_MITIGATION'}
        onTriggerScenario={handleScenario}
        isBusy={isBusy}
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="h-16 bg-white border-b border-slate-200 px-6 flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-base font-bold text-slate-900">{PAGE_TITLES[activePage]}</h2>
            <p className="text-xs text-slate-500">
              Centralized OpenFlow 1.3 Flow Telemetry | Mode: <span className="font-semibold uppercase text-slate-700">{state?.detection_mode || 'HYBRID'}</span> ({state?.ml_model_type || 'random_forest'}) | Sub-2ms Edge Mitigation
            </p>
          </div>
          <div className="flex items-center gap-2.5">
            {toast && (
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-900 text-white shadow-sm">
                {toast}
              </span>
            )}
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
              Controller: c0 {state?.controller_status || 'ONLINE'} (127.0.0.1:6653)
            </span>
            <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Health: {ov.network_health_pct ?? 96.4}%
            </span>
            <span
              className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                activeMitCount > 0
                  ? 'bg-red-50 text-red-700 border-red-200'
                  : 'bg-slate-100 text-slate-700 border-slate-200'
              }`}
            >
              Active Mitigations: {activeMitCount} {activeMitCount === 1 ? 'Rule' : 'Rules'}
            </span>
          </div>
        </header>

        <main className="flex-1 p-6 overflow-y-auto">
          {activePage === 'overview' && <OverviewPage state={state} onTriggerScenario={handleScenario} onSelectPage={setActivePage} />}
          {activePage === 'topology' && <TopologyPage state={state} onTriggerScenario={handleScenario} />}
          {activePage === 'traffic' && <TrafficMonitoringPage state={state} />}
          {activePage === 'security' && <SecurityMonitoringPage state={state} />}
          {activePage === 'mitigation' && <ThreatMitigationPage state={state} onUnblock={handleUnblock} />}
          {activePage === 'analytics' && <AnalyticsPage state={state} />}
          {activePage === 'settings' && <SettingsPage state={state} onSave={handleSaveSettings} />}
        </main>
      </div>
    </div>
  );
}
