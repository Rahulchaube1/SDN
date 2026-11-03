import React from 'react';

const NAV_ITEMS = [
  { id: 'overview', label: '1. Overview', badge: 'NOC' },
  { id: 'topology', label: '2. Live Network Topology', badge: 'OF 1.3' },
  { id: 'traffic', label: '3. Traffic Monitoring', badge: 'Flows' },
  { id: 'security', label: '4. Security Monitoring', badge: 'IDS/ML' },
  { id: 'mitigation', label: '5. Threat Mitigation', badge: 'FlowMod' },
  { id: 'analytics', label: '6. Analytics', badge: 'Eval' },
  { id: 'settings', label: '7. Settings', badge: 'Config' },
];

const SCENARIOS = [
  { code: 'A', label: 'Scenario A', desc: 'Normal Baseline', match: 'SCENARIO_A_NORMAL' },
  { code: 'B', label: 'Scenario B', desc: 'Attack Detection', match: 'SCENARIO_B_ABNORMAL_DETECTION' },
  { code: 'C', label: 'Scenario C', desc: 'Auto Mitigation', match: 'SCENARIO_C_AUTO_MITIGATION' },
  { code: 'D', label: 'Scenario D', desc: 'Recovery & Expiry', match: 'SCENARIO_D_RECOVERY' },
];

export default function Sidebar({ activePage, onSelectPage, scenarioState, onTriggerScenario, isBusy }) {
  return (
    <aside className="w-72 bg-white border-r border-slate-200 flex flex-col justify-between min-h-screen shrink-0 select-none">
      <div>
        <div className="p-5 border-b border-slate-200">
          <div className="text-[11px] font-bold uppercase tracking-wider text-blue-700">OpenFlow 1.3 Security NOC</div>
          <h1 className="text-base font-extrabold text-slate-900 mt-1">SDN Network Guardian</h1>
          <p className="text-xs text-slate-500 mt-0.5">AI Traffic & Threat Mitigation</p>
        </div>
        <nav className="p-3 space-y-1">
          {NAV_ITEMS.map((item) => {
            const active = activePage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectPage(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-semibold transition ${
                  active
                    ? 'bg-blue-50 text-blue-700 border border-blue-200 shadow-sm'
                    : 'text-slate-600 hover:bg-slate-100 border border-transparent'
                }`}
              >
                <span>{item.label}</span>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                    active ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-500'
                  }`}
                >
                  {item.badge}
                </span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-4 border-t border-slate-200 bg-slate-50 space-y-3">
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-bold text-slate-900">Active Scenario Simulation</span>
            {isBusy && <span className="text-[10px] text-blue-600 font-semibold animate-pulse">Running...</span>}
          </div>
          <div className="text-[11px] font-mono text-blue-700 bg-blue-50 border border-blue-200 rounded px-2 py-1 mb-2 truncate">
            {scenarioState || 'SCENARIO_C_AUTO_MITIGATION'}
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {SCENARIOS.map((sc) => {
              const isCurrent = scenarioState === sc.match;
              return (
                <button
                  key={sc.code}
                  disabled={isBusy}
                  onClick={() => onTriggerScenario(sc.code)}
                  className={`px-2 py-1.5 text-left rounded border transition ${
                    isCurrent
                      ? 'bg-blue-700 text-white border-blue-700 shadow-sm'
                      : 'bg-white text-slate-800 border-slate-300 hover:bg-blue-50 hover:border-blue-400'
                  }`}
                >
                  <div className="text-[11px] font-bold leading-tight">{sc.label}</div>
                  <div className={`text-[9.5px] leading-tight mt-0.5 ${isCurrent ? 'text-blue-100' : 'text-slate-500'}`}>
                    {sc.desc}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="pt-2 border-t border-slate-200 text-[11px] text-slate-500 leading-relaxed">
          <div className="font-semibold text-slate-700">Team Members:</div>
          <div>Rahul Chaube (RA2311003012372)</div>
          <div>Mayank Shah (RA2311003012388)</div>
          <div>Neha Mallik (RA2311003012393)</div>
          <div className="mt-1 text-[10px] text-slate-400">Controller: Ryu OpenFlow 1.3 (TCP 6653)</div>
        </div>
      </div>
    </aside>
  );
}
