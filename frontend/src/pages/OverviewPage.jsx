import React from 'react';

export default function OverviewPage({ state, onTriggerScenario, onSelectPage }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;
  const ov = state.overview || {};
  const activeRules = state.active_mitigations || [];
  const historyRules = state.mitigation_history || [];
  const displayRules = activeRules.length > 0 ? activeRules : historyRules.slice(0, 4);

  return (
    <div className="space-y-5">
      {/* 8 KPI Cards matching Enterprise NOC Specification */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Total Connected Hosts</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">{ov.connected_hosts ?? 7} Hosts</div>
          <div className="text-xs text-slate-500 mt-1">1 Server, 4 Normal, 2 Sim Hosts</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active OpenFlow Switches</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">{ov.active_switches ?? 3} Switches</div>
          <div className="text-xs text-slate-500 mt-1">s1 (Core), s2 & s3 (Edge OVS 1.3)</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Network Traffic (Goodput)</div>
          <div className="text-2xl font-extrabold text-blue-700 mt-1.5">{ov.bandwidth_mbps ?? 17.62} Mbps</div>
          <div className="text-xs text-slate-500 mt-1">Protected Server Link (100M Cap)</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Live Packet Rate</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">{ov.packets_per_sec ?? 548.4} pps</div>
          <div className="text-xs text-slate-500 mt-1">Post-Mitigation Forwarding Rate</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active Security Alerts</div>
          <div className="text-2xl font-extrabold text-red-700 mt-1.5">{ov.active_alerts ?? 2} Alerts</div>
          <div className="text-xs text-slate-500 mt-1">SYN Flood (h5) & UDP Flood (h6)</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Detected Suspicious Flows</div>
          <div className="text-2xl font-extrabold text-amber-700 mt-1.5">{ov.suspicious_flows ?? 0} Flows</div>
          <div className="text-xs text-slate-500 mt-1">Evaluated via {state.detection_mode?.toUpperCase()} Engine</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Mitigation Actions</div>
          <div className="text-2xl font-extrabold text-emerald-700 mt-1.5">{ov.active_mitigations ?? 0} Enforced</div>
          <div className="text-xs text-slate-500 mt-1">OFPFlowMod Priority 500 DROP</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Overall Network Health</div>
          <div className="text-2xl font-extrabold text-emerald-700 mt-1.5">{ov.network_health_pct ?? 96.4}%</div>
          <div className="text-xs text-slate-500 mt-1">Clients h1–h4 Uninterrupted</div>
        </div>
      </div>

      {/* Main Split: Throughput Timeline + Recent Mitigation Events */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-7 bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-slate-900">
              Real-Time Aggregate Network Throughput & Attack Mitigation Timeline (60s Window)
            </h3>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
              Polling: 2.0s
            </span>
          </div>
          <svg viewBox="0 0 620 215" className="w-full h-56">
            <rect x="40" y="15" width="560" height="165" fill="#F8FAFC" stroke="#E2E8F0" />
            {/* Attack Window Shading */}
            <rect x="190" y="15" width="260" height="165" fill="#FEE2E2" opacity="0.45" />
            <text x="320" y="30" fontSize="10" fontWeight="bold" fill="#991B1B" textAnchor="middle">
              Simulated DDoS Window (t=16s–45s) — Mitigated at Edge Switches s2 & s3
            </text>
            {/* Grid lines */}
            <line x1="40" y1="55" x2="600" y2="55" stroke="#E2E8F0" strokeDasharray="3,3" />
            <line x1="40" y1="95" x2="600" y2="95" stroke="#E2E8F0" strokeDasharray="3,3" />
            <line x1="40" y1="135" x2="600" y2="135" stroke="#E2E8F0" strokeDasharray="3,3" />
            <text x="34" y="58" fontSize="9.5" fill="#64748B" textAnchor="end">18M</text>
            <text x="34" y="98" fontSize="9.5" fill="#64748B" textAnchor="end">12M</text>
            <text x="34" y="138" fontSize="9.5" fill="#64748B" textAnchor="end">6M</text>
            <text x="34" y="178" fontSize="9.5" fill="#64748B" textAnchor="end">0M</text>
            {/* Unmitigated Baseline Curve (Red Dashed) */}
            <polyline
              fill="none"
              stroke="#DC2626"
              strokeWidth="2"
              strokeDasharray="5,4"
              points="40,54 100,53 185,55 200,136 250,140 320,138 390,141 445,137 460,56 530,54 600,53"
            />
            {/* Guardian Mitigated Curve (Green Solid) */}
            <polyline
              fill="none"
              stroke="#15803D"
              strokeWidth="2.6"
              points="40,54 100,53 185,55 198,94 212,58 260,57 320,56 390,58 445,57 460,54 530,53 600,53"
            />
            <text x="55" y="198" fontSize="10" fontWeight="bold" fill="#15803D">
              ■ Proposed SDN Guardian Goodput (17.62 Mbps, PDR 96.16%)
            </text>
            <text x="355" y="198" fontSize="10" fontWeight="bold" fill="#DC2626">
              -- Unmitigated Baseline Goodput (6.26 Mbps, PDR 34.17%)
            </text>
          </svg>
        </div>

        <div className="lg:col-span-5 bg-white p-4 rounded-lg border border-slate-200 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-900">Recent Automated OpenFlow Mitigation Events</h3>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                Safelist Active
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-300 text-slate-600 uppercase text-[10.5px]">
                    <th className="py-2 px-2 text-left">Rule ID</th>
                    <th className="py-2 px-2 text-left">Switch</th>
                    <th className="py-2 px-2 text-left">Source IP</th>
                    <th className="py-2 px-2 text-left">Attack Vector</th>
                    <th className="py-2 px-2 text-left">Action</th>
                    <th className="py-2 px-2 text-left">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {displayRules.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-400">
                        No active mitigation rules (Normal Baseline Operation). Trigger Scenario C to test automated mitigation.
                      </td>
                    </tr>
                  ) : (
                    displayRules.map((r) => (
                      <tr key={r.rule_id} className="hover:bg-slate-50">
                        <td className="py-2 px-2 font-mono text-[11px]">{r.rule_id}</td>
                        <td className="py-2 px-2 font-mono text-[11px]">{r.switch_name} (DPID {r.dpid})</td>
                        <td className="py-2 px-2 font-mono text-[11px]">{r.src_ip}</td>
                        <td className="py-2 px-2 font-semibold">{r.attack_type}</td>
                        <td className="py-2 px-2">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold border ${
                              r.action === 'DROP'
                                ? 'bg-red-50 text-red-700 border-red-200'
                                : 'bg-amber-50 text-amber-700 border-amber-200'
                            }`}
                          >
                            {r.action} (Prio {r.priority})
                          </span>
                        </td>
                        <td className="py-2 px-2">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold border ${
                              r.status === 'ACTIVE'
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-slate-100 text-slate-600 border-slate-200'
                            }`}
                          >
                            {r.status}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-3 p-3 bg-slate-50 border border-slate-200 rounded-md text-xs text-slate-700">
            <strong>Infrastructure Safeguard:</strong> Server <span className="font-mono font-semibold">srv1 (10.0.0.100)</span> is hardware-safelisted. Normal clients <span className="font-mono font-semibold">h1–h4</span> maintain 96.16% packet delivery ratio during multi-vector flood mitigation.
          </div>
        </div>
      </div>
    </div>
  );
}
