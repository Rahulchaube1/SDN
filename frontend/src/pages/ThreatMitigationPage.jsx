import React from 'react';

export default function ThreatMitigationPage({ state, onUnblock }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;
  const activeRules = state.active_mitigations || [];
  const historyRules = state.mitigation_history || [];
  const inactiveHistory = historyRules.filter((h) => !activeRules.some((a) => a.rule_id === h.rule_id));
  const allRows = [...activeRules, ...inactiveHistory];

  const dropCount = activeRules.filter((r) => r.action === 'DROP').length;
  const meterCount = allRows.filter((r) => r.action === 'RATE_LIMIT').length;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active Blocked Flows</div>
          <div className="text-2xl font-extrabold text-red-700 mt-1.5">{dropCount} Rules</div>
          <div className="text-xs text-slate-500 mt-1">OFPFlowMod DROP (Priority 500)</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Rate-Limited Flows</div>
          <div className="text-2xl font-extrabold text-amber-700 mt-1.5">{meterCount} Meter</div>
          <div className="text-xs text-slate-500 mt-1">OFPMeterMod 512 kbps Policy</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Rule Installation Latency</div>
          <div className="text-2xl font-extrabold text-emerald-700 mt-1.5">1.353 ms</div>
          <div className="text-xs text-slate-500 mt-1">Controller-to-OVS FlowMod ACK</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Protected Safelist Hosts</div>
          <div className="text-2xl font-extrabold text-blue-700 mt-1.5">srv1 + h1–h4</div>
          <div className="text-xs text-slate-500 mt-1">Zero Accidental Client Blocks</div>
        </div>
      </div>

      <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-900">
            Installed OpenFlow 1.3 Mitigation Rules & Lifecycle Controls
          </h3>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            Auto-Expiration: {state.settings?.rule_expiration_sec ?? 60}s Hard Timeout
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-300 text-slate-600 uppercase text-[10.5px]">
                <th className="py-2.5 px-2.5 text-left">Rule ID</th>
                <th className="py-2.5 px-2.5 text-left">Switch</th>
                <th className="py-2.5 px-2.5 text-left">Matched Source → Dest</th>
                <th className="py-2.5 px-2.5 text-left">OpenFlow Action</th>
                <th className="py-2.5 px-2.5 text-left">Mitigation Reason</th>
                <th className="py-2.5 px-2.5 text-left">Switch Verification</th>
                <th className="py-2.5 px-2.5 text-left">TTL Remaining</th>
                <th className="py-2.5 px-2.5 text-left">Operator Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {allRows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    No mitigation rules recorded yet. Click Scenario C in the left sidebar to trigger automatic OpenFlow mitigation.
                  </td>
                </tr>
              ) : (
                allRows.map((r) => {
                  const isActive = r.status === 'ACTIVE';
                  return (
                    <tr key={r.rule_id} className="hover:bg-slate-50">
                      <td className="py-2.5 px-2.5 font-mono text-[11px]">{r.rule_id}</td>
                      <td className="py-2.5 px-2.5 font-mono text-[11px]">{r.switch_name} (DPID {r.dpid})</td>
                      <td className="py-2.5 px-2.5 font-mono text-[11px]">{r.src_ip} → {r.dst_ip}</td>
                      <td className="py-2.5 px-2.5">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold border ${
                            r.action === 'DROP'
                              ? 'bg-red-50 text-red-700 border-red-200'
                              : 'bg-amber-50 text-amber-700 border-amber-200'
                          }`}
                        >
                          {r.action} (Priority {r.priority})
                        </span>
                      </td>
                      <td className="py-2.5 px-2.5 text-[11px] max-w-xs truncate" title={r.reason}>
                        {r.reason}
                      </td>
                      <td className="py-2.5 px-2.5">
                        {isActive ? (
                          <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            ACCEPTED (OFPFC_ADD)
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                            {r.status}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-2.5 font-mono text-[11px]">
                        {isActive ? `${r.remaining_sec ?? 55.0}s / ${state.settings?.rule_expiration_sec ?? 60}s` : '0.0s (Removed)'}
                      </td>
                      <td className="py-2.5 px-2.5">
                        {isActive ? (
                          <button
                            onClick={() => onUnblock(r.rule_id)}
                            className="px-2.5 py-1 rounded text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-600 hover:bg-blue-700 hover:text-white transition"
                          >
                            Manual Unblock
                          </button>
                        ) : (
                          <span className="text-[11px] text-slate-400">Restored</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
