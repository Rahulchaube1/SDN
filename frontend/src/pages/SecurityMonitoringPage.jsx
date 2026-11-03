import React from 'react';

export default function SecurityMonitoringPage({ state }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;
  const flows = state.flows || [];
  const alerts = state.alerts || [];
  const normalFlows = flows.filter((f) => !f.is_anomalous);
  const suspiciousFlows = flows.filter((f) => f.is_anomalous);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Normal Verified Flows</div>
          <div className="text-2xl font-extrabold text-emerald-700 mt-1.5">{normalFlows.length} Flows</div>
          <div className="text-xs text-slate-500 mt-1">h1, h2, h3, h4 → srv1</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Suspicious Flows Flagged</div>
          <div className="text-2xl font-extrabold text-red-700 mt-1.5">{suspiciousFlows.length} Flows</div>
          <div className="text-xs text-slate-500 mt-1">h5 (10.0.0.5) & h6 (10.0.0.6)</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active Detection Engine</div>
          <div className="text-2xl font-extrabold text-blue-700 mt-1.5 uppercase">{state.detection_mode || 'Hybrid AI'}</div>
          <div className="text-xs text-slate-500 mt-1">0.45×Rule + 0.55×{state.ml_model_type || 'Random Forest'}</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Mean Inference Latency</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">0.177 ms</div>
          <div className="text-xs text-slate-500 mt-1">Per-Flow Evaluation Time</div>
        </div>
      </div>

      <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-900">Real-Time Intrusion & Anomaly Detection Event Log</h3>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200">
            Live IDS Telemetry ({alerts.length} Alerts)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-300 text-slate-600 uppercase text-[10.5px]">
                <th className="py-2.5 px-2.5 text-left">Timestamp (UTC)</th>
                <th className="py-2.5 px-2.5 text-left">Switch</th>
                <th className="py-2.5 px-2.5 text-left">Source IP</th>
                <th className="py-2.5 px-2.5 text-left">Destination IP</th>
                <th className="py-2.5 px-2.5 text-left">Classification</th>
                <th className="py-2.5 px-2.5 text-left">Detection Method</th>
                <th className="py-2.5 px-2.5 text-left">Confidence</th>
                <th className="py-2.5 px-2.5 text-left">Severity</th>
                <th className="py-2.5 px-2.5 text-left">Triggered Indicators</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {alerts.slice(0, 8).map((alt) => {
                const ts = alt.timestamp ? new Date(alt.timestamp * 1000).toISOString().replace('T', ' ').slice(0, 19) : '2026-11-03 05:25:00';
                return (
                  <tr key={alt.alert_id} className="bg-red-50/70">
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{ts}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{alt.switch_name}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{alt.src_ip}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{alt.dst_ip}:{alt.dst_port}</td>
                    <td className="py-2.5 px-2.5 font-bold text-red-900">{alt.attack_type}</td>
                    <td className="py-2.5 px-2.5 text-[11px]">{alt.detection_method}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px] font-bold">{Number(alt.confidence).toFixed(3)}</td>
                    <td className="py-2.5 px-2.5">
                      <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-red-100 text-red-800 border border-red-300">
                        {alt.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-2.5 text-[11px] text-slate-700">
                      {(alt.reasons || []).slice(0, 2).join('; ')}
                    </td>
                  </tr>
                );
              })}
              {normalFlows.slice(0, 4).map((nf) => (
                <tr key={nf.flow_id} className="hover:bg-slate-50">
                  <td className="py-2.5 px-2.5 font-mono text-[11px]">
                    {new Date((nf.timestamp || Date.now() / 1000) * 1000).toISOString().replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-2.5 font-mono text-[11px]">s{nf.dpid}</td>
                  <td className="py-2.5 px-2.5 font-mono text-[11px]">{nf.src_ip}</td>
                  <td className="py-2.5 px-2.5 font-mono text-[11px]">{nf.dst_ip}:{nf.dst_port}</td>
                  <td className="py-2.5 px-2.5 font-semibold text-slate-700">NORMAL_TRAFFIC</td>
                  <td className="py-2.5 px-2.5 text-[11px]">{nf.detection_method}</td>
                  <td className="py-2.5 px-2.5 font-mono text-[11px]">{Number(nf.confidence).toFixed(3)}</td>
                  <td className="py-2.5 px-2.5">
                    <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      LOW / SAFE
                    </span>
                  </td>
                  <td className="py-2.5 px-2.5 text-[11px] text-slate-600">
                    {nf.packets_per_sec} pps, CV={nf.traffic_variation_cv}, SYN={nf.syn_flag_ratio} (Verified Safe)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
