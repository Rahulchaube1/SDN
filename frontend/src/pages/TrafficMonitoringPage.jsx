import React from 'react';

export default function TrafficMonitoringPage({ state }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;
  const ov = state.overview || {};
  const flows = state.flows || [];
  const droppedPps = flows
    .filter((f) => f.mitigated)
    .reduce((acc, f) => acc + Math.max(0, (f.packets_per_sec || 0) - (f.effective_pps || 0)), 0);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Live Forwarded Packet Rate</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">{ov.packets_per_sec ?? 548.4} pps</div>
          <div className="text-xs text-slate-500 mt-1">Across s1, s2, s3 Flow Tables</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Bandwidth Utilization</div>
          <div className="text-2xl font-extrabold text-blue-700 mt-1.5">{ov.bandwidth_mbps ?? 17.62} Mbps</div>
          <div className="text-xs text-slate-500 mt-1">Of 100 Mbps Core Trunk Capacity</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Dropped Attack Traffic</div>
          <div className="text-2xl font-extrabold text-red-700 mt-1.5">{Math.round(droppedPps).toLocaleString()} pps</div>
          <div className="text-xs text-slate-500 mt-1">Filtered at Ingress s2:p3 & s3:p3</div>
        </div>
        <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
          <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active OpenFlow Entries</div>
          <div className="text-2xl font-extrabold text-slate-900 mt-1.5">{12 + flows.length} Rules</div>
          <div className="text-xs text-slate-500 mt-1">L2/L3 Forwarding + Priority Drops</div>
        </div>
      </div>

      <div className="bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-900">
            Live Per-Flow OpenFlow 1.3 Counter Table (OFPFlowStatsReply Snapshot)
          </h3>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            Updated every 2.0s
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-300 text-slate-600 uppercase text-[10.5px]">
                <th className="py-2.5 px-2.5 text-left">Switch</th>
                <th className="py-2.5 px-2.5 text-left">Source IP:Port</th>
                <th className="py-2.5 px-2.5 text-left">Destination IP:Port</th>
                <th className="py-2.5 px-2.5 text-left">Proto</th>
                <th className="py-2.5 px-2.5 text-left">Packets</th>
                <th className="py-2.5 px-2.5 text-left">Bytes</th>
                <th className="py-2.5 px-2.5 text-left">Duration (s)</th>
                <th className="py-2.5 px-2.5 text-left">Rate (pps)</th>
                <th className="py-2.5 px-2.5 text-left">Throughput</th>
                <th className="py-2.5 px-2.5 text-left">Flow State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {flows.map((f) => {
                const protoLabel = f.ip_proto === 17 ? 'UDP (17)' : f.ip_proto === 1 ? 'ICMP (1)' : f.syn_flag_ratio > 0.6 ? 'TCP SYN' : 'TCP (6)';
                const mbps = ((f.bytes_per_sec || 0) * 8) / 1e6;
                const tputLabel = mbps >= 1.0 ? `${mbps.toFixed(2)} Mbps` : `${(((f.bytes_per_sec || 0) * 8) / 1e3).toFixed(1)} kbps`;
                return (
                  <tr key={f.flow_id} className={f.is_anomalous ? 'bg-red-50/70' : 'hover:bg-slate-50'}>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">s{f.dpid} (0x{f.dpid})</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{f.src_ip}:{f.src_port}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{f.dst_ip}:{f.dst_port}</td>
                    <td className="py-2.5 px-2.5 font-semibold">{protoLabel}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{Number(f.packet_count || 0).toLocaleString()}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{Number(f.byte_count || 0).toLocaleString()}</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{Number(f.flow_duration_sec || 0).toFixed(1)}s</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{Number(f.packets_per_sec || 0).toLocaleString()} pps</td>
                    <td className="py-2.5 px-2.5 font-mono text-[11px]">{tputLabel}</td>
                    <td className="py-2.5 px-2.5">
                      {f.mitigated ? (
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-red-100 text-red-800 border border-red-300">
                          DROPPED AT s{f.dpid}
                        </span>
                      ) : f.is_anomalous ? (
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-amber-100 text-amber-800 border border-amber-300">
                          FLAGGED ({f.attack_type})
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded-full text-[10.5px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          NORMAL FORWARD
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
