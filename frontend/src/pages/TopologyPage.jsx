import React from 'react';

export default function TopologyPage({ state }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;
  const hosts = state.topology?.hosts || [];
  const hostMap = {};
  hosts.forEach((h) => {
    hostMap[h.name] = h;
  });

  const h5Blocked = hostMap.h5?.status === 'BLOCKED' || (state.active_mitigations || []).some((r) => r.src_ip === '10.0.0.5');
  const h6Blocked = hostMap.h6?.status === 'BLOCKED' || (state.active_mitigations || []).some((r) => r.src_ip === '10.0.0.6');

  const inventoryRows = [
    { id: 's1-srv1', endpoints: 's1:p1 ↔ srv1 (10.0.0.100)', type: 'SERVER_TRUNK', cap: '100 Mbps', util: '17.6%', status: 'UP', blocked: false },
    { id: 's1-s2', endpoints: 's1:p2 ↔ s2:p4', type: 'INTER_SWITCH', cap: '100 Mbps', util: '18.5%', status: 'UP', blocked: false },
    { id: 's1-s3', endpoints: 's1:p3 ↔ s3:p4', type: 'INTER_SWITCH', cap: '100 Mbps', util: '16.2%', status: 'UP', blocked: false },
    { id: 's2-h1', endpoints: 's2:p1 ↔ h1 (10.0.0.1)', type: 'CLIENT_ACCESS', cap: '50 Mbps', util: '9.4%', status: 'FORWARDING', blocked: false },
    { id: 's2-h2', endpoints: 's2:p2 ↔ h2 (10.0.0.2)', type: 'CLIENT_ACCESS', cap: '50 Mbps', util: '11.2%', status: 'FORWARDING', blocked: false },
    {
      id: 's2-h5',
      endpoints: 's2:p3 ↔ h5 (10.0.0.5)',
      type: 'ISOLATED_SIM',
      cap: '50 Mbps',
      util: h5Blocked ? '0.0% (Filtered)' : '3.4%',
      status: h5Blocked ? 'PORT BLOCKED' : 'ONLINE (SIM)',
      blocked: h5Blocked,
    },
    { id: 's3-h3', endpoints: 's3:p1 ↔ h3 (10.0.0.3)', type: 'CLIENT_ACCESS', cap: '50 Mbps', util: '8.8%', status: 'FORWARDING', blocked: false },
    { id: 's3-h4', endpoints: 's3:p2 ↔ h4 (10.0.0.4)', type: 'CLIENT_ACCESS', cap: '50 Mbps', util: '10.1%', status: 'FORWARDING', blocked: false },
    {
      id: 's3-h6',
      endpoints: 's3:p3 ↔ h6 (10.0.0.6)',
      type: 'ISOLATED_SIM',
      cap: '50 Mbps',
      util: h6Blocked ? '0.0% (Filtered)' : '2.8%',
      status: h6Blocked ? 'PORT BLOCKED' : 'ONLINE (SIM)',
      blocked: h6Blocked,
    },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
      <div className="lg:col-span-7 bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-900">
            Live OpenFlow 1.3 Topology Graph (1 Controller, 3 Switches, 7 Hosts)
          </h3>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            LLDP + PacketIn Discovery
          </span>
        </div>

        <svg
          viewBox="0 0 680 390"
          className="w-full h-[390px] bg-slate-50 border border-slate-200 rounded-md"
        >
          {/* Control links */}
          <line x1="210" y1="55" x2="150" y2="165" stroke="#2563EB" strokeWidth="1.6" strokeDasharray="5,4" />
          <line x1="210" y1="55" x2="340" y2="165" stroke="#2563EB" strokeWidth="1.6" strokeDasharray="5,4" />
          <line x1="210" y1="55" x2="530" y2="165" stroke="#2563EB" strokeWidth="1.6" strokeDasharray="5,4" />
          {/* Server link */}
          <line x1="485" y1="55" x2="340" y2="165" stroke="#15803D" strokeWidth="3" />
          {/* Switch trunks */}
          <line x1="150" y1="185" x2="340" y2="185" stroke="#0F172A" strokeWidth="3" />
          <line x1="340" y1="185" x2="530" y2="185" stroke="#0F172A" strokeWidth="3" />
          {/* Host links West */}
          <line x1="150" y1="205" x2="65" y2="315" stroke="#2563EB" strokeWidth="2.2" />
          <line x1="150" y1="205" x2="165" y2="315" stroke="#2563EB" strokeWidth="2.2" />
          <line
            x1="150"
            y1="205"
            x2="265"
            y2="315"
            stroke={h5Blocked ? '#DC2626' : '#F59E0B'}
            strokeWidth="2.4"
            strokeDasharray={h5Blocked ? '4,3' : 'none'}
          />
          {/* Host links East */}
          <line x1="530" y1="205" x2="415" y2="315" stroke="#2563EB" strokeWidth="2.2" />
          <line x1="530" y1="205" x2="515" y2="315" stroke="#2563EB" strokeWidth="2.2" />
          <line
            x1="530"
            y1="205"
            x2="615"
            y2="315"
            stroke={h6Blocked ? '#DC2626' : '#F59E0B'}
            strokeWidth="2.4"
            strokeDasharray={h6Blocked ? '4,3' : 'none'}
          />

          {/* Controller Node */}
          <rect x="115" y="20" width="190" height="46" rx="6" fill="#EFF6FF" stroke="#1D4ED8" strokeWidth="2" />
          <text x="210" y="40" fontSize="11.5" fontWeight="bold" fill="#0F172A" textAnchor="middle">
            Controller c0 (Ryu OF 1.3)
          </text>
          <text x="210" y="55" fontSize="9.5" fill="#1D4ED8" textAnchor="middle">
            127.0.0.1:6653 | ACTIVE
          </text>

          {/* Server Node */}
          <rect x="395" y="20" width="185" height="46" rx="6" fill="#F0FDF4" stroke="#15803D" strokeWidth="2" />
          <text x="487" y="40" fontSize="11.5" fontWeight="bold" fill="#14532D" textAnchor="middle">
            Server srv1 (Protected)
          </text>
          <text x="487" y="55" fontSize="9.5" fill="#15803D" textAnchor="middle">
            10.0.0.100/24 | 100M UP
          </text>

          {/* Switches */}
          <rect x="85" y="160" width="130" height="48" rx="6" fill="#FFFFFF" stroke="#0F172A" strokeWidth="2" />
          <text x="150" y="181" fontSize="11" fontWeight="bold" fill="#0F172A" textAnchor="middle">
            Switch s2 (Edge W)
          </text>
          <text x="150" y="197" fontSize="9.5" fill="#475569" textAnchor="middle">
            DPID: 0x2 | OF 1.3
          </text>

          <rect x="275" y="160" width="130" height="48" rx="6" fill="#FFFFFF" stroke="#0F172A" strokeWidth="2" />
          <text x="340" y="181" fontSize="11" fontWeight="bold" fill="#0F172A" textAnchor="middle">
            Switch s1 (Core)
          </text>
          <text x="340" y="197" fontSize="9.5" fill="#475569" textAnchor="middle">
            DPID: 0x1 | OF 1.3
          </text>

          <rect x="465" y="160" width="130" height="48" rx="6" fill="#FFFFFF" stroke="#0F172A" strokeWidth="2" />
          <text x="530" y="181" fontSize="11" fontWeight="bold" fill="#0F172A" textAnchor="middle">
            Switch s3 (Edge E)
          </text>
          <text x="530" y="197" fontSize="9.5" fill="#475569" textAnchor="middle">
            DPID: 0x3 | OF 1.3
          </text>

          {/* Hosts */}
          <rect x="20" y="310" width="90" height="52" rx="5" fill="#FFFFFF" stroke="#2563EB" strokeWidth="1.8" />
          <text x="65" y="330" fontSize="10.5" fontWeight="bold" textAnchor="middle">Client h1</text>
          <text x="65" y="346" fontSize="9" fill="#475569" textAnchor="middle">10.0.0.1 (UP)</text>

          <rect x="120" y="310" width="90" height="52" rx="5" fill="#FFFFFF" stroke="#2563EB" strokeWidth="1.8" />
          <text x="165" y="330" fontSize="10.5" fontWeight="bold" textAnchor="middle">Client h2</text>
          <text x="165" y="346" fontSize="9" fill="#475569" textAnchor="middle">10.0.0.2 (UP)</text>

          <rect
            x="220"
            y="310"
            width="90"
            height="52"
            rx="5"
            fill={h5Blocked ? '#FEF2F2' : '#FFFBEB'}
            stroke={h5Blocked ? '#DC2626' : '#D97706'}
            strokeWidth="2"
          />
          <text x="265" y="330" fontSize="10.5" fontWeight="bold" fill={h5Blocked ? '#991B1B' : '#92400E'} textAnchor="middle">
            Sim Host h5
          </text>
          <text x="265" y="346" fontSize="9" fill={h5Blocked ? '#DC2626' : '#B45309'} textAnchor="middle">
            10.0.0.5 ({h5Blocked ? 'DROP' : 'SIM'})
          </text>

          <rect x="370" y="310" width="90" height="52" rx="5" fill="#FFFFFF" stroke="#2563EB" strokeWidth="1.8" />
          <text x="415" y="330" fontSize="10.5" fontWeight="bold" textAnchor="middle">Client h3</text>
          <text x="415" y="346" fontSize="9" fill="#475569" textAnchor="middle">10.0.0.3 (UP)</text>

          <rect x="470" y="310" width="90" height="52" rx="5" fill="#FFFFFF" stroke="#2563EB" strokeWidth="1.8" />
          <text x="515" y="330" fontSize="10.5" fontWeight="bold" textAnchor="middle">Client h4</text>
          <text x="515" y="346" fontSize="9" fill="#475569" textAnchor="middle">10.0.0.4 (UP)</text>

          <rect
            x="570"
            y="310"
            width="90"
            height="52"
            rx="5"
            fill={h6Blocked ? '#FEF2F2' : '#FFFBEB'}
            stroke={h6Blocked ? '#DC2626' : '#D97706'}
            strokeWidth="2"
          />
          <text x="615" y="330" fontSize="10.5" fontWeight="bold" fill={h6Blocked ? '#991B1B' : '#92400E'} textAnchor="middle">
            Sim Host h6
          </text>
          <text x="615" y="346" fontSize="9" fill={h6Blocked ? '#DC2626' : '#B45309'} textAnchor="middle">
            10.0.0.6 ({h6Blocked ? 'DROP' : 'SIM'})
          </text>
        </svg>
      </div>

      <div className="lg:col-span-5 bg-white p-4 rounded-lg border border-slate-200 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-slate-900">Switch & Link Status Inventory</h3>
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            All Links Monitored
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-300 text-slate-600 uppercase text-[10.5px]">
                <th className="py-2 px-2 text-left">Link ID</th>
                <th className="py-2 px-2 text-left">Endpoints</th>
                <th className="py-2 px-2 text-left">Type</th>
                <th className="py-2 px-2 text-left">Capacity</th>
                <th className="py-2 px-2 text-left">Utilization</th>
                <th className="py-2 px-2 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {inventoryRows.map((row) => (
                <tr key={row.id} className="hover:bg-slate-50">
                  <td className="py-2.5 px-2 font-mono text-[11px]">{row.id}</td>
                  <td className="py-2.5 px-2 font-mono text-[11px]">{row.endpoints}</td>
                  <td className="py-2.5 px-2 text-[11px]">{row.type}</td>
                  <td className="py-2.5 px-2">{row.cap}</td>
                  <td className="py-2.5 px-2 font-mono text-[11px]">{row.util}</td>
                  <td className="py-2.5 px-2">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10.5px] font-semibold border ${
                        row.blocked
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}
                    >
                      {row.status}
                    </span>
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
