import React, { useState, useEffect } from 'react';

export default function SettingsPage({ state, onSave }) {
  if (!state) return <div className="p-6 text-slate-500">Connecting to SDN Guardian Controller...</div>;

  const s = state.settings || {};
  const rt = state.rule_thresholds || {};

  const [form, setForm] = useState({
    detection_mode: s.detection_mode || state.detection_mode || 'hybrid',
    ml_model_type: s.ml_model_type || state.ml_model_type || 'random_forest',
    auto_mitigation_enabled: s.auto_mitigation_enabled ?? state.auto_mitigation_enabled ?? true,
    rule_expiration_sec: s.rule_expiration_sec ?? 60,
    refresh_interval_ms: s.refresh_interval_ms ?? 2000,
    max_packets_per_sec: rt.max_packets_per_sec ?? s.max_packets_per_sec ?? 1200.0,
    max_bytes_per_sec: rt.max_bytes_per_sec ?? s.max_bytes_per_sec ?? 1500000.0,
    max_source_flow_count: rt.max_source_flow_count ?? s.max_source_flow_count ?? 35,
    max_traffic_variation_cv: rt.max_traffic_variation_cv ?? s.max_traffic_variation_cv ?? 1.15,
    max_syn_flag_ratio: rt.max_syn_flag_ratio ?? s.max_syn_flag_ratio ?? 0.65,
  });

  useEffect(() => {
    setForm({
      detection_mode: s.detection_mode || state.detection_mode || 'hybrid',
      ml_model_type: s.ml_model_type || state.ml_model_type || 'random_forest',
      auto_mitigation_enabled: s.auto_mitigation_enabled ?? state.auto_mitigation_enabled ?? true,
      rule_expiration_sec: s.rule_expiration_sec ?? 60,
      refresh_interval_ms: s.refresh_interval_ms ?? 2000,
      max_packets_per_sec: rt.max_packets_per_sec ?? s.max_packets_per_sec ?? 1200.0,
      max_bytes_per_sec: rt.max_bytes_per_sec ?? s.max_bytes_per_sec ?? 1500000.0,
      max_source_flow_count: rt.max_source_flow_count ?? s.max_source_flow_count ?? 35,
      max_traffic_variation_cv: rt.max_traffic_variation_cv ?? s.max_traffic_variation_cv ?? 1.15,
      max_syn_flag_ratio: rt.max_syn_flag_ratio ?? s.max_syn_flag_ratio ?? 0.65,
    });
  }, [state.detection_mode, state.ml_model_type, state.auto_mitigation_enabled]);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave({
      ...form,
      rule_expiration_sec: Number(form.rule_expiration_sec),
      refresh_interval_ms: Number(form.refresh_interval_ms),
      max_packets_per_sec: Number(form.max_packets_per_sec),
      max_bytes_per_sec: Number(form.max_bytes_per_sec),
      max_source_flow_count: Number(form.max_source_flow_count),
      max_traffic_variation_cv: Number(form.max_traffic_variation_cv),
      max_syn_flag_ratio: Number(form.max_syn_flag_ratio),
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
            <h3 className="text-sm font-bold text-slate-900">Rule-Based Traffic Threshold Configuration</h3>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
              Live Hot-Reload
            </span>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Max Packet Rate Threshold (PPS)</label>
            <input
              type="number"
              step="50"
              value={form.max_packets_per_sec}
              onChange={(e) => setForm({ ...form, max_packets_per_sec: e.target.value })}
              className="w-44 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Max Byte Rate Threshold (BPS)</label>
            <input
              type="number"
              step="50000"
              value={form.max_bytes_per_sec}
              onChange={(e) => setForm({ ...form, max_bytes_per_sec: e.target.value })}
              className="w-44 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Max Concurrent Flows per Source IP</label>
            <input
              type="number"
              value={form.max_source_flow_count}
              onChange={(e) => setForm({ ...form, max_source_flow_count: e.target.value })}
              className="w-44 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Traffic Spike Variation Coefficient (CV)</label>
            <input
              type="number"
              step="0.05"
              value={form.max_traffic_variation_cv}
              onChange={(e) => setForm({ ...form, max_traffic_variation_cv: e.target.value })}
              className="w-44 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>

          <div className="flex items-center justify-between py-2 text-xs">
            <label className="font-medium text-slate-700">TCP SYN Flag Flood Ratio Threshold</label>
            <input
              type="number"
              step="0.05"
              min="0.1"
              max="1.0"
              value={form.max_syn_flag_ratio}
              onChange={(e) => setForm({ ...form, max_syn_flag_ratio: e.target.value })}
              className="w-44 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>
        </div>

        <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2.5">
            <h3 className="text-sm font-bold text-slate-900">AI Engine & OpenFlow Mitigation Policy</h3>
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
              Active Policy
            </span>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Active Detection Mode</label>
            <select
              value={form.detection_mode}
              onChange={(e) => setForm({ ...form, detection_mode: e.target.value })}
              className="w-48 px-2.5 py-1.5 font-mono text-xs border border-slate-300 rounded bg-white focus:outline-none focus:border-blue-600"
            >
              <option value="hybrid">HYBRID (Rule + ML)</option>
              <option value="ml">ML ONLY</option>
              <option value="rule">RULE-BASED ONLY</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Selected Machine Learning Classifier</label>
            <select
              value={form.ml_model_type}
              onChange={(e) => setForm({ ...form, ml_model_type: e.target.value })}
              className="w-48 px-2.5 py-1.5 font-mono text-xs border border-slate-300 rounded bg-white focus:outline-none focus:border-blue-600"
            >
              <option value="random_forest">Random Forest (35 Trees)</option>
              <option value="isolation_forest">Isolation Forest (65 iTrees)</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Automated OpenFlow Threat Mitigation</label>
            <select
              value={form.auto_mitigation_enabled ? 'true' : 'false'}
              onChange={(e) => setForm({ ...form, auto_mitigation_enabled: e.target.value === 'true' })}
              className="w-48 px-2.5 py-1.5 font-mono text-xs border border-slate-300 rounded bg-white focus:outline-none focus:border-blue-600"
            >
              <option value="true">ENABLED (OFPFlowMod)</option>
              <option value="false">DISABLED (Alert Only)</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-100 text-xs">
            <label className="font-medium text-slate-700">Temporary Mitigation Hard Timeout (sec)</label>
            <input
              type="number"
              value={form.rule_expiration_sec}
              onChange={(e) => setForm({ ...form, rule_expiration_sec: e.target.value })}
              className="w-48 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>

          <div className="flex items-center justify-between py-2 text-xs">
            <label className="font-medium text-slate-700">OpenFlow Telemetry Polling Interval (ms)</label>
            <input
              type="number"
              step="500"
              value={form.refresh_interval_ms}
              onChange={(e) => setForm({ ...form, refresh_interval_ms: e.target.value })}
              className="w-48 px-2.5 py-1.5 text-right font-mono text-xs border border-slate-300 rounded focus:outline-none focus:border-blue-600"
            />
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button
          type="submit"
          className="px-5 py-2.5 rounded-md text-xs font-bold bg-blue-700 text-white hover:bg-blue-800 shadow-sm transition"
        >
          Save & Hot-Reload Controller Policy
        </button>
      </div>
    </form>
  );
}
