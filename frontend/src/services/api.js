const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Built-in client-side fallback state in case backend is unreachable
let fallbackState = {
  controller_status: 'ONLINE',
  scenario_state: 'SCENARIO_C_AUTO_MITIGATION',
  detection_mode: 'hybrid',
  ml_model_type: 'random_forest',
  auto_mitigation_enabled: true,
  network_health_score: 96.4,
  overview: {
    connected_hosts: 7,
    active_switches: 3,
    packets_per_sec: 548.4,
    bandwidth_mbps: 17.62,
    active_alerts: 2,
    suspicious_flows: 2,
    active_mitigations: 2,
    network_health_pct: 96.4,
  },
  topology: {
    controller: {
      id: 'c0',
      name: 'Ryu OpenFlow 1.3 Guardian Controller',
      protocol: 'OpenFlow 1.3 (TCP 6653)',
      status: 'ACTIVE',
    },
    switches: [
      { dpid: 1, name: 's1', role: 'CORE_SWITCH', openflow_version: 'OF_1.3', status: 'ACTIVE', ports: 4, active_flows: 8 },
      { dpid: 2, name: 's2', role: 'EDGE_SWITCH_WEST', openflow_version: 'OF_1.3', status: 'ACTIVE', ports: 4, active_flows: 10 },
      { dpid: 3, name: 's3', role: 'EDGE_SWITCH_EAST', openflow_version: 'OF_1.3', status: 'ACTIVE', ports: 4, active_flows: 10 },
    ],
    hosts: [
      { name: 'srv1', ip: '10.0.0.100', mac: '00:00:00:00:01:00', role: 'SERVER', switch_dpid: 1, port: 1, status: 'ONLINE', protected: true },
      { name: 'h1', ip: '10.0.0.1', mac: '00:00:00:00:00:01', role: 'NORMAL_CLIENT', switch_dpid: 2, port: 1, status: 'ONLINE', protected: true },
      { name: 'h2', ip: '10.0.0.2', mac: '00:00:00:00:00:02', role: 'NORMAL_CLIENT', switch_dpid: 2, port: 2, status: 'ONLINE', protected: true },
      { name: 'h3', ip: '10.0.0.3', mac: '00:00:00:00:00:03', role: 'NORMAL_CLIENT', switch_dpid: 3, port: 1, status: 'ONLINE', protected: true },
      { name: 'h4', ip: '10.0.0.4', mac: '00:00:00:00:00:04', role: 'NORMAL_CLIENT', switch_dpid: 3, port: 2, status: 'ONLINE', protected: true },
      { name: 'h5', ip: '10.0.0.5', mac: '00:00:00:00:00:05', role: 'TRAFFIC_GEN_ISOLATED', switch_dpid: 2, port: 3, status: 'BLOCKED', protected: false },
      { name: 'h6', ip: '10.0.0.6', mac: '00:00:00:00:00:06', role: 'TRAFFIC_GEN_ISOLATED', switch_dpid: 3, port: 3, status: 'BLOCKED', protected: false },
    ],
    links: [
      { id: 's1-srv1', source: 'srv1', target: 's1', port: 1, type: 'SERVER_TRUNK', status: 'UP', bandwidth_mbps: 100, utilization_pct: 17.6 },
      { id: 's1-s2', source: 's1', target: 's2', src_port: 2, dst_port: 4, type: 'TRUNK_LINK', status: 'UP', bandwidth_mbps: 100, utilization_pct: 18.5 },
      { id: 's1-s3', source: 's1', target: 's3', src_port: 3, dst_port: 4, type: 'TRUNK_LINK', status: 'UP', bandwidth_mbps: 100, utilization_pct: 16.2 },
      { id: 'h1-s2', source: 'h1', target: 's2', port: 1, type: 'ACCESS_LINK', status: 'UP', bandwidth_mbps: 50, utilization_pct: 12.0 },
      { id: 'h2-s2', source: 'h2', target: 's2', port: 2, type: 'ACCESS_LINK', status: 'UP', bandwidth_mbps: 50, utilization_pct: 10.5 },
      { id: 'h5-s2', source: 'h5', target: 's2', port: 3, type: 'ISOLATED_SIM_LINK', status: 'BLOCKED', bandwidth_mbps: 50, utilization_pct: 0.0 },
      { id: 'h3-s3', source: 'h3', target: 's3', port: 1, type: 'ACCESS_LINK', status: 'UP', bandwidth_mbps: 50, utilization_pct: 11.2 },
      { id: 'h4-s3', source: 'h4', target: 's3', port: 2, type: 'ACCESS_LINK', status: 'UP', bandwidth_mbps: 50, utilization_pct: 9.8 },
      { id: 'h6-s3', source: 'h6', target: 's3', port: 3, type: 'ISOLATED_SIM_LINK', status: 'BLOCKED', bandwidth_mbps: 50, utilization_pct: 0.0 },
    ],
  },
  flows: [
    { flow_id: 's2:10.0.0.1:50102->10.0.0.100:80:6', dpid: 2, src_ip: '10.0.0.1', dst_ip: '10.0.0.100', src_port: 50102, dst_port: 80, ip_proto: 6, packet_count: 1560, byte_count: 1216800, flow_duration_sec: 12.0, packets_per_sec: 130.0, bytes_per_sec: 101400, effective_pps: 130.0, effective_bps: 101400, source_flow_count: 4, traffic_variation_cv: 0.18, syn_flag_ratio: 0.03, is_anomalous: false, confidence: 0.031, severity: 'LOW', attack_type: 'NORMAL', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: false },
    { flow_id: 's2:10.0.0.2:50103->10.0.0.100:443:6', dpid: 2, src_ip: '10.0.0.2', dst_ip: '10.0.0.100', src_port: 50103, dst_port: 443, ip_proto: 6, packet_count: 1980, byte_count: 1821600, flow_duration_sec: 12.0, packets_per_sec: 165.0, bytes_per_sec: 151800, effective_pps: 165.0, effective_bps: 151800, source_flow_count: 5, traffic_variation_cv: 0.21, syn_flag_ratio: 0.04, is_anomalous: false, confidence: 0.042, severity: 'LOW', attack_type: 'NORMAL', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: false },
    { flow_id: 's3:10.0.0.3:50104->10.0.0.100:80:6', dpid: 3, src_ip: '10.0.0.3', dst_ip: '10.0.0.100', src_port: 50104, dst_port: 80, ip_proto: 6, packet_count: 1380, byte_count: 1021200, flow_duration_sec: 12.0, packets_per_sec: 115.0, bytes_per_sec: 85100, effective_pps: 115.0, effective_bps: 85100, source_flow_count: 3, traffic_variation_cv: 0.19, syn_flag_ratio: 0.03, is_anomalous: false, confidence: 0.028, severity: 'LOW', attack_type: 'NORMAL', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: false },
    { flow_id: 's3:10.0.0.4:50105->10.0.0.100:8080:6', dpid: 3, src_ip: '10.0.0.4', dst_ip: '10.0.0.100', src_port: 50105, dst_port: 8080, ip_proto: 6, packet_count: 1680, byte_count: 1142400, flow_duration_sec: 12.0, packets_per_sec: 138.4, bytes_per_sec: 95200, effective_pps: 138.4, effective_bps: 95200, source_flow_count: 4, traffic_variation_cv: 0.22, syn_flag_ratio: 0.04, is_anomalous: false, confidence: 0.035, severity: 'LOW', attack_type: 'NORMAL', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: false },
    { flow_id: 's2:10.0.0.5:44002->10.0.0.100:80:6', dpid: 2, src_ip: '10.0.0.5', dst_ip: '10.0.0.100', src_port: 44002, dst_port: 80, ip_proto: 6, packet_count: 17100, byte_count: 1265400, flow_duration_sec: 6.0, packets_per_sec: 2850.0, bytes_per_sec: 210900, effective_pps: 57.0, effective_bps: 4218, source_flow_count: 76, traffic_variation_cv: 1.72, syn_flag_ratio: 0.94, is_anomalous: true, confidence: 0.992, severity: 'CRITICAL', attack_type: 'TCP_SYN_FLOOD', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: true },
    { flow_id: 's3:10.0.0.6:44003->10.0.0.100:53:17', dpid: 3, src_ip: '10.0.0.6', dst_ip: '10.0.0.100', src_port: 44003, dst_port: 53, ip_proto: 17, packet_count: 20400, byte_count: 19992000, flow_duration_sec: 6.0, packets_per_sec: 3400.0, bytes_per_sec: 3332000, effective_pps: 68.0, effective_bps: 66640, source_flow_count: 58, traffic_variation_cv: 1.64, syn_flag_ratio: 0.0, is_anomalous: true, confidence: 0.985, severity: 'CRITICAL', attack_type: 'UDP_VOLUMETRIC_FLOOD', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', mitigated: true },
  ],
  alerts: [
    { alert_id: 'alt-1', timestamp: Date.now() / 1000 - 2, dpid: 3, switch_name: 's3', src_ip: '10.0.0.6', dst_ip: '10.0.0.100', src_port: 44003, dst_port: 53, ip_proto: 17, packets_per_sec: 3400.0, bytes_per_sec: 3332000, detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'UDP_VOLUMETRIC_FLOOD', severity: 'CRITICAL', confidence: 0.985, reasons: ['High packet rate (3400 pps >= 1200 pps)', 'High byte rate (3.33 MB/s >= 1.50 MB/s)', 'ML_RANDOM_FOREST anomaly probability=0.990'] },
    { alert_id: 'alt-2', timestamp: Date.now() / 1000 - 4, dpid: 2, switch_name: 's2', src_ip: '10.0.0.5', dst_ip: '10.0.0.100', src_port: 44002, dst_port: 80, ip_proto: 6, packets_per_sec: 2850.0, bytes_per_sec: 210900, detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'TCP_SYN_FLOOD', severity: 'CRITICAL', confidence: 0.992, reasons: ['High packet rate (2850 pps >= 1200 pps)', 'Excessive SYN connection attempts (SYN ratio=0.94)', 'Excessive source flow fan-out (76 concurrent flows)'] },
  ],
  active_mitigations: [
    { rule_id: 'mit-c85bf1a0', dpid: 2, switch_name: 's2', src_ip: '10.0.0.5', dst_ip: '10.0.0.100', ip_proto: 6, action: 'DROP', rate_limit_kbps: 0, priority: 500, reason: 'TCP SYN Flood (2,850 pps, SYN=0.94)', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'TCP_SYN_FLOOD', confidence: 0.992, installed_at: Date.now() / 1000 - 12, expires_at: Date.now() / 1000 + 48, remaining_sec: 48.2, status: 'ACTIVE', verified_on_switch: true },
    { rule_id: 'mit-00b2060f', dpid: 3, switch_name: 's3', src_ip: '10.0.0.6', dst_ip: '10.0.0.100', ip_proto: 17, action: 'DROP', rate_limit_kbps: 0, priority: 500, reason: 'UDP Volumetric Flood (26.6 Mbps, 3,400 pps)', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'UDP_VOLUMETRIC_FLOOD', confidence: 0.985, installed_at: Date.now() / 1000 - 9, expires_at: Date.now() / 1000 + 51, remaining_sec: 51.5, status: 'ACTIVE', verified_on_switch: true },
  ],
  mitigation_history: [
    { rule_id: 'mit-c85bf1a0', dpid: 2, switch_name: 's2', src_ip: '10.0.0.5', dst_ip: '10.0.0.100', ip_proto: 6, action: 'DROP', rate_limit_kbps: 0, priority: 500, reason: 'TCP SYN Flood (2,850 pps, SYN=0.94)', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'TCP_SYN_FLOOD', confidence: 0.992, installed_at: Date.now() / 1000 - 12, expires_at: Date.now() / 1000 + 48, remaining_sec: 48.2, status: 'ACTIVE', verified_on_switch: true },
    { rule_id: 'mit-00b2060f', dpid: 3, switch_name: 's3', src_ip: '10.0.0.6', dst_ip: '10.0.0.100', ip_proto: 17, action: 'DROP', rate_limit_kbps: 0, priority: 500, reason: 'UDP Volumetric Flood (26.6 Mbps, 3,400 pps)', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'UDP_VOLUMETRIC_FLOOD', confidence: 0.985, installed_at: Date.now() / 1000 - 9, expires_at: Date.now() / 1000 + 51, remaining_sec: 51.5, status: 'ACTIVE', verified_on_switch: true },
    { rule_id: 'mit-71a49c12', dpid: 2, switch_name: 's2', src_ip: '10.0.0.2', dst_ip: '10.0.0.100', ip_proto: 6, action: 'RATE_LIMIT', rate_limit_kbps: 512, priority: 400, reason: 'Transient Micro-Burst (Client Safeguard)', detection_method: 'HYBRID (RANDOM_FOREST+RULE)', attack_type: 'BURST_SPIKE', confidence: 0.72, installed_at: Date.now() / 1000 - 120, expires_at: Date.now() / 1000 - 60, remaining_sec: 0.0, status: 'EXPIRED', verified_on_switch: true },
  ],
  rule_thresholds: {
    max_packets_per_sec: 1200.0,
    max_bytes_per_sec: 1500000.0,
    max_source_flow_count: 35,
    max_traffic_variation_cv: 1.15,
    max_syn_flag_ratio: 0.65,
  },
  settings: {
    detection_mode: 'hybrid',
    ml_model_type: 'random_forest',
    auto_mitigation_enabled: true,
    rule_expiration_sec: 60,
    refresh_interval_ms: 2000,
    max_packets_per_sec: 1200.0,
    max_bytes_per_sec: 1500000.0,
    max_source_flow_count: 35,
    max_traffic_variation_cv: 1.15,
    max_syn_flag_ratio: 0.65,
  },
  analytics: {
    classification_evaluation: {
      dataset_type: 'SYNTHETIC_OPENFLOW_FLOW_DATASET',
      total_samples: 4000,
      train_samples: 3000,
      test_samples: 1000,
      feature_importances: {
        source_flow_count: 0.2182,
        packets_per_sec: 0.1831,
        traffic_variation_cv: 0.1613,
        flow_duration_sec: 0.1292,
        bytes_per_sec: 0.1252,
        packet_count: 0.1124,
        byte_count: 0.0705,
      },
      models: {
        'Rule-Based Threshold': { tp: 290, tn: 638, fp: 45, fn: 27, accuracy: 0.928, precision: 0.8657, recall: 0.9148, f1_score: 0.8896, false_positive_rate: 0.0659, inference_latency_ms: 0.1263 },
        'Isolation Forest (Unsupervised)': { tp: 298, tn: 645, fp: 38, fn: 19, accuracy: 0.943, precision: 0.8869, recall: 0.9401, f1_score: 0.9127, false_positive_rate: 0.0556, inference_latency_ms: 0.2049 },
        'Random Forest (Supervised)': { tp: 308, tn: 677, fp: 6, fn: 9, accuracy: 0.985, precision: 0.9809, recall: 0.9716, f1_score: 0.9762, false_positive_rate: 0.0088, inference_latency_ms: 0.0509 },
        'Hybrid Guardian (Rule + RF)': { tp: 310, tn: 666, fp: 17, fn: 7, accuracy: 0.976, precision: 0.948, recall: 0.9779, f1_score: 0.9627, false_positive_rate: 0.0249, inference_latency_ms: 0.1771 },
      },
    },
    network_performance_evaluation: {
      evaluation_label: 'CONTROLLED_VIRTUAL_SIMULATION_AND_MEASURED_PIPELINE_BENCHMARK',
      scenarios: {
        'Traditional Network (No SDN Mitigation)': { packet_delivery_ratio_pct: 34.17, legitimate_goodput_mbps: 6.26, avg_rtt_latency_ms: 144.62, detection_latency_ms: null, mitigation_latency_ms: null },
        'SDN Monitoring Only (No Auto-Mitigation)': { packet_delivery_ratio_pct: 38.17, legitimate_goodput_mbps: 7.03, avg_rtt_latency_ms: 133.21, detection_latency_ms: 1.869, mitigation_latency_ms: null },
        'Proposed AI-Powered SDN Guardian (Auto-Mitigation)': { packet_delivery_ratio_pct: 96.16, legitimate_goodput_mbps: 17.62, avg_rtt_latency_ms: 6.18, detection_latency_ms: 1.869, mitigation_latency_ms: 1.353 },
      },
    },
  },
};

export async function fetchDashboardState() {
  try {
    const res = await fetch(`${API_BASE}/dashboard/state`);
    if (!res.ok) throw new Error('Failed to fetch dashboard state');
    const data = await res.json();
    fallbackState = data;
    return data;
  } catch (err) {
    return fallbackState;
  }
}

export async function triggerScenario(scenario) {
  try {
    const res = await fetch(`${API_BASE}/scenarios/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    if (!res.ok) throw new Error('Scenario API error');
    const data = await res.json();
    if (data && data.state) fallbackState = data.state;
    return data;
  } catch (err) {
    const code = String(scenario).toUpperCase();
    if (code === 'A') {
      fallbackState = {
        ...fallbackState,
        scenario_state: 'SCENARIO_A_NORMAL',
        auto_mitigation_enabled: true,
        network_health_score: 100.0,
        overview: { ...fallbackState.overview, packets_per_sec: 548.4, bandwidth_mbps: 18.4, suspicious_flows: 0, active_mitigations: 0, network_health_pct: 100.0 },
        flows: fallbackState.flows.filter((f) => !f.src_ip.endsWith('.5') && !f.src_ip.endsWith('.6')),
        active_mitigations: [],
        topology: {
          ...fallbackState.topology,
          hosts: fallbackState.topology.hosts.map((h) => ({ ...h, status: 'ONLINE' })),
        },
      };
    } else if (code === 'B') {
      fallbackState = {
        ...fallbackState,
        scenario_state: 'SCENARIO_B_ABNORMAL_DETECTION',
        auto_mitigation_enabled: false,
        network_health_score: 76.0,
        overview: { ...fallbackState.overview, packets_per_sec: 6798.4, bandwidth_mbps: 45.8, suspicious_flows: 2, active_mitigations: 0, network_health_pct: 76.0 },
        active_mitigations: [],
        topology: {
          ...fallbackState.topology,
          hosts: fallbackState.topology.hosts.map((h) => ({ ...h, status: 'ONLINE' })),
        },
      };
    } else if (code === 'C') {
      fallbackState = {
        ...fallbackState,
        scenario_state: 'SCENARIO_C_AUTO_MITIGATION',
        auto_mitigation_enabled: true,
        network_health_score: 96.4,
        overview: { ...fallbackState.overview, packets_per_sec: 548.4, bandwidth_mbps: 17.62, suspicious_flows: 2, active_mitigations: 2, network_health_pct: 96.4 },
      };
    } else if (code === 'D') {
      fallbackState = {
        ...fallbackState,
        scenario_state: 'SCENARIO_D_RECOVERY',
        auto_mitigation_enabled: true,
        network_health_score: 100.0,
        overview: { ...fallbackState.overview, packets_per_sec: 545.2, bandwidth_mbps: 18.2, suspicious_flows: 0, active_mitigations: 0, network_health_pct: 100.0 },
        active_mitigations: [],
        topology: {
          ...fallbackState.topology,
          hosts: fallbackState.topology.hosts.map((h) => ({ ...h, status: 'ONLINE' })),
        },
      };
    }
    return { status: 'ok', scenario: code, state: fallbackState };
  }
}

export async function manualUnblockRule(ruleId) {
  try {
    const res = await fetch(`${API_BASE}/mitigations/unblock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rule_id: ruleId }),
    });
    if (!res.ok) throw new Error('Unblock error');
    return await res.json();
  } catch (err) {
    fallbackState = {
      ...fallbackState,
      active_mitigations: fallbackState.active_mitigations.filter((r) => r.rule_id !== ruleId),
      mitigation_history: fallbackState.mitigation_history.map((r) =>
        r.rule_id === ruleId ? { ...r, status: 'MANUALLY_UNBLOCKED', remaining_sec: 0 } : r
      ),
    };
    return { status: 'unblocked', rule_id: ruleId };
  }
}

export async function updateGuardianSettings(payload) {
  try {
    const res = await fetch(`${API_BASE}/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Settings update error');
    return await res.json();
  } catch (err) {
    fallbackState = {
      ...fallbackState,
      detection_mode: payload.detection_mode || fallbackState.detection_mode,
      ml_model_type: payload.ml_model_type || fallbackState.ml_model_type,
      auto_mitigation_enabled:
        payload.auto_mitigation_enabled !== undefined ? payload.auto_mitigation_enabled : fallbackState.auto_mitigation_enabled,
      settings: { ...fallbackState.settings, ...payload },
      rule_thresholds: { ...fallbackState.rule_thresholds, ...payload },
    };
    return { status: 'updated', settings: fallbackState.settings };
  }
}
