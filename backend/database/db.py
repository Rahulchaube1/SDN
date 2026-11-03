"""
SQLite Persistence Layer (`db.py`)
Stores:
- Security alerts (`security_alerts`)
- OpenFlow mitigation events (`mitigation_events`)
- Periodic traffic telemetry snapshots (`traffic_metrics`)
- System configuration settings (`system_settings`)
Includes automatic fallback to `/tmp/guardian_sdn.db` if the working directory is mounted
on a filesystem that does not support POSIX file locks (such as FUSE/virtiofs).
"""
import os
import sqlite3
import json
import time
import tempfile
from typing import Dict, Any, List, Optional


class GuardianDatabase:
    """Thread-safe SQLite database manager for SDN Network Guardian."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if os.getenv("VERCEL") or (os.path.exists(db_dir) and not os.access(db_dir, os.W_OK)):
            self.db_path = os.path.join(tempfile.gettempdir(), os.path.basename(db_path))
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
            self.init_schema()
        except (sqlite3.OperationalError, OSError, PermissionError):
            # Fallback to system temp dir if current mount is read-only or does not support locks (e.g., serverless/FUSE)
            self.db_path = os.path.join(tempfile.gettempdir(), os.path.basename(db_path))
            self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=MEMORY;")
        conn.execute("PRAGMA synchronous=OFF;")
        return conn

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    dpid INTEGER NOT NULL,
                    switch_name TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    ip_proto INTEGER,
                    packets_per_sec REAL,
                    bytes_per_sec REAL,
                    detection_method TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasons_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mitigation_events (
                    rule_id TEXT PRIMARY KEY,
                    dpid INTEGER NOT NULL,
                    switch_name TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    ip_proto INTEGER,
                    action TEXT NOT NULL,
                    rate_limit_kbps INTEGER,
                    priority INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    installed_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    verified_on_switch INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    dpid INTEGER NOT NULL,
                    total_pps REAL NOT NULL,
                    total_bps REAL NOT NULL,
                    total_mbps REAL NOT NULL,
                    active_flows INTEGER NOT NULL,
                    suspicious_flows INTEGER NOT NULL,
                    active_mitigations INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)
            conn.execute(
                "INSERT OR REPLACE INTO system_settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                ("_db_writable_check", "true", time.time()),
            )
            conn.commit()

    def insert_alert(self, alert: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_alerts
                (alert_id, timestamp, dpid, switch_name, src_ip, dst_ip, src_port, dst_port, ip_proto,
                 packets_per_sec, bytes_per_sec, detection_method, attack_type, severity, confidence, reasons_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["alert_id"],
                    float(alert["timestamp"]),
                    int(alert["dpid"]),
                    str(alert["switch_name"]),
                    str(alert["src_ip"]),
                    str(alert["dst_ip"]),
                    int(alert.get("src_port", 0)),
                    int(alert.get("dst_port", 80)),
                    int(alert.get("ip_proto", 6)),
                    float(alert.get("packets_per_sec", 0.0)),
                    float(alert.get("bytes_per_sec", 0.0)),
                    str(alert["detection_method"]),
                    str(alert["attack_type"]),
                    str(alert["severity"]),
                    float(alert["confidence"]),
                    json.dumps(alert.get("reasons", [])),
                ),
            )
            conn.commit()

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["reasons"] = json.loads(d.pop("reasons_json", "[]"))
                out.append(d)
            return out

    def upsert_mitigation(self, rule: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO mitigation_events
                (rule_id, dpid, switch_name, src_ip, dst_ip, ip_proto, action, rate_limit_kbps,
                 priority, reason, detection_method, attack_type, confidence, installed_at, expires_at, status, verified_on_switch)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["rule_id"],
                    int(rule["dpid"]),
                    str(rule["switch_name"]),
                    str(rule["src_ip"]),
                    str(rule["dst_ip"]),
                    int(rule.get("ip_proto", 6)),
                    str(rule["action"]),
                    int(rule.get("rate_limit_kbps", 0)),
                    int(rule["priority"]),
                    str(rule["reason"]),
                    str(rule["detection_method"]),
                    str(rule["attack_type"]),
                    float(rule["confidence"]),
                    float(rule["installed_at"]),
                    float(rule["expires_at"]),
                    str(rule["status"]),
                    1 if rule.get("verified_on_switch", True) else 0,
                ),
            )
            conn.commit()

    def get_mitigations(self, status_filter: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if status_filter:
                rows = conn.execute(
                    "SELECT * FROM mitigation_events WHERE status = ? ORDER BY installed_at DESC LIMIT ?",
                    (status_filter, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM mitigation_events ORDER BY installed_at DESC LIMIT ?", (limit,)
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["verified_on_switch"] = bool(d["verified_on_switch"])
                d["remaining_sec"] = max(0.0, round(d["expires_at"] - time.time(), 1)) if d["status"] == "ACTIVE" else 0.0
                out.append(d)
            return out

    def insert_traffic_metric(self, metric: Dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO traffic_metrics
                (timestamp, dpid, total_pps, total_bps, total_mbps, active_flows, suspicious_flows, active_mitigations)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(metric["timestamp"]),
                    int(metric.get("dpid", 1)),
                    float(metric["total_pps"]),
                    float(metric["total_bps"]),
                    float(metric["total_mbps"]),
                    int(metric["active_flows"]),
                    int(metric["suspicious_flows"]),
                    int(metric["active_mitigations"]),
                ),
            )
            conn.commit()

    def save_setting(self, key: str, value: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_settings (key, value_json, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time()),
            )
            conn.commit()

    def load_settings(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value_json FROM system_settings").fetchall()
            return {r["key"]: json.loads(r["value_json"]) for r in rows}
