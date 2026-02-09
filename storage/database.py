import sqlite3
import json
import time
import threading
import logging
import os

logger = logging.getLogger("edr.storage")


class Database:
    def __init__(self, db_path="data/edr.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                timestamp REAL NOT NULL,
                data TEXT NOT NULL,
                process_id INTEGER,
                source TEXT DEFAULT 'sensor'
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                threat_score REAL DEFAULT 0,
                source TEXT NOT NULL,
                rule_id TEXT,
                mitre_technique TEXT,
                mitre_tactic TEXT,
                process_pid INTEGER,
                process_name TEXT,
                process_cmdline TEXT,
                description TEXT,
                status TEXT DEFAULT 'open',
                response_action TEXT,
                data TEXT
            );

            CREATE TABLE IF NOT EXISTS processes (
                pid INTEGER NOT NULL,
                ppid INTEGER,
                name TEXT,
                cmdline TEXT,
                username TEXT,
                exe_hash TEXT,
                first_seen REAL,
                last_seen REAL,
                threat_score REAL DEFAULT 0,
                status TEXT DEFAULT 'running',
                PRIMARY KEY (pid, first_seen)
            );

            CREATE TABLE IF NOT EXISTS ioc_database (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                source TEXT,
                description TEXT,
                added_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
            CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_database(ioc_type, value);
        """)
        conn.commit()

    def insert_event(self, event_type, data, process_id=None, source="sensor"):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO events (event_type, timestamp, data, process_id, source) VALUES (?, ?, ?, ?, ?)",
            (event_type, time.time(), json.dumps(data), process_id, source),
        )
        conn.commit()

    def insert_alert(self, alert_data):
        conn = self._get_conn()
        cursor = conn.execute(
            """INSERT INTO alerts (timestamp, severity, threat_score, source, rule_id,
               mitre_technique, mitre_tactic, process_pid, process_name, process_cmdline,
               description, status, response_action, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert_data.get("timestamp", time.time()),
                alert_data.get("severity", "medium"),
                alert_data.get("threat_score", 0),
                alert_data.get("source", "unknown"),
                alert_data.get("rule_id"),
                alert_data.get("mitre_technique"),
                alert_data.get("mitre_tactic"),
                alert_data.get("process_pid"),
                alert_data.get("process_name"),
                alert_data.get("process_cmdline"),
                alert_data.get("description"),
                alert_data.get("status", "open"),
                alert_data.get("response_action"),
                json.dumps(alert_data.get("data", {})),
            ),
        )
        conn.commit()
        return cursor.lastrowid

    def upsert_process(self, proc_info):
        conn = self._get_conn()
        now = time.time()
        existing = conn.execute(
            "SELECT * FROM processes WHERE pid = ? AND status = 'running' ORDER BY first_seen DESC LIMIT 1",
            (proc_info["pid"],),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE processes SET last_seen = ?, threat_score = ? WHERE pid = ? AND first_seen = ?",
                (now, proc_info.get("threat_score", 0), proc_info["pid"], existing["first_seen"]),
            )
        else:
            conn.execute(
                """INSERT INTO processes (pid, ppid, name, cmdline, username, exe_hash, first_seen, last_seen, threat_score, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    proc_info["pid"],
                    proc_info.get("ppid"),
                    proc_info.get("name"),
                    proc_info.get("cmdline"),
                    proc_info.get("username"),
                    proc_info.get("exe_hash"),
                    now,
                    now,
                    proc_info.get("threat_score", 0),
                    "running",
                ),
            )
        conn.commit()

    def mark_process_terminated(self, pid):
        conn = self._get_conn()
        conn.execute(
            "UPDATE processes SET status = 'terminated', last_seen = ? WHERE pid = ? AND status = 'running'",
            (time.time(), pid),
        )
        conn.commit()

    def get_alerts(self, limit=100, offset=0, severity=None, status=None):
        conn = self._get_conn()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_alert_stats(self):
        conn = self._get_conn()
        stats = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM alerts WHERE severity = ? AND status = 'open'",
                (sev,),
            ).fetchone()
            stats[sev] = row["cnt"]

        hourly = conn.execute(
            """SELECT CAST((timestamp / 3600) AS INTEGER) * 3600 as hour,
               COUNT(*) as count FROM alerts
               WHERE timestamp > ? GROUP BY hour ORDER BY hour""",
            (time.time() - 86400,),
        ).fetchall()
        stats["hourly"] = [{"hour": r["hour"], "count": r["count"]} for r in hourly]
        stats["total"] = sum(stats.get(s, 0) for s in ["critical", "high", "medium", "low", "info"])
        return stats

    def get_processes(self, status="running"):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM processes WHERE status = ? ORDER BY last_seen DESC LIMIT 200",
            (status,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_process_tree(self, pid):
        conn = self._get_conn()
        proc = conn.execute(
            "SELECT * FROM processes WHERE pid = ? ORDER BY first_seen DESC LIMIT 1",
            (pid,),
        ).fetchone()
        if not proc:
            return None
        proc = dict(proc)
        children = conn.execute(
            "SELECT * FROM processes WHERE ppid = ? AND status = 'running'",
            (pid,),
        ).fetchall()
        proc["children"] = [dict(c) for c in children]
        return proc

    def get_events_timeline(self, hours=1):
        conn = self._get_conn()
        since = time.time() - (hours * 3600)
        rows = conn.execute(
            """SELECT event_type, CAST((timestamp / 300) AS INTEGER) * 300 as bucket,
               COUNT(*) as count FROM events
               WHERE timestamp > ? GROUP BY event_type, bucket ORDER BY bucket""",
            (since,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_alerts_for_process(self, pid, window=60):
        conn = self._get_conn()
        since = time.time() - window
        rows = conn.execute(
            "SELECT * FROM alerts WHERE process_pid = ? AND timestamp > ?",
            (pid, since),
        ).fetchall()
        return [dict(r) for r in rows]

    def update_alert_status(self, alert_id, status, response_action=None):
        conn = self._get_conn()
        if response_action:
            conn.execute(
                "UPDATE alerts SET status = ?, response_action = ? WHERE id = ?",
                (status, response_action, alert_id),
            )
        else:
            conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        conn.commit()

    def add_ioc(self, ioc_type, value, severity="medium", source="manual", description=""):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO ioc_database (ioc_type, value, severity, source, description, added_at) VALUES (?, ?, ?, ?, ?, ?)",
            (ioc_type, value, severity, source, description, time.time()),
        )
        conn.commit()

    def check_ioc(self, ioc_type, value):
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM ioc_database WHERE ioc_type = ? AND value = ?",
            (ioc_type, value),
        ).fetchone()
        return dict(row) if row else None

    def get_all_iocs(self, ioc_type=None):
        conn = self._get_conn()
        if ioc_type:
            rows = conn.execute("SELECT * FROM ioc_database WHERE ioc_type = ?", (ioc_type,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ioc_database").fetchall()
        return [dict(r) for r in rows]

    def cleanup_old_events(self, retention_hours=24):
        conn = self._get_conn()
        cutoff = time.time() - (retention_hours * 3600)
        conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.commit()
        logger.info("Cleaned up events older than %d hours", retention_hours)

    def get_mitre_coverage(self):
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT mitre_technique, mitre_tactic, COUNT(*) as count
               FROM alerts WHERE mitre_technique IS NOT NULL
               GROUP BY mitre_technique, mitre_tactic"""
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
