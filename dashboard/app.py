import json
import logging
import time

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

logger = logging.getLogger("edr.dashboard")


class Dashboard:
    def __init__(self, config, database, ensemble, response_engine,
                 feature_pipeline, alert_manager, threat_intel, process_monitor):
        self.config = config.get("dashboard", {})
        self.database = database
        self.ensemble = ensemble
        self.response_engine = response_engine
        self.feature_pipeline = feature_pipeline
        self.alert_manager = alert_manager
        self.threat_intel = threat_intel
        self.process_monitor = process_monitor

        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "edr-poc-secret"
        self.socketio = SocketIO(self.app, async_mode="eventlet", cors_allowed_origins="*")

        self._register_routes()
        self._start_time = time.time()

    def _register_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/api/alerts")
        def api_alerts():
            limit = request.args.get("limit", 100, type=int)
            offset = request.args.get("offset", 0, type=int)
            severity = request.args.get("severity")
            status = request.args.get("status")
            alerts = self.database.get_alerts(limit=limit, offset=offset,
                                              severity=severity, status=status)
            return jsonify(alerts)

        @app.route("/api/alerts/stats")
        def api_alert_stats():
            return jsonify(self.database.get_alert_stats())

        @app.route("/api/processes")
        def api_processes():
            status = request.args.get("status", "running")
            processes = self.database.get_processes(status=status)
            for proc in processes:
                fv = self.feature_pipeline.get_feature_vector(proc["pid"])
                if fv:
                    proc["threat_score"] = float(proc.get("threat_score", 0))
            return jsonify(processes)

        @app.route("/api/process/<int:pid>/tree")
        def api_process_tree(pid):
            tree = self.database.get_process_tree(pid)
            if tree is None:
                return jsonify({"error": "Process not found"}), 404
            return jsonify(tree)

        @app.route("/api/ml/metrics")
        def api_ml_metrics():
            metrics = self.ensemble.get_metrics()
            metrics["threat_intel"] = self.threat_intel.get_stats()
            return jsonify(metrics)

        @app.route("/api/events/timeline")
        def api_events_timeline():
            hours = request.args.get("hours", 1, type=int)
            timeline = self.database.get_events_timeline(hours=hours)
            return jsonify(timeline)

        @app.route("/api/mitre/matrix")
        def api_mitre_matrix():
            from detection.mitre_attack import get_matrix_data
            matrix = get_matrix_data()
            coverage = self.database.get_mitre_coverage()
            coverage_map = {}
            for item in coverage:
                tid = item["mitre_technique"]
                coverage_map[tid] = item["count"]
            return jsonify({"matrix": matrix, "coverage": coverage_map})

        @app.route("/api/response/kill/<int:pid>", methods=["POST"])
        def api_kill_process(pid):
            result = self.response_engine.kill_process(pid, reason="Dashboard manual kill")
            return jsonify(result)

        @app.route("/api/response/quarantine", methods=["POST"])
        def api_quarantine():
            data = request.get_json() or {}
            path = data.get("path", "")
            if not path:
                return jsonify({"error": "No path provided"}), 400
            result = self.response_engine.quarantine_file(path, reason="Dashboard quarantine")
            return jsonify(result)

        @app.route("/api/response/log")
        def api_response_log():
            return jsonify(self.response_engine.get_action_log())

        @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
        def api_acknowledge_alert(alert_id):
            self.alert_manager.acknowledge_alert(alert_id)
            return jsonify({"status": "acknowledged"})

        @app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
        def api_resolve_alert(alert_id):
            self.alert_manager.resolve_alert(alert_id)
            return jsonify({"status": "resolved"})

        @app.route("/api/status")
        def api_status():
            return jsonify({
                "uptime": time.time() - self._start_time,
                "ml": self.ensemble.get_metrics(),
                "response": self.response_engine.get_stats(),
                "threat_intel": self.threat_intel.get_stats(),
            })

    def emit_alert(self, alert):
        try:
            self.socketio.emit("new_alert", alert, namespace="/")
        except Exception as e:
            logger.debug("WebSocket emit error: %s", e)

    def emit_process_update(self, data):
        try:
            self.socketio.emit("process_update", data, namespace="/")
        except Exception as e:
            logger.debug("WebSocket emit error: %s", e)

    def emit_ml_score(self, data):
        try:
            self.socketio.emit("ml_score_update", data, namespace="/")
        except Exception as e:
            logger.debug("WebSocket emit error: %s", e)

    def run(self):
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 5000)
        debug = self.config.get("debug", False)
        logger.info("Dashboard starting on http://%s:%d", host, port)
        self.socketio.run(self.app, host=host, port=port, debug=debug,
                         use_reloader=False, allow_unsafe_werkzeug=True)
