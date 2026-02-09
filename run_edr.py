#!/usr/bin/env python3
"""EDR PoC - Main Entry Point

Starts all components: sensors, feature pipeline, ML engine,
detection engine, response engine, and web dashboard.
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time

import yaml

# Configure logging before imports
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("edr")


def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


def main():
    logger.info("=" * 60)
    logger.info("  EDR PoC - Endpoint Detection & Response")
    logger.info("  CrowdStrike Falcon-inspired Architecture")
    logger.info("=" * 60)

    config = load_config()

    # --- Initialize Storage ---
    from storage.database import Database
    db_path = config.get("storage", {}).get("database_path", "data/edr.db")
    database = Database(db_path)
    logger.info("Database initialized at %s", db_path)

    # --- Initialize Sensor Layer ---
    event_queue = asyncio.Queue(maxsize=10000)

    from sensor.process_monitor import ProcessMonitor
    from sensor.file_monitor import FileMonitor
    from sensor.network_monitor import NetworkMonitor
    from sensor.collector import EventCollector

    process_monitor = ProcessMonitor(config, event_queue)
    file_monitor = FileMonitor(config, event_queue)
    network_monitor = NetworkMonitor(config, event_queue)
    collector = EventCollector(config, database)

    # --- Initialize Feature Engineering ---
    from features.pipeline import FeaturePipeline
    feature_pipeline = FeaturePipeline(config, process_monitor)

    # --- Initialize ML Engine ---
    from ml.isolation_forest import IsolationForestDetector
    from ml.autoencoder import AutoencoderDetector
    from ml.ensemble import EnsembleDetector
    from ml.model_store import ModelStore

    iso_forest = IsolationForestDetector(config)
    autoencoder = AutoencoderDetector(config)
    ensemble = EnsembleDetector(config, iso_forest, autoencoder)
    model_store = ModelStore()

    # Try to load previously trained models
    if model_store.load_all(iso_forest, autoencoder):
        logger.info("Loaded pre-trained models from disk")

    # --- Initialize Detection Layer ---
    from detection.behavioral_rules import BehavioralRuleEngine
    from detection.threat_intel import ThreatIntelEngine
    from detection.alert_manager import AlertManager

    behavioral_engine = BehavioralRuleEngine(process_monitor=process_monitor)
    threat_intel = ThreatIntelEngine(database)
    alert_manager = AlertManager(config, database)

    # --- Initialize Response Engine ---
    from response.response_engine import ResponseEngine
    response_engine = ResponseEngine(config, database)

    # --- Initialize Dashboard ---
    from dashboard.app import Dashboard
    dashboard = Dashboard(
        config, database, ensemble, response_engine,
        feature_pipeline, alert_manager, threat_intel, process_monitor,
    )

    # --- Wire alert callbacks ---
    alert_manager.on_alert(dashboard.emit_alert)
    alert_manager.on_alert(response_engine.handle_alert)

    # --- Detection callback for feature pipeline ---
    def on_feature_vector(feature_vector):
        """Process a feature vector through ML and behavioral detection."""
        features = feature_vector.get("features")
        if features is None:
            return

        event_type = feature_vector.get("event_type", "")
        event_data = feature_vector.get("event_data", {})

        # Reconstruct event for behavioral analysis
        event = {"type": event_type, "data": event_data}

        # Behavioral analysis
        behavioral_score, rule_results = behavioral_engine.get_behavioral_score(event)

        # Create behavioral alerts
        for rule_result in rule_results:
            alert_manager.create_behavioral_alert(rule_result, event)

        # Threat intel check
        ioc_matches = threat_intel.check_event(event)
        for match in ioc_matches:
            alert_manager.create_ioc_alert(match, event)

        # ML scoring (only for process-level feature vectors with full dimensions)
        if "pid" in feature_vector and len(features) == 25:
            ml_result = ensemble.predict(features, behavioral_score=behavioral_score)
            alert = alert_manager.create_ml_alert(ml_result, feature_vector)

            # Update process threat score in database
            pid = feature_vector.get("pid")
            if pid:
                proc_info = {
                    "pid": pid,
                    "name": feature_vector.get("process_name", ""),
                    "threat_score": ml_result["threat_score"],
                }
                try:
                    database.upsert_process(proc_info)
                except Exception:
                    pass

                dashboard.emit_ml_score(ml_result)

            # Check if models need retraining
            training_data = feature_pipeline.get_training_data()
            retrained = ensemble.check_retrain(training_data)
            if retrained:
                logger.info("Retrained models: %s", retrained)
                model_store.save_all(iso_forest, autoencoder)

    feature_pipeline.subscribe(on_feature_vector)

    # --- Wire collector to feature pipeline ---
    async def on_event(event):
        """Route events from collector to feature pipeline and detection."""
        await feature_pipeline.process_event(event)

        # Also run behavioral + threat intel on raw events not handled by feature pipeline
        event_type = event.get("type", "")
        if event_type in ("file_create", "file_modify", "file_delete", "file_rename",
                          "net_connect", "net_listen", "net_high_traffic"):
            _, rule_results = behavioral_engine.get_behavioral_score(event)
            for rule_result in rule_results:
                alert_manager.create_behavioral_alert(rule_result, event)

            ioc_matches = threat_intel.check_event(event)
            for match in ioc_matches:
                alert_manager.create_ioc_alert(match, event)

        # Store process info
        if event_type == "process_create":
            data = event.get("data", {})
            database.upsert_process(data)
        elif event_type == "process_terminate":
            pid = event.get("data", {}).get("pid")
            if pid:
                database.mark_process_terminated(pid)

    collector.subscribe(on_event)

    # --- Periodic cleanup task ---
    async def cleanup_loop():
        retention = config.get("storage", {}).get("event_retention_hours", 24)
        interval = config.get("storage", {}).get("cleanup_interval", 3600)
        while True:
            await asyncio.sleep(interval)
            try:
                database.cleanup_old_events(retention)
            except Exception as e:
                logger.error("Cleanup error: %s", e)

    # --- Start everything ---
    shutdown_event = asyncio.Event()

    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start dashboard in a separate thread (Flask + eventlet)
    dashboard_thread = threading.Thread(target=dashboard.run, daemon=True)
    dashboard_thread.start()
    host = config.get("dashboard", {}).get("host", "0.0.0.0")
    port = config.get("dashboard", {}).get("port", 5000)
    logger.info("Dashboard available at http://%s:%d", host, port)

    # Run async event loop
    async def run_async():
        # Redirect events from the shared queue to the collector's queue
        async def queue_relay():
            while not shutdown_event.is_set():
                try:
                    event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                    await collector.event_queue.put(event)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error("Queue relay error: %s", e)

        tasks = [
            asyncio.create_task(process_monitor.start()),
            asyncio.create_task(file_monitor.start()),
            asyncio.create_task(network_monitor.start()),
            asyncio.create_task(collector.start()),
            asyncio.create_task(queue_relay()),
            asyncio.create_task(cleanup_loop()),
        ]

        logger.info("All sensors started. Collecting telemetry...")
        logger.info("Press Ctrl+C to stop")

        await shutdown_event.wait()

        logger.info("Shutting down...")
        process_monitor.stop()
        file_monitor.stop()
        network_monitor.stop()
        collector.stop()

        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

        # Save models on shutdown
        model_store.save_all(iso_forest, autoencoder)
        database.close()
        logger.info("EDR shutdown complete")

    asyncio.run(run_async())


if __name__ == "__main__":
    main()
