import asyncio
import logging
import math
import os
import time
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("edr.sensor.file")


def calculate_entropy(data):
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


class EDRFileHandler(FileSystemEventHandler):
    def __init__(self, event_queue, loop):
        self.event_queue = event_queue
        self.loop = loop

    def on_created(self, event):
        if event.is_directory:
            return
        self._emit("file_create", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._emit("file_modify", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._emit("file_delete", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self._emit("file_rename", event.src_path, dest=event.dest_path)

    def _emit(self, event_type, path, dest=None):
        data = {
            "path": path,
            "filename": os.path.basename(path),
            "directory": os.path.dirname(path),
            "timestamp": time.time(),
        }

        if dest:
            data["dest_path"] = dest

        if event_type != "file_delete" and os.path.exists(path):
            try:
                stat = os.stat(path)
                data["size"] = stat.st_size
                data["is_executable"] = bool(stat.st_mode & 0o111)
                data["is_hidden"] = os.path.basename(path).startswith(".")

                if stat.st_size < 1_000_000 and stat.st_size > 0:
                    with open(path, "rb") as f:
                        content = f.read(65536)
                    data["entropy"] = calculate_entropy(content)
                else:
                    data["entropy"] = 0.0
            except (OSError, PermissionError):
                data["size"] = 0
                data["entropy"] = 0.0
                data["is_executable"] = False
                data["is_hidden"] = False
        else:
            data["size"] = 0
            data["entropy"] = 0.0
            data["is_executable"] = False
            data["is_hidden"] = os.path.basename(path).startswith(".")

        sensitive_dirs = ["/tmp", "/var/tmp", "/etc", "LaunchAgents", "LaunchDaemons"]
        data["is_sensitive_dir"] = any(d in path for d in sensitive_dirs)
        data["is_temp_dir"] = "/tmp" in path or "/var/tmp" in path

        ext = os.path.splitext(path)[1].lower()
        high_risk_exts = {".sh", ".py", ".rb", ".pl", ".plist", ".dylib", ".so", ".app", ".command"}
        medium_risk_exts = {".zip", ".tar", ".gz", ".dmg", ".pkg", ".js", ".scpt"}
        if ext in high_risk_exts:
            data["extension_risk"] = 0.8
        elif ext in medium_risk_exts:
            data["extension_risk"] = 0.5
        else:
            data["extension_risk"] = 0.1

        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data,
        }

        asyncio.run_coroutine_threadsafe(self.event_queue.put(event), self.loop)


class FileMonitor:
    def __init__(self, config, event_queue):
        self.config = config.get("sensor", {}).get("file_monitor", {})
        self.event_queue = event_queue
        self.observer = None
        self._running = False
        self.watched_dirs = self.config.get("watched_dirs", [
            "/tmp", "/var/tmp", "~/Downloads", "~/Desktop",
            "/etc", "~/Library/LaunchAgents", "~/Library/LaunchDaemons",
        ])

    async def start(self):
        logger.info("File monitor starting")
        self._running = True
        loop = asyncio.get_event_loop()
        handler = EDRFileHandler(self.event_queue, loop)
        self.observer = Observer()

        for dir_path in self.watched_dirs:
            expanded = os.path.expanduser(dir_path)
            if os.path.isdir(expanded):
                self.observer.schedule(handler, expanded, recursive=True)
                logger.info("Watching directory: %s", expanded)
            else:
                logger.warning("Directory not found, skipping: %s", expanded)

        self.observer.start()

        while self._running:
            await asyncio.sleep(1)

    def stop(self):
        self._running = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
