import asyncio
import hashlib
import logging
import time

import psutil

logger = logging.getLogger("edr.sensor.process")


class ProcessMonitor:
    def __init__(self, config, event_queue):
        self.config = config.get("sensor", {}).get("process_monitor", {})
        self.poll_interval = self.config.get("poll_interval", 1.0)
        self.hash_executables = self.config.get("hash_executables", True)
        self.event_queue = event_queue
        self.known_pids = {}
        self.process_tree = {}
        self._running = False

    async def start(self):
        logger.info("Process monitor starting (interval=%.1fs)", self.poll_interval)
        self._running = True
        self._snapshot_current_processes()
        while self._running:
            try:
                await self._poll()
            except Exception as e:
                logger.error("Process monitor error: %s", e)
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def _snapshot_current_processes(self):
        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "username", "create_time"]):
            try:
                info = proc.info
                self.known_pids[info["pid"]] = info
                ppid = info.get("ppid", 0)
                if ppid not in self.process_tree:
                    self.process_tree[ppid] = set()
                self.process_tree[ppid].add(info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    async def _poll(self):
        current_pids = set()
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "cmdline", "username", "create_time",
             "cpu_percent", "memory_info", "num_threads", "status"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                if pid not in self.known_pids:
                    proc_data = self._build_process_data(proc, info)
                    self.known_pids[pid] = info
                    ppid = info.get("ppid", 0)
                    if ppid not in self.process_tree:
                        self.process_tree[ppid] = set()
                    self.process_tree[ppid].add(pid)

                    await self.event_queue.put({
                        "type": "process_create",
                        "timestamp": time.time(),
                        "data": proc_data,
                    })
                else:
                    self.known_pids[pid] = info

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        terminated = set(self.known_pids.keys()) - current_pids
        for pid in terminated:
            old_info = self.known_pids.pop(pid, {})
            ppid = old_info.get("ppid", 0)
            if ppid in self.process_tree:
                self.process_tree[ppid].discard(pid)
            self.process_tree.pop(pid, None)

            await self.event_queue.put({
                "type": "process_terminate",
                "timestamp": time.time(),
                "data": {
                    "pid": pid,
                    "name": old_info.get("name", "unknown"),
                    "ppid": ppid,
                },
            })

    def _build_process_data(self, proc, info):
        data = {
            "pid": info["pid"],
            "ppid": info.get("ppid", 0),
            "name": info.get("name", ""),
            "cmdline": " ".join(info.get("cmdline") or []),
            "username": info.get("username", ""),
            "create_time": info.get("create_time", 0),
            "cpu_percent": info.get("cpu_percent", 0),
            "num_threads": info.get("num_threads", 0),
            "status": info.get("status", ""),
        }

        try:
            mem = info.get("memory_info")
            if mem:
                data["memory_rss"] = mem.rss
                data["memory_vms"] = mem.vms
        except Exception:
            data["memory_rss"] = 0
            data["memory_vms"] = 0

        try:
            data["exe"] = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            data["exe"] = ""

        if self.hash_executables and data.get("exe"):
            data["exe_hash"] = self._hash_file(data["exe"])
        else:
            data["exe_hash"] = ""

        try:
            data["open_files"] = len(proc.open_files())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            data["open_files"] = 0

        try:
            data["connections"] = len(proc.net_connections())
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            data["connections"] = 0

        return data

    def _hash_file(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return ""

    def get_process_info(self, pid):
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(attrs=[
                "pid", "ppid", "name", "cmdline", "username", "create_time",
                "cpu_percent", "memory_info", "num_threads", "status",
            ])
            return self._build_process_data(proc, info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_children(self, pid):
        return list(self.process_tree.get(pid, set()))

    def get_tree_depth(self, pid):
        depth = 0
        current = pid
        visited = set()
        while current in self.known_pids and current not in visited:
            visited.add(current)
            ppid = self.known_pids[current].get("ppid", 0)
            if ppid == 0 or ppid == current:
                break
            current = ppid
            depth += 1
        return depth

    def get_parent_name(self, pid):
        info = self.known_pids.get(pid)
        if info:
            ppid = info.get("ppid", 0)
            parent = self.known_pids.get(ppid)
            if parent:
                return parent.get("name", "")
        return ""
