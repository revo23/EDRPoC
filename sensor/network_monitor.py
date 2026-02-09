import asyncio
import logging
import time

import psutil

logger = logging.getLogger("edr.sensor.network")


class NetworkMonitor:
    def __init__(self, config, event_queue):
        self.config = config.get("sensor", {}).get("network_monitor", {})
        self.poll_interval = self.config.get("poll_interval", 2.0)
        self.event_queue = event_queue
        self.known_connections = {}
        self._running = False
        self._io_counters_prev = {}

    async def start(self):
        logger.info("Network monitor starting (interval=%.1fs)", self.poll_interval)
        self._running = True
        self._snapshot_connections()
        while self._running:
            try:
                await self._poll()
            except Exception as e:
                logger.error("Network monitor error: %s", e)
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def _snapshot_connections(self):
        try:
            for conn in psutil.net_connections(kind="inet"):
                key = self._conn_key(conn)
                if key:
                    self.known_connections[key] = {
                        "timestamp": time.time(),
                        "status": conn.status,
                        "pid": conn.pid,
                    }
        except (psutil.AccessDenied, OSError):
            pass

    async def _poll(self):
        try:
            current_connections = {}
            for conn in psutil.net_connections(kind="inet"):
                key = self._conn_key(conn)
                if not key:
                    continue

                current_connections[key] = conn

                if key not in self.known_connections:
                    event_type = "net_listen" if conn.status == "LISTEN" else "net_connect"
                    data = self._build_connection_data(conn)
                    await self.event_queue.put({
                        "type": event_type,
                        "timestamp": time.time(),
                        "data": data,
                    })
                    self.known_connections[key] = {
                        "timestamp": time.time(),
                        "status": conn.status,
                        "pid": conn.pid,
                    }

            closed = set(self.known_connections.keys()) - set(current_connections.keys())
            for key in closed:
                self.known_connections.pop(key, None)

            await self._check_io_counters()

        except (psutil.AccessDenied, OSError) as e:
            logger.debug("Network poll error: %s", e)

    async def _check_io_counters(self):
        try:
            counters = psutil.net_io_counters(pernic=False)
            now = time.time()

            if hasattr(self, "_last_counters") and self._last_counters:
                dt = now - self._last_counter_time
                if dt > 0:
                    bytes_sent_rate = (counters.bytes_sent - self._last_counters.bytes_sent) / dt
                    bytes_recv_rate = (counters.bytes_recv - self._last_counters.bytes_recv) / dt

                    if bytes_sent_rate > 10_000_000:
                        await self.event_queue.put({
                            "type": "net_high_traffic",
                            "timestamp": now,
                            "data": {
                                "bytes_sent_rate": bytes_sent_rate,
                                "bytes_recv_rate": bytes_recv_rate,
                                "direction": "outbound",
                            },
                        })

            self._last_counters = counters
            self._last_counter_time = now
        except Exception:
            pass

    def _conn_key(self, conn):
        try:
            laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else ("", 0)
            raddr = (conn.raddr.ip, conn.raddr.port) if conn.raddr else ("", 0)
            return (conn.pid, laddr, raddr, conn.type)
        except Exception:
            return None

    def _build_connection_data(self, conn):
        data = {
            "pid": conn.pid,
            "status": conn.status,
            "type": str(conn.type),
            "family": str(conn.family),
        }
        if conn.laddr:
            data["local_addr"] = conn.laddr.ip
            data["local_port"] = conn.laddr.port
        if conn.raddr:
            data["remote_addr"] = conn.raddr.ip
            data["remote_port"] = conn.raddr.port
            data["non_standard_port"] = conn.raddr.port not in (80, 443, 53, 22, 8080, 8443)
            data["is_private_ip"] = self._is_private_ip(conn.raddr.ip)
        else:
            data["remote_addr"] = ""
            data["remote_port"] = 0
            data["non_standard_port"] = False
            data["is_private_ip"] = True

        try:
            if conn.pid:
                proc = psutil.Process(conn.pid)
                data["process_name"] = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            data["process_name"] = "unknown"

        return data

    def _is_private_ip(self, ip):
        if not ip:
            return True
        parts = ip.split(".")
        if len(parts) != 4:
            return ip.startswith("::") or ip.startswith("fe80")
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
        except ValueError:
            pass
        return False

    def get_connections_for_pid(self, pid):
        connections = []
        try:
            proc = psutil.Process(pid)
            for conn in proc.net_connections(kind="inet"):
                connections.append(self._build_connection_data(conn))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return connections
