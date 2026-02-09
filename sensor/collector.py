import asyncio
import logging
import time

logger = logging.getLogger("edr.sensor.collector")


class EventCollector:
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.subscribers = []
        self._running = False
        self._event_count = 0
        self._start_time = None

    def get_queue(self):
        return self.event_queue

    def subscribe(self, callback):
        self.subscribers.append(callback)

    async def start(self):
        logger.info("Event collector starting")
        self._running = True
        self._start_time = time.time()

        while self._running:
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                self._event_count += 1

                self._store_event(event)

                for callback in self.subscribers:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(event)
                        else:
                            callback(event)
                    except Exception as e:
                        logger.error("Subscriber error: %s", e)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Collector error: %s", e)

    def stop(self):
        self._running = False
        logger.info("Collector stopped. Processed %d events", self._event_count)

    def _store_event(self, event):
        try:
            event_type = event.get("type", "unknown")
            data = event.get("data", {})
            process_id = data.get("pid")
            self.database.insert_event(event_type, data, process_id=process_id)
        except Exception as e:
            logger.error("Failed to store event: %s", e)

    def get_stats(self):
        uptime = time.time() - self._start_time if self._start_time else 0
        return {
            "events_processed": self._event_count,
            "queue_size": self.event_queue.qsize(),
            "uptime_seconds": uptime,
            "events_per_second": self._event_count / uptime if uptime > 0 else 0,
            "subscribers": len(self.subscribers),
        }
