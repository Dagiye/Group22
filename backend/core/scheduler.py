# backend/core/scheduler.py

import asyncio
from typing import Callable, List, Any, Dict
import time
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ScanTask:
    """
    Represents a single scan task.
    """
    def __init__(self, name: str, func: Callable, args: List[Any] = None, kwargs: Dict[str, Any] = None):
        self.name = name
        self.func = func
        self.args = args or []
        self.kwargs = kwargs or {}
        self.result = None
        self.exception = None
        self.completed = False
        self.started_at = None
        self.finished_at = None

    async def run(self):
        """Execute the scan task asynchronously."""
        try:
            self.started_at = time.time()
            logger.info(f"Starting task: {self.name}")
            if asyncio.iscoroutinefunction(self.func):
                self.result = await self.func(*self.args, **self.kwargs)
            else:
                loop = asyncio.get_event_loop()
                self.result = await loop.run_in_executor(None, self.func, *self.args, **self.kwargs)
            self.completed = True
            logger.info(f"Completed task: {self.name}")
        except Exception as e:
            self.exception = e
            self.completed = True
            logger.error(f"Task {self.name} failed: {e}")
        finally:
            self.finished_at = time.time()


class Scheduler:
    """
    Manages the execution of scan tasks with concurrency.
    """
    def __init__(self, max_concurrent_tasks: int = 5):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.tasks: List[ScanTask] = []

    def add_task(self, task: ScanTask):
        """Add a scan task to the scheduler"""
        self.tasks.append(task)

    async def run_all(self):
        """Run all tasks asynchronously with limited concurrency"""
        semaphore = asyncio.Semaphore(self.max_concurrent_tasks)

        async def sem_task(task: ScanTask):
            async with semaphore:
                await task.run()

        await asyncio.gather(*(sem_task(task) for task in self.tasks))

    def run(self):
        """Blocking run"""
        asyncio.run(self.run_all())

    def pending_tasks(self):
        return [t for t in self.tasks if not t.completed]

    def completed_tasks(self):
        return [t for t in self.tasks if t.completed]

    def __repr__(self):
        return f"<Scheduler tasks={len(self.tasks)} max_concurrent={self.max_concurrent_tasks}>"


# Example usage:
# async def sample_scan(url):
#     await asyncio.sleep(1)
#     return f"Scanned {url}"
#
# scheduler = Scheduler(max_concurrent_tasks=3)
# scheduler.add_task(ScanTask("Task1", sample_scan, args=["https://example.com"]))
# scheduler.add_task(ScanTask("Task2", sample_scan, args=["https://test.com"]))
# scheduler.run()
