"""Main-thread executor for IDA Pro API calls.

IDA Pro's Python API requires all calls to be made from the main thread.
FastMCP dispatches sync tool handlers to a worker thread pool via
anyio.to_thread.run_sync(), which breaks IDA's thread-safety requirement.

This module provides a MainThreadExecutor that keeps the main thread as a
dedicated IDA worker, shuttling calls from worker threads back to it.
"""

import queue
import threading
from concurrent.futures import Future
from typing import Any, Callable


class MainThreadExecutor:
    _instance: "MainThreadExecutor | None" = None

    def __init__(self) -> None:
        self._queue: queue.Queue = queue.Queue()
        self._running = False

    @classmethod
    def instance(cls) -> "MainThreadExecutor":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def submit(self, fn: Callable, *args: Any, **kwargs: Any) -> Future:
        """Submit a callable to be executed on the main thread."""
        future: Future = Future()
        self._queue.put((fn, args, kwargs, future))
        return future

    def execute(self, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        """Submit work to the main thread and block until complete.

        If already on the main thread, execute directly.
        """
        if threading.current_thread() is threading.main_thread():
            return fn(*args, **kwargs)
        future = self.submit(fn, *args, **kwargs)
        return future.result()

    def run_forever(self) -> None:
        """Run on the main thread, processing work items until stopped."""
        self._running = True
        while self._running:
            try:
                fn, args, kwargs, future = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                result = fn(*args, **kwargs)
                future.set_result(result)
            except BaseException as e:
                future.set_exception(e)

    def stop(self) -> None:
        self._running = False
