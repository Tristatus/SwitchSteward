"""Bounded, cached reverse DNS lookups for client names."""

import contextvars
import socket
import threading
import time
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

DNS_LOOKUP_TIMEOUT_SECONDS = 3.0


class ReverseDnsResolver:
    """Limit DNS work and waiting time, also across parallel HTTP requests.

    Running system resolver calls cannot be cancelled. They stay in one shared,
    bounded pool and may fill the cache later. Neither a new pool per request
    nor an unbounded queue is created.
    """

    def __init__(self, max_workers: int = 8, cache_size: int = 1024, cache_ttl: float = 60.0):
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="switchsteward-dns")
        self.max_pending = max_workers
        self.cache_size = cache_size
        self.cache_ttl = cache_ttl
        self.lock = threading.RLock()
        self.pending = {}
        self.cache = OrderedDict()

    @staticmethod
    def _lookup(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0].rstrip(".") or None
        except OSError:
            return None

    def _completed(self, ip: str, future) -> None:
        try:
            name = future.result()
        except Exception:
            name = None
        with self.lock:
            self.pending.pop(ip, None)
            self.cache[ip] = (time.monotonic() + self.cache_ttl, name)
            self.cache.move_to_end(ip)
            while len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)

    def resolve(self, ip_addresses: set[str], timeout: float) -> dict[str, str]:
        deadline = time.monotonic() + timeout
        remaining = set(ip_addresses)
        pending = {}
        names = {}
        while remaining or pending:
            with self.lock:
                for ip in sorted(remaining):
                    cached = self.cache.get(ip)
                    if cached and cached[0] > time.monotonic():
                        if cached[1]:
                            names[ip] = cached[1]
                        self.cache.move_to_end(ip)
                        remaining.remove(ip)
                        continue
                    future = self.pending.get(ip)
                    if future is None:
                        if len(self.pending) >= self.max_pending or time.monotonic() >= deadline:
                            continue
                        # Each task needs its own context copy (language, request id).
                        future = self.executor.submit(contextvars.copy_context().run, self._lookup, ip)
                        self.pending[ip] = future
                        future.add_done_callback(lambda completed, address=ip: self._completed(address, completed))
                    pending[future] = ip
                    remaining.remove(ip)
            if not pending:
                break
            done, _ = wait(pending, timeout=max(0.0, deadline - time.monotonic()), return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                ip = pending.pop(future)
                try:
                    name = future.result()
                except Exception:
                    name = None
                if name:
                    names[ip] = name
            if time.monotonic() >= deadline:
                break
        return names


DNS_RESOLVER = ReverseDnsResolver()


def device_names_by_ip(ip_addresses: set[str], neighbors: list[dict]) -> dict[str, str]:
    """Names from neighbor advertisements first, reverse DNS for the remaining addresses."""
    names = {
        ip: neighbor["device_id"]
        for neighbor in neighbors
        if neighbor.get("device_id")
        for ip in neighbor.get("ip_addresses", [])
        if ip in ip_addresses
    }
    unresolved_ips = ip_addresses - names.keys()
    if not unresolved_ips:
        return names

    names.update(DNS_RESOLVER.resolve(unresolved_ips, DNS_LOOKUP_TIMEOUT_SECONDS))
    return names
