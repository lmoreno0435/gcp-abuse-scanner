"""Inventory cache — persist and restore ResourceInventory between runs."""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from gcp_abuse_scanner.models.inventory import ResourceInventory

logger = logging.getLogger(__name__)


class InventoryCache:
    """
    Persists ResourceInventory to disk as gzip-compressed JSON.

    Cache files are stored in a configurable directory (default: ~/.cache/gcp-abuse-scanner/).
    Cache key = SHA256 of (sorted project_ids + organization_id).
    TTL default: 3600 seconds (1 hour).
    """

    DEFAULT_CACHE_DIR = Path.home() / ".cache" / "gcp-abuse-scanner"
    DEFAULT_TTL_SECONDS = 3600

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._cache_dir = cache_dir if cache_dir is not None else self.DEFAULT_CACHE_DIR
        self._ttl_seconds = ttl_seconds

    def _cache_key(self, project_ids: list[str], organization_id: str | None) -> str:
        """SHA256 of sorted project_ids + org_id → hex string (first 16 chars)."""
        sorted_projects = sorted(project_ids)
        org_part = organization_id or ""
        raw = ",".join(sorted_projects) + "|" + org_part
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return digest[:16]

    def _cache_path(self, key: str) -> Path:
        """Returns path: cache_dir / f"{key}.inventory.json.gz" """
        return self._cache_dir / f"{key}.inventory.json.gz"

    def get(
        self,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> ResourceInventory | None:
        """
        Returns cached inventory if it exists and is within TTL.
        Returns None if cache miss, expired, or corrupt.
        """
        key = self._cache_key(project_ids, organization_id)
        path = self._cache_path(key)

        if not path.exists():
            logger.debug("Cache miss (key=%s): file not found", key)
            return None

        try:
            compressed = path.read_bytes()
            raw_json = gzip.decompress(compressed)
            data = json.loads(raw_json)

            cached_at_str: str = data["cached_at"]
            ttl_seconds: int = data["ttl_seconds"]
            inventory_data: dict = data["inventory"]

            cached_at_timestamp = datetime.fromisoformat(cached_at_str).timestamp()
            age = time.time() - cached_at_timestamp

            if age >= ttl_seconds:
                logger.warning(
                    "Cache expired (key=%s): age=%.1fs, ttl=%ds",
                    key,
                    age,
                    ttl_seconds,
                )
                return None

            inventory = ResourceInventory.model_validate(inventory_data)
            logger.debug(
                "Cache hit (key=%s): age=%.1fs, ttl=%ds",
                key,
                age,
                ttl_seconds,
            )
            return inventory

        except Exception as exc:  # noqa: BLE001
            logger.warning("Cache read failed (key=%s): %s", key, exc)
            return None

    def set(
        self,
        inventory: ResourceInventory,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> Path:
        """
        Serializes inventory to gzip JSON and writes to cache.
        Returns the cache file path.
        """
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        key = self._cache_key(project_ids, organization_id)
        path = self._cache_path(key)

        cached_at = datetime.now(tz=timezone.utc).isoformat()
        payload = {
            "cached_at": cached_at,
            "ttl_seconds": self._ttl_seconds,
            "inventory": inventory.model_dump(mode="json"),
        }

        raw_json = json.dumps(payload)
        compressed = gzip.compress(raw_json.encode())
        path.write_bytes(compressed)

        logger.info(
            "Inventory cached (key=%s, path=%s, ttl=%ds)",
            key,
            path,
            self._ttl_seconds,
        )
        return path

    def invalidate(
        self,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> bool:
        """Deletes the cache file. Returns True if deleted, False if not found."""
        key = self._cache_key(project_ids, organization_id)
        path = self._cache_path(key)

        if path.exists():
            path.unlink()
            logger.info("Cache invalidated (key=%s, path=%s)", key, path)
            return True

        logger.debug("Cache invalidate: file not found (key=%s)", key)
        return False

    def clear_all(self) -> int:
        """Deletes all .inventory.json.gz files in cache_dir. Returns count deleted."""
        if not self._cache_dir.exists():
            return 0

        deleted = 0
        for cache_file in self._cache_dir.glob("*.inventory.json.gz"):
            try:
                cache_file.unlink()
                deleted += 1
                logger.debug("Deleted cache file: %s", cache_file)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to delete cache file %s: %s", cache_file, exc)

        logger.info("Cache cleared: %d file(s) deleted from %s", deleted, self._cache_dir)
        return deleted

    def is_valid(
        self,
        project_ids: list[str],
        organization_id: str | None = None,
    ) -> bool:
        """Returns True if a valid (non-expired) cache entry exists."""
        return self.get(project_ids, organization_id) is not None
