"""Authentication manager — service account key, ADC, and impersonation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import google.auth
import google.auth.impersonated_credentials
import google.oauth2.service_account
from google.auth.credentials import Credentials

logger = logging.getLogger(__name__)

# Scopes required for all GCP APIs used by collectors
_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform.read-only",
]


class AuthError(Exception):
    """Raised when authentication cannot be established."""


class AuthManager:
    """
    Resolves GCP credentials in order of preference:
    1. Impersonation of a target service account (recommended).
    2. Service account key file (JSON).
    3. Application Default Credentials (ADC).

    Warns when a key file is used (anti-pattern for production).
    """

    def __init__(
        self,
        service_account_key: str | None = None,
        impersonate_service_account: str | None = None,
        quota_project_id: str | None = None,
    ) -> None:
        self._key_file = service_account_key
        self._impersonate_sa = impersonate_service_account
        self._quota_project_id = quota_project_id
        self._credentials: Credentials | None = None

    def get_credentials(self) -> Credentials:
        if self._credentials is not None:
            return self._credentials

        if self._impersonate_sa:
            self._credentials = self._impersonated_credentials()
        elif self._key_file:
            self._credentials = self._key_file_credentials()
        else:
            self._credentials = self._adc_credentials()

        return self._credentials

    def _impersonated_credentials(self) -> Credentials:
        logger.info("Using impersonation for SA: %s", self._impersonate_sa)
        source_creds, _ = google.auth.default(scopes=_SCOPES)
        return google.auth.impersonated_credentials.Credentials(
            source_credentials=source_creds,
            target_principal=self._impersonate_sa,
            target_scopes=_SCOPES,
            quota_project_id=self._quota_project_id,
        )

    def _key_file_credentials(self) -> Credentials:
        key_path = Path(self._key_file)  # type: ignore[arg-type]
        if not key_path.exists():
            raise AuthError(f"Service account key file not found: {self._key_file}")

        logger.warning(
            "⚠️  Using a service account key file (%s). "
            "Prefer --impersonate-service-account or Workload Identity Federation "
            "to avoid distributing long-lived credentials.",
            self._key_file,
        )
        return google.oauth2.service_account.Credentials.from_service_account_file(
            str(key_path),
            scopes=_SCOPES,
            quota_project_id=self._quota_project_id,
        )

    def _adc_credentials(self) -> Credentials:
        logger.info("Using Application Default Credentials (ADC)")
        creds, project = google.auth.default(scopes=_SCOPES)
        if project and not self._quota_project_id:
            logger.debug("ADC project: %s", project)
        return creds

    @property
    def identity(self) -> str:
        """Human-readable description of the credential being used."""
        if self._impersonate_sa:
            return f"impersonated:{self._impersonate_sa}"
        if self._key_file:
            return f"key_file:{self._key_file}"
        return "adc"

    def build_service(self, service_name: str, version: str, **kwargs: Any) -> Any:
        """Build a Google API client service with the resolved credentials."""
        from googleapiclient import discovery

        return discovery.build(
            service_name,
            version,
            credentials=self.get_credentials(),
            **kwargs,
        )
