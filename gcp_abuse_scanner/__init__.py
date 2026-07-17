"""gcp-abuse-scanner — Preventive GCP security scanner."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("gcp-abuse-scanner")
except PackageNotFoundError:  # running from source without install
    __version__ = "0.1.0"

__author__ = "GCP Abuse Scanner Contributors"
__license__ = "Apache-2.0"
