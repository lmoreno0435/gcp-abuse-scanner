"""Tests for _fmt_exc() — concise HttpError formatting in collectors."""

from __future__ import annotations

from unittest.mock import MagicMock

from gcp_abuse_scanner.collectors.base import _fmt_exc


def _make_http_error(status: int, message: str, uri: str = "https://example.com/api") -> Exception:
    """Build a real googleapiclient.errors.HttpError for testing."""
    from googleapiclient.errors import HttpError

    resp = MagicMock()
    resp.status = status
    resp.reason = "Forbidden" if status == 403 else "Error"
    content = f'{{"error": {{"code": {status}, "message": "{message}"}}}}'.encode()
    return HttpError(resp=resp, content=content, uri=uri)


class TestFmtExcHttpError:
    """_fmt_exc correctly summarises googleapiclient HttpError objects."""

    def test_billing_disabled_403(self):
        exc = _make_http_error(
            403,
            "This API method requires billing to be enabled. "
            "Please enable billing on project #my-proj by visiting "
            "https://console.developers.google.com/billing/enable?project=my-proj then retry.",
            uri="https://container.googleapis.com/v1/projects/my-proj/locations/-/clusters?alt=json",
        )
        result = _fmt_exc(exc)
        assert result.startswith("HTTP 403:")
        assert "billing" in result.lower()
        # Must be a single line with no embedded JSON
        assert "\n" not in result
        assert "{" not in result

    def test_permission_denied_403(self):
        exc = _make_http_error(
            403,
            "The caller does not have permission.",
            uri="https://compute.googleapis.com/compute/v1/projects/my-proj/global/firewalls",
        )
        result = _fmt_exc(exc)
        assert result == "HTTP 403: The caller does not have permission"

    def test_service_disabled_403(self):
        exc = _make_http_error(
            403,
            "Cloud Billing API has not been used in project my-proj before or it is disabled. "
            "Enable it by visiting https://console.developers.google.com/apis/api/cloudbilling.googleapis.com/overview?project=my-proj then retry.",
            uri="https://cloudbilling.googleapis.com/v1/projects/my-proj/billingInfo",
        )
        result = _fmt_exc(exc)
        assert result.startswith("HTTP 403:")
        # First sentence only — no URL noise
        assert "https://" not in result
        assert "\n" not in result

    def test_404_not_found(self):
        exc = _make_http_error(
            404,
            "The resource 'projects/my-proj' was not found.",
            uri="https://cloudresourcemanager.googleapis.com/v1/projects/my-proj",
        )
        result = _fmt_exc(exc)
        assert result.startswith("HTTP 404:")
        assert "not found" in result.lower()

    def test_429_quota_exceeded(self):
        exc = _make_http_error(
            429,
            "Quota exceeded for quota metric 'compute.googleapis.com/cpus'.",
            uri="https://compute.googleapis.com/compute/v1/projects/my-proj/regions/us-central1",
        )
        result = _fmt_exc(exc)
        assert result.startswith("HTTP 429:")
        assert "Quota" in result

    def test_result_is_single_line(self):
        """No matter how long the original error, output must be one line."""
        exc = _make_http_error(
            403,
            "A" * 500,  # very long message
            uri="https://example.com/api",
        )
        result = _fmt_exc(exc)
        assert "\n" not in result

    def test_result_is_concise(self):
        """Output must be much shorter than the raw HttpError string."""
        exc = _make_http_error(
            403,
            "This API method requires billing to be enabled. "
            "Please enable billing on project #my-proj by visiting "
            "https://console.developers.google.com/billing/enable?project=my-proj then retry.",
            uri="https://container.googleapis.com/v1/projects/my-proj/locations/-/clusters?alt=json",
        )
        raw_len = len(str(exc))
        result_len = len(_fmt_exc(exc))
        assert (
            result_len < raw_len / 2
        ), f"_fmt_exc output ({result_len} chars) should be much shorter than raw ({raw_len} chars)"


class TestFmtExcGenericExceptions:
    """_fmt_exc handles non-HttpError exceptions gracefully."""

    def test_plain_exception(self):
        result = _fmt_exc(Exception("something went wrong"))
        assert result == "something went wrong"

    def test_value_error(self):
        result = _fmt_exc(ValueError("invalid value"))
        assert result == "invalid value"

    def test_connection_error(self):
        result = _fmt_exc(ConnectionError("Connection refused"))
        assert result == "Connection refused"

    def test_long_generic_exception_truncated(self):
        long_msg = "x" * 300
        result = _fmt_exc(Exception(long_msg))
        assert len(result) <= 120
        assert result == "x" * 120

    def test_exact_120_chars_not_truncated(self):
        msg = "a" * 120
        result = _fmt_exc(Exception(msg))
        assert result == msg

    def test_121_chars_truncated(self):
        msg = "a" * 121
        result = _fmt_exc(Exception(msg))
        assert len(result) == 120

    def test_empty_exception(self):
        result = _fmt_exc(Exception(""))
        assert result == ""

    def test_runtime_error(self):
        result = _fmt_exc(RuntimeError("timeout after 30s"))
        assert result == "timeout after 30s"


class TestFmtExcCollectorIntegration:
    """_fmt_exc is used correctly in collector warning messages."""

    def test_gke_collector_logs_concise_error(self, caplog):
        """GKECollector warning message uses _fmt_exc — no JSON dump in logs."""
        import logging
        from unittest.mock import MagicMock, patch

        from gcp_abuse_scanner.collectors.gke import GKECollector
        from gcp_abuse_scanner.models.inventory import EnabledAPI, ResourceInventory

        inv = ResourceInventory(project_ids=["proj-x"])
        inv.enabled_apis.append(
            EnabledAPI(project_id="proj-x", service_name="container.googleapis.com")
        )

        auth = MagicMock()
        auth.get_credentials.return_value = MagicMock()

        http_err = _make_http_error(
            403,
            "This API method requires billing to be enabled. Please enable billing on project #proj-x.",
            uri="https://container.googleapis.com/v1/projects/proj-x/locations/-/clusters?alt=json",
        )

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.projects().locations().clusters().list().execute.side_effect = http_err

            with caplog.at_level(logging.WARNING, logger="gcp_abuse_scanner.collectors.gke"):
                collector = GKECollector(auth)
                collector.collect(inv, ["proj-x"])

        # There should be a warning logged
        assert len(caplog.records) >= 1
        warning_msg = caplog.records[0].message

        # Must contain project context
        assert "proj-x" in warning_msg
        # Must be concise — no raw JSON, no multi-line HttpError dump
        assert "{" not in warning_msg
        assert "\n" not in warning_msg
        # Must start with HTTP status
        assert "HTTP 403" in warning_msg

    def test_network_collector_logs_concise_error(self, caplog):
        """NetworkCollector warning message uses _fmt_exc."""
        import logging
        from unittest.mock import MagicMock, patch

        from gcp_abuse_scanner.collectors.network import NetworkCollector
        from gcp_abuse_scanner.models.inventory import EnabledAPI, ResourceInventory

        inv = ResourceInventory(project_ids=["proj-y"])
        inv.enabled_apis.append(
            EnabledAPI(project_id="proj-y", service_name="compute.googleapis.com")
        )

        auth = MagicMock()
        auth.get_credentials.return_value = MagicMock()

        http_err = _make_http_error(
            403,
            "This API method requires billing to be enabled. Please enable billing.",
            uri="https://compute.googleapis.com/compute/v1/projects/proj-y/global/firewalls",
        )

        with patch("googleapiclient.discovery.build") as mock_build:
            mock_client = MagicMock()
            mock_build.return_value = mock_client
            mock_client.firewalls().list().execute.side_effect = http_err

            with caplog.at_level(logging.WARNING, logger="gcp_abuse_scanner.collectors.network"):
                collector = NetworkCollector(auth)
                collector.collect(inv, ["proj-y"])

        assert any("HTTP 403" in r.message for r in caplog.records)
        assert all("{" not in r.message for r in caplog.records)
