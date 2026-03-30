"""
Tests for TrivyIntegration – Dependency Scan
Covers all 3 scan methods:
  1. Repo scan  (trivy repo <path>)
  2. Image scan by name  (trivy image <name>)
  3. Tar / tar.gz file  (trivy image --input <file>)

Also covers error handling:
  - Binary not found
  - Scan timeout
  - Non-zero exit code
  - Invalid JSON output
  - Server fallback
  - Credential passing
  - Deduplication (duplicate fingerprint skipped)
"""

import json
import subprocess
from unittest.mock import MagicMock, patch, call

import pytest

from app.integrations.trivy import TrivyIntegration


# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

SAMPLE_TRIVY_VULN_REPORT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "requests",
                    "InstalledVersion": "2.27.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Description": "SSRF vulnerability in requests",
                    "CVSS": {
                        "nvd": {"V3Score": 8.1}
                    },
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "PkgName": "urllib3",
                    "InstalledVersion": "1.26.0",
                    "FixedVersion": "2.0.0",
                    "Severity": "CRITICAL",
                    "Description": "Header injection in urllib3",
                    "CVSS": {},
                },
            ],
        },
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-9999",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "MEDIUM",
                    "Description": "Prototype pollution",
                    "CVSS": {"ghsa": {"V3Score": 5.6}},
                }
            ],
        },
    ]
}

EMPTY_REPORT = {"Results": []}

NO_VULNS_REPORT = {
    "Results": [
        {"Target": "go.sum", "Vulnerabilities": None}
    ]
}


def _make_proc(stdout: str, returncode: int = 0, stderr: str = "") -> MagicMock:
    """Build a mock CompletedProcess."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# 1. REPO SCAN
# ---------------------------------------------------------------------------

class TestRepoScan:

    def test_repo_scan_calls_trivy_repo(self, mocker):
        """trivy repo <path> --format json must be called for scan_type=repo."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan("/cloned/repo", {"scan_type": "repo", "scan_subtype": "dependency"})

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "trivy"
        assert cmd[1] == "repo"
        assert "/cloned/repo" in cmd
        assert "--format" in cmd
        assert "json" in cmd

    def test_repo_scan_returns_parsed_findings(self, mocker):
        """Findings are correctly parsed from a repo scan report."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo", "scan_subtype": "dependency"})

        assert len(findings) == 3
        cve_ids = {f.cve_id for f in findings}
        assert "CVE-2024-1234" in cve_ids
        assert "CVE-2024-5678" in cve_ids
        assert "CVE-2024-9999" in cve_ids

    def test_repo_scan_severity_normalized(self, mocker):
        """Severity values are normalised to lowercase."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})

        severities = {f.severity for f in findings}
        assert all(s in ("critical", "high", "medium", "low", "info") for s in severities)

    def test_repo_scan_cvss_score_extracted(self, mocker):
        """CVSS V3 score is extracted from the first available source."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})

        high_finding = next(f for f in findings if f.cve_id == "CVE-2024-1234")
        assert float(high_finding.cvss_score) == 8.1

    def test_repo_scan_remediation_contains_fixed_version(self, mocker):
        """Remediation text mentions the fixed version."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})

        req_finding = next(f for f in findings if f.cve_id == "CVE-2024-1234")
        assert "2.31.0" in req_finding.remediation

    def test_repo_scan_empty_results(self, mocker):
        """Empty Results list returns empty findings list."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_repo_scan_null_vulnerabilities_skipped(self, mocker):
        """Result blocks with Vulnerabilities=null are safely skipped."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(NO_VULNS_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_repo_scan_uses_server_url_when_configured(self, mocker):
        """--server flag is passed when TRIVY_SERVER_URL is set."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = "http://trivy:4954"

        integration.run_scan("/repo", {"scan_type": "repo"})

        cmd = mock_run.call_args[0][0]
        assert "--server" in cmd
        assert "http://trivy:4954" in cmd

    def test_repo_scan_falls_back_to_local_when_server_fails(self, mocker):
        """When the server scan fails, a local scan is retried without --server."""
        server_fail = _make_proc("", returncode=1, stderr="server unavailable")
        local_ok    = _make_proc(json.dumps(EMPTY_REPORT))
        mock_run = mocker.patch("subprocess.run", side_effect=[server_fail, local_ok])

        integration = TrivyIntegration()
        integration.server_url = "http://trivy:4954"

        findings = integration.run_scan("/repo", {"scan_type": "repo"})

        assert mock_run.call_count == 2
        fallback_cmd = mock_run.call_args_list[1][0][0]
        assert "--server" not in fallback_cmd
        assert findings == []


# ---------------------------------------------------------------------------
# 2. IMAGE SCAN BY NAME
# ---------------------------------------------------------------------------

class TestImageScanByName:

    def test_image_scan_calls_trivy_image(self, mocker):
        """trivy image <name> --format json must be called for scan_type=image."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan("nginx:latest", {"scan_type": "image", "scan_subtype": "dependency"})

        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "image"
        assert "nginx:latest" in cmd

    def test_image_scan_public_no_credentials(self, mocker):
        """No --username/--password flags for public images."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan("nginx:latest", {"scan_type": "image"})

        cmd = mock_run.call_args[0][0]
        assert "--username" not in cmd
        assert "--password" not in cmd

    def test_image_scan_private_passes_credentials(self, mocker):
        """--username and --password are appended for private registries."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan(
            "ghcr.io/org/app:latest",
            {
                "scan_type": "image",
                "registry_username": "myuser",
                "registry_password": "ghp_secret",
            },
        )

        cmd = mock_run.call_args[0][0]
        assert "--username" in cmd
        assert "myuser" in cmd
        assert "--password" in cmd
        assert "ghp_secret" in cmd

    def test_image_scan_ghcr_link_parsed_correctly(self, mocker):
        """ghcr.io image reference is passed through unchanged."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan("ghcr.io/myorg/myapp:v1.2.3", {"scan_type": "image"})

        cmd = mock_run.call_args[0][0]
        assert "ghcr.io/myorg/myapp:v1.2.3" in cmd

    def test_image_scan_returns_findings(self, mocker):
        """Findings from an image scan are returned correctly."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("ubuntu:22.04", {"scan_type": "image"})

        assert len(findings) == 3
        assert all(f.fingerprint is not None for f in findings)


# ---------------------------------------------------------------------------
# 3. TAR FILE SCAN
# ---------------------------------------------------------------------------

class TestTarFileScan:

    @pytest.mark.parametrize("filename", [
        "/uploads/myimage.tar",
        "/uploads/myimage.tar.gz",
        "/uploads/myimage.tgz",
    ])
    def test_tar_scan_uses_input_flag(self, filename, mocker):
        """For .tar/.tar.gz/.tgz files, --input flag must be used instead of positional arg."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan(filename, {"scan_type": "image", "scan_subtype": "dependency"})

        cmd = mock_run.call_args[0][0]
        assert "--input" in cmd
        assert filename in cmd
        # tar path must NOT appear as a positional image name (after `image`)
        assert cmd.index("--input") < cmd.index(filename)

    def test_tar_scan_does_not_add_credentials(self, mocker):
        """Credentials are not passed for local tar file scans."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan(
            "/uploads/img.tar.gz",
            {"scan_type": "image", "registry_username": "user", "registry_password": "pass"},
        )

        cmd = mock_run.call_args[0][0]
        assert "--username" not in cmd
        assert "--password" not in cmd

    def test_tar_scan_does_not_use_server_flag(self, mocker):
        """--server flag must not be used with tar file scans."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = "http://trivy:4954"

        integration.run_scan("/uploads/img.tar.gz", {"scan_type": "image"})

        cmd = mock_run.call_args[0][0]
        assert "--server" not in cmd

    def test_tar_scan_returns_findings(self, mocker):
        """Findings are correctly extracted from a tar-based image scan."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/uploads/img.tar", {"scan_type": "image"})

        assert len(findings) == 3

    def test_tar_scan_failed_exit_code_returns_empty(self, mocker):
        """Non-zero exit code from trivy returns empty list (scan marked failed)."""
        mocker.patch(
            "subprocess.run",
            return_value=_make_proc("", returncode=1, stderr="unable to find image"),
        )
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/uploads/img.tar.gz", {"scan_type": "image"})

        assert findings == []


# ---------------------------------------------------------------------------
# 4. ERROR HANDLING (applies to all scan types)
# ---------------------------------------------------------------------------

class TestErrorHandling:

    def test_trivy_binary_not_found_returns_empty(self, mocker):
        """FileNotFoundError (binary missing) is caught and returns empty list."""
        mocker.patch("subprocess.run", side_effect=FileNotFoundError)
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_scan_timeout_returns_empty(self, mocker):
        """TimeoutExpired is caught and returns empty list."""
        mocker.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=600))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_invalid_json_output_returns_empty(self, mocker):
        """Malformed JSON from trivy is caught and returns empty list."""
        mocker.patch("subprocess.run", return_value=_make_proc("not-valid-json{{{"))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_nonzero_exit_no_fallback_returns_empty(self, mocker):
        """Non-zero exit with no server configured returns empty list."""
        mocker.patch("subprocess.run", return_value=_make_proc("", returncode=1, stderr="some error"))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("nginx:latest", {"scan_type": "image"})
        assert findings == []

    def test_unexpected_exception_returns_empty(self, mocker):
        """Any unexpected exception is caught and returns empty list."""
        mocker.patch("subprocess.run", side_effect=RuntimeError("unexpected"))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})
        assert findings == []

    def test_empty_target_with_repo_scan(self, mocker):
        """Empty target string still runs trivy (target passed as empty string)."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("", {"scan_type": "repo"})

        assert mock_run.called
        assert findings == []

    def test_unknown_scan_type_defaults_to_repo(self, mocker):
        """Unrecognised scan_type is silently coerced to 'repo'."""
        mock_run = mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(EMPTY_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        integration.run_scan("/path", {"scan_type": "foobar"})

        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "repo"


# ---------------------------------------------------------------------------
# 5. DEDUPLICATION (fingerprint)
# ---------------------------------------------------------------------------

class TestDeduplication:

    def test_each_finding_has_unique_fingerprint(self, mocker):
        """All findings in a report with distinct CVEs have unique fingerprints."""
        mocker.patch("subprocess.run", return_value=_make_proc(json.dumps(SAMPLE_TRIVY_VULN_REPORT)))
        integration = TrivyIntegration()
        integration.server_url = None

        findings = integration.run_scan("/repo", {"scan_type": "repo"})

        fingerprints = [f.fingerprint for f in findings]
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprints found"

    def test_same_cve_same_pkg_produces_same_fingerprint(self):
        """Identical CVE + package produces identical fingerprint (enables dedup)."""
        integration = TrivyIntegration()
        vuln = {
            "VulnerabilityID": "CVE-2024-1234",
            "PkgName": "requests",
            "Severity": "HIGH",
            "Description": "test",
            "CVSS": {},
            "FixedVersion": "",
        }
        report = {"Results": [{"Target": "req.txt", "Vulnerabilities": [vuln, vuln]}]}

        with patch("subprocess.run", return_value=_make_proc(json.dumps(report))):
            findings = integration.run_scan("/repo", {"scan_type": "repo"})

        # Both findings exist (dedup happens at DB level, not integration level)
        assert len(findings) == 2
        assert findings[0].fingerprint == findings[1].fingerprint


# ---------------------------------------------------------------------------
# 6. REPORT PARSING (from uploaded file)
# ---------------------------------------------------------------------------

class TestReportParsing:

    def test_parse_report_file_returns_findings(self, tmp_path):
        """parse_report() loads a JSON file and returns findings."""
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(SAMPLE_TRIVY_VULN_REPORT))

        integration = TrivyIntegration()
        findings = integration.parse_report(str(report_file))

        assert len(findings) == 3

    def test_parse_report_file_not_found_returns_empty(self):
        """Missing report file returns empty list."""
        integration = TrivyIntegration()
        findings = integration.parse_report("/nonexistent/report.json")
        assert findings == []

    def test_parse_report_invalid_json_returns_empty(self, tmp_path):
        """Malformed JSON report file returns empty list."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")

        integration = TrivyIntegration()
        findings = integration.parse_report(str(bad_file))
        assert findings == []
