"""Live smoke tests against the real openVuln API and CISA KEV feed (opt-in).

Run with ``NETSEC_LIVE=1 uv run pytest -m live``. openVuln tests also need
``CISCO_CLIENT_ID`` / ``CISCO_CLIENT_SECRET`` in the environment or ``.env``.
Nothing returned by the API is written to disk.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from netsec_check.cli import main
from netsec_check.psirt import OpenVulnClient, credentials_from_env, fetch_kev

ROOT = Path(__file__).resolve().parent.parent
WEBUI = "cisco-sa-iosxe-webui-privesc-j22SaA4z"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("NETSEC_LIVE") != "1", reason="set NETSEC_LIVE=1"),
]


@pytest.fixture(scope="module")
def client() -> OpenVulnClient:
    creds = credentials_from_env(ROOT / ".env")
    if creds is None:
        pytest.skip("no openVuln credentials")
    return OpenVulnClient(*creds)


def test_openvuln_os_version(client: OpenVulnClient) -> None:
    advisories = client.advisories_for_version("17.9.3a")
    ids = {a.advisory_id for a in advisories}
    assert WEBUI in ids  # fixed in 17.9.4a
    assert WEBUI not in {a.advisory_id for a in client.advisories_for_version("17.9.4a")}


def test_openvuln_advisory_csaf(client: OpenVulnClient) -> None:
    adv = client.advisory(WEBUI)
    assert adv is not None
    assert "CVE-2023-20198" in adv.cves
    assert client.csaf(adv)["document"]["tracking"]["id"] == WEBUI


def test_kev_feed() -> None:
    kev = fetch_kev()
    assert "CVE-2023-20198" in kev.entries
    assert len(kev.entries) > 1000


def test_cli_live(capsys: pytest.CaptureFixture[str], client: OpenVulnClient) -> None:
    args = ["check", "--configs", str(ROOT / "samples/configs"), "--rules", str(ROOT / "rules")]
    args += ["--env-file", str(ROOT / ".env"), "--device", "branch-isr-01", "--rule", "webui"]
    assert main(args) == 0
    row = capsys.readouterr().out.splitlines()[1].split()
    assert row[5] in ("AFFECTED", "NOT_AFFECTED_FEATURE_DISABLED")
    assert row[6] == "yes"


def test_netbox_matches_file_mode(capsys: pytest.CaptureFixture[str]) -> None:
    """Needs the local lab: docker compose up + ``netsec-check netbox-seed`` (see README)."""
    from netsec_check.netbox import netbox_from_env

    if netbox_from_env(ROOT / ".env") is None:
        pytest.skip("no NETBOX_URL / NETBOX_TOKEN")
    base = ["check", "--offline", "--format", "json", "--rules", str(ROOT / "rules")]
    base += ["--advisories", str(ROOT / "tests/fixtures/psirt"), "--env-file", str(ROOT / ".env")]
    assert main([*base, "--configs", str(ROOT / "samples/configs")]) == 0
    from_files = capsys.readouterr().out
    code = main([*base, "--netbox", "--netbox-filter", "site=netsec-lab"])
    out, err = capsys.readouterr()
    if code == 2 and "cannot reach NetBox" in err:
        pytest.skip("NetBox not reachable")
    assert code == 0, err
    assert out == from_files
