"""Advisory data sources: the PSIRT openVuln API, CSAF documents and the CISA KEV catalog."""

from netsec_check.psirt.kev import KEV_URL, KevCatalog, KevEntry, fetch_kev, load_kev, parse_kev
from netsec_check.psirt.openvuln import (
    OpenVulnAdvisory,
    OpenVulnClient,
    OpenVulnError,
    credentials_from_env,
)
from netsec_check.psirt.versions import (
    CsafVersionSource,
    OpenVulnVersionSource,
    VersionSource,
    csaf_affected_versions,
    normalize_version,
)

__all__ = [
    "KEV_URL",
    "CsafVersionSource",
    "KevCatalog",
    "KevEntry",
    "OpenVulnAdvisory",
    "OpenVulnClient",
    "OpenVulnError",
    "OpenVulnVersionSource",
    "VersionSource",
    "credentials_from_env",
    "csaf_affected_versions",
    "fetch_kev",
    "load_kev",
    "normalize_version",
    "parse_kev",
]
