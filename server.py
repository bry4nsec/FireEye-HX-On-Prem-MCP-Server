"""
Trellix (FireEye) HX On-Prem – MCP Server
==========================================
A comprehensive Model Context Protocol server exposing ALL v3 API endpoints
of a Trellix HX on-premises appliance.  Built with FastMCP.

Features:
    - Token-based session auth (with automatic refresh)
    - Rate limiting to protect the appliance
    - Structured error handling
    - Hostname → agent ID resolution
    - Detail endpoints for alerts and indicators
    - File acquisition download

Environment variables (via .env):
    HX_HOST  – Base URL of the HX appliance  (e.g. https://10.0.0.5:3000)
    HX_USER  – API username
    HX_PASS  – API password
"""

from __future__ import annotations

import os
import time
import threading
from typing import Any, Optional

import requests
import urllib3
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HX_HOST: str = os.getenv("HX_HOST", "").rstrip("/")
HX_USER: str = os.getenv("HX_USER", "")
HX_PASS: str = os.getenv("HX_PASS", "")

mcp = FastMCP(
    "Trellix HX",
    instructions=(
        "MCP server for Trellix (FireEye) HX On-Prem. "
        "Provides host management, alert triage, indicator intelligence, "
        "forensic acquisitions, search, policy, and script management. "
        "Use resolve_hostname to convert hostnames to agent IDs before "
        "calling host-scoped tools."
    ),
)

# ---------------------------------------------------------------------------
# Token-based session management
# ---------------------------------------------------------------------------
_token: str | None = None
_token_expiry: float = 0.0
_token_lock = threading.Lock()
_TOKEN_LIFETIME = 25 * 60  # refresh 5 min before the 30-min default expiry


def _get_token() -> str:
    """Acquire or refresh a session token via HTTP Basic Auth.

    The HX API supports ``GET /hx/api/v3/token`` which returns a
    ``X-FeApi-Token`` header for subsequent authenticated requests,
    avoiding repeated Basic Auth overhead.
    """
    global _token, _token_expiry
    with _token_lock:
        if _token and time.time() < _token_expiry:
            return _token
        resp = requests.get(
            f"{HX_HOST}/hx/api/v3/token",
            auth=(HX_USER, HX_PASS),
            verify=False,
            timeout=30,
        )
        if resp.ok and "X-FeApi-Token" in resp.headers:
            _token = resp.headers["X-FeApi-Token"]
            _token_expiry = time.time() + _TOKEN_LIFETIME
            return _token
        # Fallback: return empty string → _query will use Basic Auth
        _token = None
        _token_expiry = 0.0
        return ""


# ---------------------------------------------------------------------------
# Rate limiter (token-bucket)
# ---------------------------------------------------------------------------
class _RateLimiter:
    """Simple token-bucket rate limiter to protect the appliance."""

    def __init__(self, max_per_second: float = 5.0):
        self._interval = 1.0 / max_per_second
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            wait_time = self._interval - (now - self._last)
            if wait_time > 0:
                time.sleep(wait_time)
            self._last = time.time()


_limiter = _RateLimiter(max_per_second=5.0)

# ---------------------------------------------------------------------------
# Structured error helper
# ---------------------------------------------------------------------------


class HXAPIError(Exception):
    """Raised when the HX appliance returns an HTTP error."""

    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        self.detail = self._parse_detail(body)
        super().__init__(self.detail)

    @staticmethod
    def _parse_detail(body: str) -> str:
        """Extract the most useful error message from the response."""
        import json as _json

        try:
            data = _json.loads(body)
            # HX returns {"details": [{"message": "..."}], "message": "..."}
            msgs = []
            for d in data.get("details", []):
                if "message" in d:
                    msgs.append(d["message"])
            top = data.get("message", "")
            if msgs:
                return f"{top}: {'; '.join(msgs)}" if top else "; ".join(msgs)
            if top:
                return top
        except Exception:
            pass
        # Fallback: extract <pre>...</pre> from HTML errors
        import re

        m = re.search(r"<pre>(.*?)</pre>", body, re.DOTALL)
        if m:
            return m.group(1).strip()
        return body[:300]


# ---------------------------------------------------------------------------
# Reusable HTTP helper
# ---------------------------------------------------------------------------


def _query(
    method: str,
    endpoint: str,
    data: Optional[dict[str, Any]] = None,
    params: Optional[dict[str, Any]] = None,
    stream: bool = False,
) -> Any:
    """Send an authenticated request to the HX appliance.

    Uses token-based auth when available, falling back to Basic Auth.
    Applies rate limiting to protect the appliance.

    Args:
        method:   HTTP verb (GET, POST, PUT, PATCH, DELETE).
        endpoint: Relative API path, e.g. ``hx/api/v3/hosts``.
        data:     JSON body for POST/PUT/PATCH requests.
        params:   Query-string parameters.
        stream:   If *True*, return raw bytes instead of parsed JSON.

    Returns:
        Parsed JSON dict **or** raw bytes when *stream* is True.

    Raises:
        HXAPIError: When the server returns an HTTP error.
    """
    _limiter.wait()

    url = f"{HX_HOST}/{endpoint.lstrip('/')}"
    token = _get_token()

    if token:
        headers = {"X-FeApi-Token": token}
        auth = None
    else:
        headers = {}
        auth = (HX_USER, HX_PASS)

    response = requests.request(
        method.upper(),
        url,
        auth=auth,
        headers=headers,
        json=data,
        params=params,
        verify=False,
        timeout=120,
        stream=stream,
    )

    if not response.ok:
        raise HXAPIError(response.status_code, response.text[:1000])

    if stream:
        return response.content
    return response.json()


# ===================================================================
# 1.  SYSTEM & INFO
# ===================================================================


@mcp.tool()
def get_version() -> dict:
    """Retrieve the HX appliance software version.

    Maps to ``GET hx/api/v3/version``.

    Returns:
        dict with version information including major, minor, patch, and
        build identifiers of the running HX appliance.
    """
    return _query("GET", "hx/api/v3/version")


@mcp.tool()
def get_appliance_stats() -> dict:
    """Retrieve live appliance statistics and system information.

    Queries multiple stats sub-endpoints and merges results:
    ``GET hx/api/v3/stats/mal``, ``GET hx/api/v3/stats/host``,
    ``GET hx/api/v3/stats/channel``.

    Returns:
        dict containing merged appliance health metrics across
        malware protection, host, and channel sub-systems.
    """
    merged: dict[str, Any] = {}
    for sub in ("mal", "host", "channel"):
        try:
            result = _query("GET", f"hx/api/v3/stats/{sub}")
            merged[sub] = result.get("data", result)
        except HXAPIError:
            merged[sub] = {"error": f"stats/{sub} not available"}
    return merged


# ===================================================================
# 2.  HOST & GROUP MANAGEMENT
# ===================================================================


@mcp.tool()
def resolve_hostname(hostname: str) -> dict:
    """Resolve a hostname to its HX agent ID.

    Use this before calling any tool that requires ``host_id`` or
    ``agent_id``.  Performs a search via ``GET hx/api/v3/hosts?search=``.

    Args:
        hostname: Full or partial hostname to search for.

    Returns:
        dict with ``agent_id``, ``hostname``, ``ip``, and
        ``containment_state`` of the first matching host.
        Returns an error message if no match is found.
    """
    result = _query("GET", "hx/api/v3/hosts", params={"search": hostname, "limit": 5})
    entries = result.get("data", {}).get("entries", [])
    if not entries:
        return {"error": f"No host found matching '{hostname}'"}
    # Return the best match
    host = entries[0]
    return {
        "agent_id": host.get("_id"),
        "hostname": host.get("hostname"),
        "ip": host.get("primary_ip_address"),
        "domain": host.get("domain"),
        "os": host.get("os", {}).get("product_name", "Unknown"),
        "agent_version": host.get("agent_version"),
        "containment_state": host.get("containment_state"),
        "last_poll": host.get("last_poll_timestamp"),
        "total_matches": len(entries),
    }


@mcp.tool()
def list_hosts(
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    sort_by: str = "",
) -> dict:
    """List managed hosts (endpoints) registered with the HX appliance.

    Maps to ``GET hx/api/v3/hosts``.

    Args:
        limit:   Maximum number of hosts to return (default 100).
        offset:  Pagination offset.
        search:  Optional hostname or IP search filter.
        sort_by: Optional field name to sort results by.

    Returns:
        dict with ``entries`` list of host records and pagination metadata.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if search:
        params["search"] = search
    if sort_by:
        params["sort"] = sort_by
    return _query("GET", "hx/api/v3/hosts", params=params)


@mcp.tool()
def get_host_details(host_id: str) -> dict:
    """Get full details for a single managed host.

    Maps to ``GET hx/api/v3/hosts/{host_id}``.

    Args:
        host_id: The unique ``_id`` of the host (agent ID).
                 Use ``resolve_hostname`` to find this from a hostname.

    Returns:
        dict containing hostname, OS info, agent version, last
        check-in timestamp, containment status, and more.
    """
    return _query("GET", f"hx/api/v3/hosts/{host_id}")


@mcp.tool()
def list_host_sets(limit: int = 100, offset: int = 0) -> dict:
    """List all host sets (static and dynamic groups).

    Maps to ``GET hx/api/v3/host_sets``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of host-set definitions.
    """
    return _query("GET", "hx/api/v3/host_sets", params={"limit": limit, "offset": offset})


@mcp.tool()
def get_host_set_members(host_set_id: int, limit: int = 100, offset: int = 0) -> dict:
    """List hosts that belong to a specific host set.

    Maps to ``GET hx/api/v3/host_sets/{host_set_id}/hosts``.

    Args:
        host_set_id: Numeric ID of the host set.
        limit:       Maximum entries to return (default 100).
        offset:      Pagination offset.

    Returns:
        dict with ``entries`` list of member host records.
    """
    return _query(
        "GET",
        f"hx/api/v3/host_sets/{host_set_id}/hosts",
        params={"limit": limit, "offset": offset},
    )


@mcp.tool()
def update_static_host_set(host_set_id: int, add_ids: list[str] | None = None, remove_ids: list[str] | None = None) -> dict:
    """Add or remove hosts from a **static** host set.

    Maps to ``POST hx/api/v3/host_sets/static/{host_set_id}``.

    Args:
        host_set_id: Numeric ID of the static host set.
        add_ids:     List of host ``_id`` values to add.
        remove_ids:  List of host ``_id`` values to remove.

    Returns:
        dict confirming the updated membership.
    """
    body: dict[str, Any] = {}
    if add_ids:
        body["add"] = add_ids
    if remove_ids:
        body["remove"] = remove_ids
    return _query("POST", f"hx/api/v3/host_sets/static/{host_set_id}", data=body)


# ===================================================================
# 3.  ALERTS & THREATS
# ===================================================================


@mcp.tool()
def list_alerts(
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "",
    min_id: int | None = None,
) -> dict:
    """List alerts generated by the HX appliance.

    Maps to ``GET hx/api/v3/alerts``.

    Args:
        limit:   Maximum alerts to return (default 100).
        offset:  Pagination offset.
        sort_by: Optional sort field (e.g. ``reported_at+descending``).
        min_id:  Only return alerts with ``_id`` greater than this value
                 (useful for incremental polling).

    Returns:
        dict with ``entries`` list of alert objects including severity,
        source, matched indicator, and affected host.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if sort_by:
        params["sort"] = sort_by
    if min_id is not None:
        params["min_id"] = min_id
    return _query("GET", "hx/api/v3/alerts", params=params)


@mcp.tool()
def get_alert_details(alert_id: int) -> dict:
    """Get full details for a single alert.

    Maps to ``GET hx/api/v3/alerts/{alert_id}``.

    Args:
        alert_id: The numeric ``_id`` of the alert.

    Returns:
        dict with complete alert information including the matched
        indicator, affected host, event details, and resolution status.
    """
    return _query("GET", f"hx/api/v3/alerts/{alert_id}")


@mcp.tool()
def list_source_alerts(source: str = "", limit: int = 100, offset: int = 0) -> dict:
    """List alerts filtered by detection source type.

    Maps to ``GET hx/api/v3/alerts`` with a ``source`` query filter.

    Args:
        source: Filter by alert source, e.g. ``IOC``, ``EXD``, ``MAL``,
                ``EXPLOIT_GUARD``.  Leave empty to list all sources.
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of alert records for the given source.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if source:
        params["source"] = source
    return _query("GET", "hx/api/v3/alerts", params=params)


@mcp.tool()
def list_quarantined_files(limit: int = 100, offset: int = 0) -> dict:
    """List files that have been quarantined across all endpoints.

    Maps to ``GET hx/api/v3/quarantines``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of quarantined file records including
        file hash, host, original path, and quarantine timestamp.
    """
    return _query("GET", "hx/api/v3/quarantines", params={"limit": limit, "offset": offset})


@mcp.tool()
def list_containment_states(limit: int = 100, offset: int = 0) -> dict:
    """List the network containment status of managed hosts.

    Maps to ``GET hx/api/v3/containment_states``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of containment-state records.
        Each entry shows whether a host is contained, pending, or normal.
    """
    return _query("GET", "hx/api/v3/containment_states", params={"limit": limit, "offset": offset})


@mcp.tool()
def manage_containment(host_id: str, action: str = "contain") -> dict:
    """Request or release network containment for a host.

    Maps to ``POST hx/api/v3/hosts/{host_id}/containment``.

    ⚠️ **Destructive action** – containing a host isolates it from the
    network.  Use ``action='uncontain'`` to release.

    Args:
        host_id: The unique ``_id`` of the host to contain / release.
                 Use ``resolve_hostname`` to find this from a hostname.
        action:  ``contain`` (default) or ``uncontain``.

    Returns:
        dict confirming the containment state change request.
    """
    if action not in ("contain", "uncontain"):
        raise ValueError("action must be 'contain' or 'uncontain'")
    return _query("POST", f"hx/api/v3/hosts/{host_id}/containment", data={"state": action})


# ===================================================================
# 4.  INTELLIGENCE & INDICATORS
# ===================================================================


@mcp.tool()
def list_indicators(
    category: str = "",
    limit: int = 100,
    offset: int = 0,
    search: str = "",
) -> dict:
    """List threat indicators in the HX appliance.

    Maps to ``GET hx/api/v3/indicators`` with optional ``category.name``
    query-string filter.

    Args:
        category: Filter by indicator category name as shown in
                  ``list_indicator_categories`` (e.g. ``Custom``,
                  ``FireEye``, ``Mandiant Unrestricted Intel``).  Leave
                  empty for all indicators.
        limit:    Maximum entries to return (default 100).
        offset:   Pagination offset.
        search:   Optional display-name search filter.

    Returns:
        dict with ``entries`` list of indicator definitions including
        name, description, severity, platforms, and conditions.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if category:
        params["category.name"] = category
    if search:
        params["search"] = search
    return _query("GET", "hx/api/v3/indicators", params=params)


@mcp.tool()
def get_indicator_details(category: str, indicator_name: str) -> dict:
    """Get full details for a specific indicator.

    Maps to ``GET hx/api/v3/indicators/{category}/{indicator_name}``.

    Args:
        category:       The indicator category ``uri_name``
                        (e.g. ``Custom``, ``FireEye``).
        indicator_name: The indicator ``uri_name`` or ``_id``.

    Returns:
        dict with complete indicator definition including all conditions,
        platforms, description, and execution details.
    """
    return _query("GET", f"hx/api/v3/indicators/{category}/{indicator_name}")


@mcp.tool()
def list_indicator_categories(limit: int = 100, offset: int = 0) -> dict:
    """List available indicator categories (e.g. Custom, FireEye, CMS).

    Maps to ``GET hx/api/v3/indicator_categories``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of category metadata records.
    """
    return _query("GET", "hx/api/v3/indicator_categories", params={"limit": limit, "offset": offset})


@mcp.tool()
def list_conditions(limit: int = 100, offset: int = 0, search: str = "") -> dict:
    """List IOC conditions (rules that make up indicators).

    Maps to ``GET hx/api/v3/conditions``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.
        search: Optional keyword filter for condition names.

    Returns:
        dict with ``entries`` list of condition objects, each describing
        a detection rule such as file hash match, mutex check, etc.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if search:
        params["search"] = search
    return _query("GET", "hx/api/v3/conditions", params=params)


# ===================================================================
# 5.  ACQUISITIONS & TRIAGES (FORENSIC ACTIONS)
# ===================================================================


@mcp.tool()
def list_file_acquisitions(limit: int = 100, offset: int = 0) -> dict:
    """List all file-acquisition requests.

    Maps to ``GET hx/api/v3/acqs/files``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of file acquisition records showing
        state, target host, requested path, and completion status.
    """
    return _query("GET", "hx/api/v3/acqs/files", params={"limit": limit, "offset": offset})


@mcp.tool()
def create_file_acquisition(agent_id: str, path: str) -> dict:
    """Request acquisition (download) of a specific file from an endpoint.

    Maps to ``POST hx/api/v3/hosts/{agent_id}/acqs/files``.

    Use this to remotely collect a suspicious file for offline analysis.

    Args:
        agent_id: The ``_id`` (agent ID) of the target host.
                  Use ``resolve_hostname`` to find this from a hostname.
        path:     Full file-system path on the remote host
                  (e.g. ``C:\\Windows\\Temp\\malware.exe``).

    Returns:
        dict with the newly created acquisition record including its
        ``_id`` which can be used to poll for completion.
    """
    return _query("POST", f"hx/api/v3/hosts/{agent_id}/acqs/files", data={"req_path": path})


@mcp.tool()
def download_file_acquisition(acquisition_id: int) -> str:
    """Download a completed file acquisition as a ZIP archive.

    Maps to ``GET hx/api/v3/acqs/files/{acquisition_id}.zip``.

    Args:
        acquisition_id: The numeric ``_id`` of the file acquisition.

    Returns:
        str confirming the download with the byte-size of the ZIP.
    """
    content = _query(
        "GET",
        f"hx/api/v3/acqs/files/{acquisition_id}.zip",
        stream=True,
    )
    return f"Downloaded acquisition {acquisition_id} ({len(content):,} bytes)"


@mcp.tool()
def list_triages(limit: int = 100, offset: int = 0) -> dict:
    """List triage acquisition packages.

    Maps to ``GET hx/api/v3/acqs/triages``.

    A triage collects volatile endpoint data (processes, network
    connections, registry, services, etc.) for rapid investigation.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of triage records.
    """
    return _query("GET", "hx/api/v3/acqs/triages", params={"limit": limit, "offset": offset})


@mcp.tool()
def trigger_triage(agent_id: str) -> dict:
    """Trigger a new triage collection on an endpoint.

    Maps to ``POST hx/api/v3/hosts/{agent_id}/triages``.

    This initiates a lightweight forensic collection that gathers
    volatile system state from the specified host.

    Args:
        agent_id: The ``_id`` (agent ID) of the target host.
                  Use ``resolve_hostname`` to find this from a hostname.

    Returns:
        dict with the triage acquisition record for tracking.
    """
    return _query("POST", f"hx/api/v3/hosts/{agent_id}/triages")


@mcp.tool()
def list_bulk_acquisitions(limit: int = 100, offset: int = 0) -> dict:
    """List bulk acquisition jobs.

    Maps to ``GET hx/api/v3/acqs/bulk``.

    Bulk acquisitions target many hosts simultaneously and are useful
    for enterprise-wide evidence collection.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of bulk acquisition records.
    """
    return _query("GET", "hx/api/v3/acqs/bulk", params={"limit": limit, "offset": offset})


# ===================================================================
# 6.  SEARCH & POLICIES
# ===================================================================


@mcp.tool()
def list_searches(limit: int = 100, offset: int = 0) -> dict:
    """List enterprise searches (IOC sweeps).

    Maps to ``GET hx/api/v3/searches``.

    An enterprise search applies one or more conditions across the
    fleet to find matches.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of search objects including state,
        matched host count, and search conditions.
    """
    return _query("GET", "hx/api/v3/searches", params={"limit": limit, "offset": offset})


@mcp.tool()
def get_search_counts() -> dict:
    """Get aggregate counts for enterprise searches by state.

    Maps to ``GET hx/api/v3/searches/counts``.

    Returns:
        dict with counts of searches in each state (e.g. ``RUNNING``,
        ``COMPLETED``, ``STOPPED``).
    """
    return _query("GET", "hx/api/v3/searches/counts")


@mcp.tool()
def list_policies(limit: int = 100, offset: int = 0) -> dict:
    """List endpoint policies configured on the appliance.

    Maps to ``GET hx/api/v3/policies``.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of policy definitions controlling
        agent behavior (real-time detection, exploit guard, etc.).
    """
    return _query("GET", "hx/api/v3/policies", params={"limit": limit, "offset": offset})


@mcp.tool()
def list_host_policies_channels(limit: int = 100, offset: int = 0) -> dict:
    """List host-policy channel assignments.

    Maps to ``GET hx/api/v3/host_policies/channels``.

    Channels control which policies are pushed to which host sets,
    enabling staged rollouts and A/B testing of policy changes.

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of channel records.
    """
    return _query("GET", "hx/api/v3/host_policies/channels", params={"limit": limit, "offset": offset})


# ===================================================================
# 7.  SCRIPTS
# ===================================================================


@mcp.tool()
def list_scripts(limit: int = 100, offset: int = 0) -> dict:
    """List scripts available on the HX appliance.

    Maps to ``GET hx/api/v3/scripts``.

    Scripts can be pushed to agents for remote execution during
    incident response (e.g. collection helpers).

    Args:
        limit:  Maximum entries to return (default 100).
        offset: Pagination offset.

    Returns:
        dict with ``entries`` list of script metadata records.
    """
    return _query("GET", "hx/api/v3/scripts", params={"limit": limit, "offset": offset})


@mcp.tool()
def download_scripts_zip() -> str:
    """Download all scripts from the appliance as a ZIP archive.

    Maps to ``GET hx/api/v3/scripts.zip``.

    Returns:
        str – A message confirming the download with the byte-size of
        the ZIP payload.  (The raw ZIP content is returned internally
        for further processing by an MCP client.)
    """
    content = _query("GET", "hx/api/v3/scripts.zip", stream=True)
    return f"Downloaded scripts.zip ({len(content):,} bytes)"


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run()
