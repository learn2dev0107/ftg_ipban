"""FortiOS REST client for the quarantine (banned users) monitor.

Endpoints used:
  GET  /api/v2/monitor/user/banned              list banned IPs (FortiOS 6.2+)
  GET  /api/v2/monitor/user/banned/select       same, older FortiOS (fallback on 404)
  POST /api/v2/monitor/user/banned/add_users    {"ip_addresses": [...], "expiry": seconds}
  POST /api/v2/monitor/user/banned/clear_users  {"ip_addresses": [...]}
  POST /api/v2/monitor/user/banned/clear_all
  GET  /api/v2/cmdb/system/vdom                 VDOM names, to expand vdoms = all

Every call takes `vdom`; None = the API admin's default VDOM.
"""
import sys
from typing import Any, List, Optional

import requests
import urllib3

from fwban.config import Context

BASE = "/api/v2/monitor/user/banned"


class APIError(Exception):
    def __init__(self, method: str, path: str, status: int, body: Any):
        self.status = status
        self.body = body
        if isinstance(body, dict):
            # FortiOS often only says status=error plus a numeric code; show all of it
            keep = ("error", "cli_error", "message", "vdom", "http_status", "build", "version")
            detail = ", ".join(f"{k}={body[k]}" for k in keep if k in body) or str(body)
        else:
            detail = body or "(empty body)"
        super().__init__(f"{method} {path} -> HTTP {status}: {detail}")


class FortiGate:
    def __init__(self, ctx: Context, verbose: bool = False):
        self.ctx = ctx
        self.verbose = verbose
        self.session = requests.Session()
        self.session.trust_env = False          # only the proxy from the context is used
        if ctx.proxy:
            self.session.proxies = {"http": ctx.proxy, "https": ctx.proxy}
        self.session.verify = ctx.verify_ssl
        self.session.headers.update({
            "Authorization": f"Bearer {ctx.token}",
            "Accept": "application/json",
        })
        if not ctx.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _call(self, method: str, path: str, json_body: Optional[dict] = None,
              vdom: Optional[str] = None) -> dict:
        params = {"vdom": vdom} if vdom else {}
        resp = self.session.request(method, self.ctx.base_url + path, params=params,
                                    json=json_body, timeout=self.ctx.timeout)
        if self.verbose:
            extra = f" {json_body}" if json_body else ""
            print(f"> {method} {resp.url}{extra} -> HTTP {resp.status_code}", file=sys.stderr)
            print(f"< {resp.text[:1000]}", file=sys.stderr)
        try:
            body = resp.json()
        except ValueError:
            body = resp.text[:500]
        if not resp.ok or (isinstance(body, dict) and body.get("status") == "error"):
            raise APIError(method, path, resp.status_code, body)
        return body if isinstance(body, dict) else {"results": body}

    # --- quarantine ---------------------------------------------------------

    def list_vdoms(self) -> List[str]:
        body = self._call("GET", "/api/v2/cmdb/system/vdom")
        return [r["name"] for r in body.get("results", []) if r.get("name")]

    def list_banned(self, vdom: Optional[str] = None) -> List[dict]:
        try:
            body = self._call("GET", BASE, vdom=vdom)
        except APIError as e:
            if e.status != 404:
                raise
            body = self._call("GET", BASE + "/select", vdom=vdom)
        return body.get("results", []) or []

    def add_banned(self, ips: List[str], expiry: int, vdom: Optional[str] = None) -> dict:
        return self._call("POST", BASE + "/add_users", {"ip_addresses": ips, "expiry": expiry}, vdom)

    def delete_banned(self, ips: List[str], vdom: Optional[str] = None) -> dict:
        return self._call("POST", BASE + "/clear_users", {"ip_addresses": ips}, vdom)

    def delete_all_banned(self, vdom: Optional[str] = None) -> dict:
        return self._call("POST", BASE + "/clear_all", vdom=vdom)
