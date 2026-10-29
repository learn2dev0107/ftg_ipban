"""Offline tests: the FortiGate is replaced by a fake HTTP layer."""
import json
import time
from unittest import mock

import pytest

from fwban import cli


class FakeResp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.ok = status < 400
        self.text = json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def fgt(monkeypatch):
    monkeypatch.setenv("FWBAN_CONFIG", "/nonexistent")
    monkeypatch.setenv("FGT_HOST", "fw.test")
    monkeypatch.setenv("FGT_API_TOKEN", "tok")
    state = {"banned": {}, "calls": []}

    def request(self, method, url, params=None, json=None, timeout=None):
        state["calls"].append((method, url.split("fw.test:443")[1], params, json))
        path = url.split("fw.test:443")[1]
        if path == "/api/v2/cmdb/system/vdom":
            return FakeResp(200, {"results": [{"name": "root"}, {"name": "Inbound"}]})
        if method == "GET" and path.endswith("/user/banned"):
            now = int(time.time())
            return FakeResp(200, {"status": "success", "results": [
                {"ip_address": ip, "source": "Administrative", "created": now - 60,
                 "expires": now + e if e else 0} for ip, e in state["banned"].items()]})
        if path.endswith("/add_users"):
            for ip in json["ip_addresses"]:
                state["banned"][ip] = json["expiry"]
            return FakeResp(200, {"status": "success"})
        if path.endswith("/clear_users"):
            for ip in json["ip_addresses"]:
                state["banned"].pop(ip, None)
            return FakeResp(200, {"status": "success"})
        if path.endswith("/clear_all"):
            state["banned"].clear()
            return FakeResp(200, {"status": "success"})
        return FakeResp(404, {"status": "error"})

    with mock.patch("requests.Session.request", request):
        yield state


def test_expiry():
    assert cli.parse_expiry("3600") == 3600
    assert cli.parse_expiry("1h30m") == 5400
    assert cli.parse_expiry("never") == 0
    with pytest.raises(Exception):
        cli.parse_expiry("1x")


def test_add_list_delete(fgt, capsys):
    assert cli.main(["add", "203.0.113.7", "2001:db8::1", "--expiry", "1h", "--vdom", "root"]) == 0
    assert fgt["calls"][0][2] == {"vdom": "root"}
    assert fgt["calls"][0][3] == {"ip_addresses": ["203.0.113.7", "2001:db8::1"], "expiry": 3600}
    capsys.readouterr()

    assert cli.main(["get"]) == 0
    out = capsys.readouterr().out
    assert "203.0.113.7" in out and "EXPIRES-IN" in out and "SOURCE" not in out

    assert cli.main(["get", "-o", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2

    assert cli.main(["delete", "203.0.113.7", "198.51.100.1"]) == 0
    out = capsys.readouterr().out
    assert "198.51.100.1 deleted (was not in quarantine)" in out
    assert list(fgt["banned"]) == ["2001:db8::1"]

    assert cli.main(["delete", "--all", "--yes"]) == 0
    assert fgt["banned"] == {}


def test_rejects_subnet(fgt):
    with pytest.raises(SystemExit):
        cli.main(["add", "10.0.0.0/24"])
    assert fgt["calls"] == []


def test_api_error(fgt, capsys):
    with mock.patch("requests.Session.request", lambda *a, **k: FakeResp(401, {"status": "error"})):
        assert cli.main(["get"]) == 1
    assert "check the API token" in capsys.readouterr().err


@pytest.fixture
def multi(fgt, tmp_path, monkeypatch):
    conf = tmp_path / "config.ini"
    conf.write_text("[context fw]\nhost = fw.test\ntoken = tok\nvdoms = A, B\n")
    monkeypatch.setenv("FWBAN_CONFIG", str(conf))
    return fgt


def test_multi_vdom_write_needs_choice(multi):
    with pytest.raises(SystemExit) as e:
        cli.main(["add", "1.2.3.4"])
    assert "several VDOMs" in str(e.value)
    assert multi["calls"] == []


def test_multi_vdom_explicit(multi, capsys):
    assert cli.main(["add", "1.2.3.4", "--vdom", "B"]) == 0
    assert [c[2] for c in multi["calls"]] == [{"vdom": "B"}]
    assert cli.main(["get", "-o", "json"]) == 0                 # reads cover A and B
    assert [c[2] for c in multi["calls"][1:]] == [{"vdom": "A"}, {"vdom": "B"}]


def test_vdom_all_expands(multi, capsys):
    assert cli.main(["add", "1.2.3.4", "--vdom", "all"]) == 0
    vd = [c[2].get("vdom") for c in multi["calls"] if c[0] == "POST"]
    assert vd == ["root", "Inbound"]


def test_ban_file(fgt, tmp_path, capsys):
    f = tmp_path / "banned.txt"
    f.write_text("# comment\n203.0.113.7,7\n198.51.100.9\n192.0.2.1, never  # perm\n\n10.1.1.1,12h\n")
    assert cli.main(["add", "-f", str(f)]) == 0
    sent = {ip: c[3]["expiry"] for c in fgt["calls"] for ip in c[3]["ip_addresses"]}
    assert sent == {"203.0.113.7": 7 * 86400, "198.51.100.9": 30 * 86400,
                    "192.0.2.1": 0, "10.1.1.1": 12 * 3600}
    out = capsys.readouterr().out
    assert "198.51.100.9 added (expires in 30d)" in out and "192.0.2.1 added (never expires)" in out

    assert cli.main(["delete", "-f", str(f)]) == 0       # same file, day column ignored
    assert fgt["banned"] == {}


def test_ban_file_errors(fgt, tmp_path):
    f = tmp_path / "bad.txt"
    f.write_text("203.0.113.7,abc\n10.0.0.0/24,5\n")
    with pytest.raises(SystemExit) as e:
        cli.main(["add", "-f", str(f)])
    assert "bad.txt:1: bad day count" in str(e.value) and "bad.txt:2:" in str(e.value)
    assert fgt["calls"] == []


def test_list_alias(fgt, capsys):
    cli.main(["add", "203.0.113.7"])
    capsys.readouterr()
    assert cli.main(["list"]) == 0
    assert "203.0.113.7" in capsys.readouterr().out
