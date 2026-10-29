"""fwban: kubectl-style CLI for the FortiGate quarantine (banned IP) list.

  fwban get [-o table|wide|json] [IP ...]
  fwban add IP [IP ...] [--expiry 1h] [-f FILE]
  fwban delete IP [IP ...] [-f FILE] | --all
  fwban config get-contexts | current-context | use-context NAME
"""
import argparse
import ipaddress
import json
import re
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple

import requests

from fwban import __version__
from fwban import config as cfg
from fwban.client import APIError, FortiGate

CHUNK = 100          # IPs per API call
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


# --- helpers ----------------------------------------------------------------

def parse_expiry(text: str) -> int:
    """'3600', '30m', '1h30m', '2d' -> seconds. '0' / 'never' -> 0 (no expiry)."""
    t = text.strip().lower()
    if t in ("0", "never", "forever", "permanent"):
        return 0
    if t.isdigit():
        return int(t)
    parts = re.findall(r"(\d+)([smhdw])", t)
    if not parts or "".join(n + u for n, u in parts) != t:
        raise argparse.ArgumentTypeError(f"bad expiry {text!r} (examples: 3600, 30m, 1h30m, 7d, never)")
    return sum(int(n) * _UNITS[u] for n, u in parts)


def parse_days(text: str) -> int:
    """Day column of a ban file: '7' = 7 days, '0' / 'never' = permanent,
    or a duration with a unit such as '12h' or '2w'."""
    t = text.strip().lower()
    if t.isdigit():
        return int(t) * 86400
    return parse_expiry(t)


def read_entries(args_ips: Iterable[str], files: Iterable[str]) -> List[Tuple[str, Optional[int]]]:
    """IPs from the command line and from ban files, as (ip, expiry_seconds).

    File format, one entry per line ('#' starts a comment):
        203.0.113.7,7        ban for 7 days
        198.51.100.9         no day count -> --expiry (default 30 days)
        2001:db8::1,never    permanent
    expiry is None when no day count was given.
    """
    entries, seen, bad = [], set(), []

    def take(ip_text: str, expiry: Optional[int], where: str) -> None:
        try:
            ip = str(ipaddress.ip_address(ip_text.strip()))
        except ValueError:
            bad.append(f"{where}{ip_text.strip()!r}")
            return
        if ip not in seen:
            seen.add(ip)
            entries.append((ip, expiry))

    for item in args_ips:
        take(item, None, "")
    for path in files or []:
        fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
        with fh:
            for n, line in enumerate(fh, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                where = f"{path}:{n}: "
                ip_text, _, days = line.partition(",")
                expiry = None
                if days.strip():
                    try:
                        expiry = parse_days(days)
                    except argparse.ArgumentTypeError:
                        bad.append(f"{where}bad day count {days.strip()!r}")
                        continue
                take(ip_text, expiry, where)
    if bad:
        raise SystemExit("error: invalid entries (single IPs only, subnets are not supported):\n  "
                         + "\n  ".join(bad))
    return entries


def collect_ips(args_ips: Iterable[str], files: Iterable[str]) -> List[str]:
    """Just the IPs (the day column, if any, is ignored)."""
    return [ip for ip, _ in read_entries(args_ips, files)]


def chunks(items: List[str], n: int = CHUNK):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec < 0:
        return "-"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if sec >= size:
            major, rest = divmod(sec, size)
            sub = {"d": ("h", 3600), "h": ("m", 60), "m": ("s", 1)}[unit]
            minor = rest // sub[1]
            return f"{major}{unit}{minor}{sub[0]}" if minor and major < 10 else f"{major}{unit}"
    return f"{sec}s"


def fmt_time(epoch) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch)) if epoch else "-"


def print_table(headers: List[str], rows: List[List[str]]) -> None:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    print("   ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
    for r in rows:
        print("   ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())


def connect(args) -> FortiGate:
    return FortiGate(cfg.load_context(args.context), verbose=args.verbose)


def target_vdoms(args, fgt: FortiGate, write: bool) -> List[Optional[str]]:
    """VDOMs a command acts on. [None] = the API admin's default VDOM.

    --vdom (comma list or 'all') wins over the context's vdoms. Reads cover every
    VDOM of the context; writes need an explicit --vdom when there are several.
    """
    wanted = cfg.split_vdoms(args.vdom) if args.vdom else fgt.ctx.vdoms
    if not wanted:
        return [None]
    if write and not args.vdom and (len(wanted) > 1 or wanted == ("all",)):
        raise SystemExit(
            f"error: context {fgt.ctx.name} covers several VDOMs ({', '.join(wanted)}). "
            f"Choose with --vdom NAME[,NAME...], or --vdom all for every one.")
    if wanted == ("all",):
        names = fgt.list_vdoms()
        if not names:
            raise SystemExit("error: FortiGate returned no VDOM names")
        return names
    return list(wanted)


# --- commands ---------------------------------------------------------------

def cmd_get(args) -> int:
    fgt = connect(args)
    vdoms = target_vdoms(args, fgt, write=False)
    wanted = set(collect_ips(args.ips, [])) if args.ips else None
    items = []
    for v in vdoms:
        for i in fgt.list_banned(v):
            if wanted is None or i.get("ip_address") in wanted:
                items.append(i)

    if args.output == "json":
        print(json.dumps(items, indent=2))
        return 0
    if not items:
        print("No quarantined IPs found.", file=sys.stderr)
        return 0

    now = time.time()
    wide = args.output == "wide"
    headers = ["IP", "SOURCE", "CREATED", "AGE", "EXPIRES-IN", "EXPIRES"] if wide else ["IP", "EXPIRES-IN"]
    rows = []
    for i in sorted(items, key=lambda x: -(x.get("created") or 0)):
        created, expires = i.get("created") or 0, i.get("expires") or 0
        ip = str(i.get("ip_address", "?"))
        expires_in = fmt_duration(expires - now) if expires else "never"
        if wide:
            row = [ip, str(i.get("source") or i.get("cause") or "-"), fmt_time(created),
                   fmt_duration(now - created) if created else "-", expires_in,
                   fmt_time(expires) if expires else "never"]
        else:
            row = [ip, expires_in]
        rows.append(row)
    print_table(headers, rows)
    return 0


def cmd_add(args) -> int:
    entries = read_entries(args.ips, args.filename)
    if not entries:
        raise SystemExit("error: give at least one IP (or -f FILE)")
    # add_users takes one expiry per call, so group the IPs by expiry
    groups: Dict[int, List[str]] = {}
    for ip, expiry in entries:
        groups.setdefault(args.expiry if expiry is None else expiry, []).append(ip)

    fgt = connect(args)
    vdoms = target_vdoms(args, fgt, write=True)
    if not args.dry_run:
        for v in vdoms:
            for expiry, ips in groups.items():
                for part in chunks(ips):
                    fgt.add_banned(part, expiry, v)
    for ip, expiry in entries:
        sec = args.expiry if expiry is None else expiry
        ttl = "never expires" if sec == 0 else f"expires in {fmt_duration(sec)}"
        print(f"{ip} would be added ({ttl}) (dry run)" if args.dry_run else f"{ip} added ({ttl})")
    return 0


def cmd_delete(args) -> int:
    fgt = connect(args)
    if args.all:
        if args.ips or args.filename:
            raise SystemExit("error: --all cannot be combined with IPs")
        vdoms = target_vdoms(args, fgt, write=True)
        where = f"{fgt.ctx.name} ({fgt.ctx.host})"
        if args.dry_run:
            print(f"all quarantine entries on {where} would be deleted (dry run)")
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                raise SystemExit("error: --all needs --yes when not run interactively")
            if input(f"Delete ALL quarantined IPs on {where}? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return 1
        for v in vdoms:
            fgt.delete_all_banned(v)
        print(f"all quarantine entries deleted on {where}")
        return 0

    ips = collect_ips(args.ips, args.filename)
    if not ips:
        raise SystemExit("error: give at least one IP (or -f FILE, or --all)")
    vdoms = target_vdoms(args, fgt, write=True)
    if args.dry_run:
        for ip in ips:
            print(f"{ip} would be deleted (dry run)")
        return 0
    present = set()
    for v in vdoms:
        present |= {i.get("ip_address") for i in fgt.list_banned(v)}
        for part in chunks(ips):
            fgt.delete_banned(part, v)
    for ip in ips:
        print(f"{ip} deleted{'' if ip in present else ' (was not in quarantine)'}")
    return 0


def cmd_vdoms(args) -> int:
    fgt = connect(args)
    configured = set(fgt.ctx.vdoms)
    names = fgt.list_vdoms()
    for name in names:
        print(f"{name}{'   (in context)' if name in configured else ''}")
    missing = configured - set(names) - {"all"}
    if missing:
        print(f"warning: context lists VDOM(s) not on this firewall: {', '.join(sorted(missing))}",
              file=sys.stderr)
        return 1
    return 0


def cmd_config(args) -> int:
    if args.action == "get-contexts":
        names = cfg.context_names()
        if not names:
            print(f"No contexts in {cfg.config_path()}", file=sys.stderr)
            return 0
        current = cfg.current_context_name()
        rows = [["*" if n == current else "", n, s.get("host", ""), s.get("port", "443"),
                 ",".join(cfg.split_vdoms(s.get("vdoms", "") or s.get("vdom", ""))) or "(default)"]
                for n, s in names.items()]
        print_table(["CURRENT", "NAME", "HOST", "PORT", "VDOMS"], rows)
    elif args.action == "current-context":
        print(cfg.current_context_name() or "(none)")
    elif args.action == "use-context":
        if not args.name:
            raise SystemExit("error: use-context needs a NAME")
        cfg.use_context(args.name)
        print(f'Switched to context "{args.name}".')
    elif args.action == "view":
        print(f"# {cfg.config_path()}")
        try:
            print(re.sub(r"(?m)^(\s*token\s*=\s*).+$", r"\1<redacted>",
                         cfg.config_path().read_text(encoding="utf-8")))
        except FileNotFoundError:
            print("(file does not exist)")
    return 0


# --- argument parsing -------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--context", help="context from the config file (default: current-context)")
    common.add_argument("--vdom", help="VDOM(s) to act on: NAME, NAME1,NAME2, or all "
                        "(default: the context's vdoms)")
    common.add_argument("-v", "--verbose", action="store_true",
                        help="print each API request (method, full URL with ?vdom=, status) to stderr")

    p = argparse.ArgumentParser(
        prog="fwban",
        description="kubectl-style CLI for the FortiGate quarantine (banned IP) list.",
        epilog="examples:\n"
               "  fwban get\n"
               "  fwban get -o wide\n"
               "  fwban add 203.0.113.7 198.51.100.9 --expiry 1h\n"
               "  fwban add -f banned.txt               # lines: ip or ip,days (default 30 days)\n"
               "  fwban delete 203.0.113.7\n"
               "  fwban add 203.0.113.7 --context core-fw --vdom Inbound\n"
               "  fwban add 203.0.113.7 --vdom all      # every VDOM on the firewall\n"
               "  fwban delete --all --yes --context lab\n"
               "  fwban config use-context prod-inbound",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"fwban {__version__}")
    sub = p.add_subparsers(dest="verb", metavar="COMMAND", required=True)

    g = sub.add_parser("get", aliases=["list"], parents=[common], help="list quarantined IPs")
    g.add_argument("ips", nargs="*", metavar="IP", help="show only these IPs")
    g.add_argument("-o", "--output", choices=["table", "wide", "json"], default="table")
    g.set_defaults(func=cmd_get)

    a = sub.add_parser("add", parents=[common], help="quarantine IPs")
    a.add_argument("ips", nargs="*", metavar="IP")
    a.add_argument("-f", "--filename", action="append", default=[],
                   help="ban file: one 'ip' or 'ip,days' per line ('-' = stdin); repeatable")
    a.add_argument("--expiry", type=parse_expiry, default=parse_expiry("30d"),
                   help="ban duration for IPs without their own day count: seconds or 30m / 1h / 7d, "
                        "'never' = permanent (default: 30d)")
    a.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    a.set_defaults(func=cmd_add)

    d = sub.add_parser("delete", aliases=["del", "rm"], parents=[common], help="release IPs from quarantine")
    d.add_argument("ips", nargs="*", metavar="IP")
    d.add_argument("-f", "--filename", action="append", default=[],
                   help="ban file (same format as add; the day column is ignored); repeatable")
    d.add_argument("--all", action="store_true", help="release every quarantined IP")
    d.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation with --all")
    d.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    d.set_defaults(func=cmd_delete)

    vd = sub.add_parser("vdoms", parents=[common], help="list the firewall's VDOM names (check your config)")
    vd.set_defaults(func=cmd_vdoms)

    c = sub.add_parser("config", help="manage contexts (like kubectl config)")
    c.add_argument("action", choices=["get-contexts", "current-context", "use-context", "view"])
    c.add_argument("name", nargs="?")
    c.set_defaults(func=cmd_config)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except cfg.ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
    except APIError as e:
        hint = {401: " (check the API token)", 403: " (API admin profile lacks permission, or trusted host blocks you)",
                404: " (endpoint not found: check FortiOS version / VDOM)",
                424: " (FortiOS 'failed dependency': usually the VDOM name is wrong or not allowed for this "
                     "API admin; run 'fwban vdoms' and retry with -v)"}.get(e.status, "")
        print(f"error: {e}{hint}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"error: cannot reach FortiGate: {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    return 1


if __name__ == "__main__":
    sys.exit(main())
