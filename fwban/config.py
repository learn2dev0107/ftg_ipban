"""Contexts, kubeconfig-style.

Config file: $FWBAN_CONFIG, else ~/.config/fwban/config.ini.
Each [context NAME] section describes one FortiGate (+ optional VDOM).
[fwban] current-context picks the default; --context overrides it.

With no config file at all, a single context is built from environment
variables: FGT_HOST, FGT_API_TOKEN, FGT_PORT, FGT_VDOM, FGT_VERIFY_SSL, FGT_PROXY.
"""
import configparser
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

_TRUE = {"1", "true", "yes", "on"}
_PREFIX = "context "


def config_path() -> Path:
    p = os.getenv("FWBAN_CONFIG")
    return Path(p).expanduser() if p else Path.home() / ".config" / "fwban" / "config.ini"


@dataclass(frozen=True)
class Context:
    name: str
    host: str
    port: int = 443
    token: str = ""
    vdoms: Tuple[str, ...] = ()        # () = admin's default VDOM; ("all",) = every VDOM
    verify_ssl: bool = False
    timeout: int = 15
    proxy: str = ""

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"


class ConfigError(Exception):
    pass


def split_vdoms(text: str) -> Tuple[str, ...]:
    """'A, B' -> ('A', 'B'). 'all' anywhere -> ('all',)."""
    names = tuple(v.strip() for v in (text or "").split(",") if v.strip())
    return ("all",) if any(v.lower() == "all" for v in names) else names


def _read() -> configparser.ConfigParser:
    cp = configparser.ConfigParser(default_section="__none__")
    cp.read(config_path(), encoding="utf-8")
    return cp


def _context_from_section(name: str, sec) -> Context:
    host = sec.get("host", "").strip()
    if not host:
        raise ConfigError(f"context {name}: missing host")
    token = sec.get("token", "").strip()
    token_env = sec.get("token_env", "").strip()
    if token_env:
        token = os.getenv(token_env, "").strip()
        if not token:
            raise ConfigError(f"context {name}: environment variable {token_env} is not set")
    if not token:
        raise ConfigError(f"context {name}: set token_env (recommended) or token")
    return Context(
        name=name,
        host=host,
        port=sec.getint("port", 443),
        token=token,
        vdoms=split_vdoms(sec.get("vdoms", "") or sec.get("vdom", "")),
        verify_ssl=sec.get("verify_ssl", "false").strip().lower() in _TRUE,
        timeout=sec.getint("timeout", 15),
        proxy=sec.get("proxy", "").strip(),
    )


def _env_context() -> Context:
    host = os.getenv("FGT_HOST", "").strip()
    token = os.getenv("FGT_API_TOKEN", "").strip()
    if not host or not token:
        raise ConfigError(f"no config file at {config_path()} and FGT_HOST / FGT_API_TOKEN not set")
    return Context(
        name="(env)",
        host=host,
        port=int(os.getenv("FGT_PORT", "443")),
        token=token,
        vdoms=split_vdoms(os.getenv("FGT_VDOM", "")),
        verify_ssl=os.getenv("FGT_VERIFY_SSL", "false").strip().lower() in _TRUE,
        timeout=int(os.getenv("FGT_TIMEOUT", "15")),
        proxy=os.getenv("FGT_PROXY", "").strip(),
    )


def context_names() -> Dict[str, configparser.SectionProxy]:
    cp = _read()
    return {s[len(_PREFIX):].strip(): cp[s] for s in cp.sections() if s.startswith(_PREFIX)}


def current_context_name() -> str:
    cp = _read()
    return cp.get("fwban", "current-context", fallback="").strip()


def load_context(name: Optional[str] = None) -> Context:
    contexts = context_names()
    if not contexts:
        if name:
            raise ConfigError(f"--context {name} given but no contexts in {config_path()}")
        return _env_context()
    name = name or current_context_name()
    if not name:
        if len(contexts) == 1:
            name = next(iter(contexts))
        else:
            raise ConfigError("no current-context set; run: fwban config use-context NAME")
    if name not in contexts:
        raise ConfigError(f"unknown context {name!r}. Known: {', '.join(contexts)}")
    return _context_from_section(name, contexts[name])


def use_context(name: str) -> None:
    if name not in context_names():
        raise ConfigError(f"unknown context {name!r}")
    cp = _read()
    if not cp.has_section("fwban"):
        cp.add_section("fwban")
    cp.set("fwban", "current-context", name)
    path = config_path()
    with open(path, "w", encoding="utf-8") as f:
        cp.write(f)
