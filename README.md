# fwban

kubectl-style CLI to manage the FortiGate **quarantine** list
(the banned IPs shown in the Quarantine Monitor): list, ban and release IPs
over the FortiOS REST API, on one or more firewalls and VDOMs.

```bash
fwban list                               # what is banned right now
fwban add 203.0.113.7                    # ban for 30 days
fwban add -f banned.txt                  # ban a list (ip or ip,days per line)
fwban rm 203.0.113.7                     # release
fwban list --context dc-fw       # same, on another firewall
```

## Install

```bash
cd ~/Workspace/fwban
python3 -m venv .venv
.venv/bin/pip install -e '.[socks]'      # [socks] is needed for socks5:// / socks5h:// proxies
```

Run it as `.venv/bin/fwban`, or put it on your PATH once:

```bash
mkdir -p ~/.local/bin && ln -sf ~/Workspace/fwban/.venv/bin/fwban ~/.local/bin/fwban
fwban --help
```

## Configure

Two files in `~/.config/fwban/`:

| File | Holds | Permissions |
|---|---|---|
| `config.ini` | Where each firewall is (one *context* per firewall / VDOM) | `chmod 600` |
| `tokens.env` | The API tokens, as `export` lines | `chmod 600` |

### Contexts: `~/.config/fwban/config.ini`

Works like a kubeconfig. Start from [config.example.ini](config.example.ini):

```bash
mkdir -p ~/.config/fwban
cp config.example.ini ~/.config/fwban/config.ini && chmod 600 ~/.config/fwban/config.ini
```

Example with three firewalls:

```ini
[fwban]
# default context when --context is not given
current-context = core-fw

[context dr-fw]
host = 10.0.30.1
port = 8443
vdoms = External
token_env = DR_FW_TOKEN
proxy = socks5h://127.0.0.1:1081

[context core-fw]
host = 10.0.10.1
port = 8443
vdoms = Inbound
token_env = CORE_FW_TOKEN
proxy = socks5h://127.0.0.1:1080

[context dc-fw]
host = 10.0.20.1
port = 8443
vdoms = External
token_env = DC_FW_TOKEN
proxy = socks5h://127.0.0.1:1082
```

| Key | Meaning |
|---|---|
| `host` | Firewall IP or hostname (required) |
| *(comments)* | Only on their own line starting with `#`; text after a value is read as part of it |
| `port` | HTTPS admin port (default 443) |
| `vdoms` | VDOM(s): one name, `A, B`, or `all`. Omit for the API admin's default VDOM. `vdom = A` also works. |
| `token_env` | Name of the variable in `tokens.env` holding this firewall's token (letters, digits, `_` only) |
| `token` | The token itself, instead of `token_env` (not recommended) |
| `proxy` | `http://host:port`, `socks5h://host:port`, or omit for a direct connection |
| `verify_ssl` | `true` to check the firewall's certificate (default `false`) |
| `timeout` | Seconds per request (default 15) |

Check it:

```bash
fwban config get-contexts
fwban vdoms                      # VDOM names on the firewall match the config?
```

### Tokens: `~/.config/fwban/tokens.env`

Each context names an environment variable with `token_env`; the token itself lives in
a separate file that only you can read. One `export` line per context:

```bash
# ~/.config/fwban/tokens.env  (chmod 600)
# The name must match token_env in config.ini.
# No spaces around "=", value in single quotes, only letters/digits/_ in the name.

export DR_FW_TOKEN='paste-DR-token-here'
export CORE_FW_TOKEN='paste-core-token-here'
export DC_FW_TOKEN='paste-DC-token-here'
```

Create it and keep it private:

```bash
nano ~/.config/fwban/tokens.env
chmod 600 ~/.config/fwban/tokens.env
```

Load it in the current terminal, or in every new terminal via `~/.bashrc`:

```bash
source ~/.config/fwban/tokens.env
echo '[ -f ~/.config/fwban/tokens.env ] && source ~/.config/fwban/tokens.env' >> ~/.bashrc
```

Common mistakes:

| Error | Cause / fix |
|---|---|
| `bash: export: ... not a valid identifier` | Hyphen in the name (`Core-Fw_TOKEN`) or spaces around `=`. Use `CORE_FW_TOKEN='...'`. |
| `environment variable X is not set` | File not sourced in this terminal, or the name differs from `token_env`. |
| `HTTP 401` | Token wrong or regenerated on the firewall; update the file and `source` it again. |

### FortiGate side

The REST API admin needs:

- an admin profile with **read-write** access to *User & Device* (the quarantine endpoints);
- access to the VDOMs in your contexts (and global scope if you use `fwban vdoms` or `--vdom all`);
- your IP (or the proxy's) in its **trusted hosts**.

### Without a config file

A single context is taken from environment variables: `FGT_HOST`, `FGT_API_TOKEN`
(+ optional `FGT_PORT`, `FGT_VDOM`, `FGT_VERIFY_SSL`, `FGT_PROXY`).
`FWBAN_CONFIG=/path/to/config.ini` uses a different config file.

## Commands

```
fwban {get (list), add, delete (del, rm), vdoms, config} [options]
```

| Command | What it does | FortiOS API call |
|---|---|---|
| `get`, `list` | List quarantined IPs | `GET /api/v2/monitor/user/banned` |
| `add` | Quarantine (ban) IPs | `POST .../user/banned/add_users` |
| `delete`, `del`, `rm` | Release IPs from quarantine | `POST .../user/banned/clear_users` (`clear_all` with `--all`) |
| `vdoms` | List the firewall's VDOM names | `GET /api/v2/cmdb/system/vdom` |
| `config` | Manage contexts (which firewall to talk to) | none, local config file only |

### Options for every command except `config`

| Option | Meaning |
|---|---|
| `--context NAME` | Firewall to use, from the config file. Default: `current-context`. |
| `--vdom NAME` | VDOM to act on. Also `A,B` for several, or `all` for every VDOM on the firewall. Default: the context's `vdoms`. |
| `-v`, `--verbose` | Print every API request (method, full URL with `?vdom=`, HTTP status) and the reply to stderr. The token is never shown. |

### `get` (alias `list`): list quarantined IPs

```bash
fwban get                        # IP and time left
fwban get -o wide                # + source, created time, age, exact expiry
fwban get -o json                # raw FortiOS data
fwban get 203.0.113.7 192.0.2.1  # only these IPs (are they banned?)
fwban list                       # same as fwban get
```

| Column | Meaning |
|---|---|
| `IP` | Banned address |
| `EXPIRES-IN` | Time left, e.g. `28d`, `5h30m`; `never` = permanent |
| `SOURCE` (wide) | What banned it, e.g. `Administrative` (manual / API) or a security feature such as `IPS` |
| `CREATED` (wide) | When the ban started (local time) |
| `AGE` (wide) | How long ago that was |
| `EXPIRES` (wide) | Exact expiry date and time |

When the context has several VDOMs, `get` reads all of them.

### `add`: ban IPs

```bash
fwban add 203.0.113.7                      # 30 days (default)
fwban add 203.0.113.7 198.51.100.9 --expiry 1h
fwban add 203.0.113.7 --expiry never       # permanent
fwban add -f banned.txt                    # ban file, see below
fwban add -f banned.txt --dry-run          # show what would happen, change nothing
```

| Option | Meaning |
|---|---|
| `IP ...` | One or more single IPv4/IPv6 addresses (no subnets; the API doesn't accept them). |
| `-f FILE` | Ban file; repeatable; `-f -` reads stdin. |
| `--expiry` | Ban length for IPs without their own day count: seconds, or `30m`, `1h30m`, `7d`, `2w`; `never` or `0` = permanent. Default `30d`. |
| `--dry-run` | Print what would be banned, send no changes. |

Ban file format (example: [banned.example.txt](banned.example.txt)), one entry per line:

```
203.0.113.7,7        # 7 days
198.51.100.9         # no day count -> --expiry (default 30 days)
2001:db8::1,never    # permanent
10.1.1.1,12h         # a unit also works: m, h, d, w
```

`#` starts a comment. A bad line stops the whole run before anything is sent, and the error names the file and line.

If the context has several VDOMs, choose with `--vdom` (fwban won't guess where to ban).

### `delete` (aliases `del`, `rm`): release IPs

```bash
fwban delete 203.0.113.7
fwban rm -f banned.txt            # same ban file as add; day column ignored
fwban delete --all                # release everything (asks for confirmation)
fwban delete --all --yes          # no question (needed in scripts / cron)
fwban delete 203.0.113.7 --dry-run
```

| Option | Meaning |
|---|---|
| `IP ...` | Addresses to release. An IP that wasn't banned is reported as `(was not in quarantine)`. |
| `-f FILE` | Ban file; the day column is ignored. |
| `--all` | Release every quarantined IP in the selected VDOM(s). |
| `-y`, `--yes` | Skip the confirmation for `--all`. |
| `--dry-run` | Print what would be released, send no changes. |

Same VDOM rule as `add`: with several VDOMs in the context, choose with `--vdom`.

### `vdoms`: check VDOM names

```bash
fwban vdoms
fwban vdoms --context core-fw
```

Lists the VDOMs that exist on the firewall and marks the ones your context uses with
`(in context)`. If the context names a VDOM that doesn't exist, it prints a warning and
exits with code 1. Use it when a command fails with HTTP 424 (usually a wrong VDOM name).
The API admin needs access to the global VDOM list for this to work.

### `config`: manage contexts

| Action | What it does |
|---|---|
| `fwban config get-contexts` | Table of all contexts (name, host, port, VDOMs); `*` marks the current one. |
| `fwban config current-context` | Print the current context's name. |
| `fwban config use-context NAME` | Make `NAME` the default for every command. This rewrites the config file, so comments in it are lost. |
| `fwban config view` | Print the config file, with `token =` values hidden. |

Use `--context NAME` on any command to target another firewall once, without switching.

### Exit codes

`0` success · `1` error (bad input, API error, firewall unreachable, aborted) · `2` wrong command or option · `130` Ctrl+C.

## Tests

```bash
.venv/bin/pip install pytest && .venv/bin/pytest -q
```
