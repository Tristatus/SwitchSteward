# Configuration reference

SwitchSteward reads all environment-specific settings from one JSON file,
`backend/config.json`. The start scripts and `python -m app.run` create it from
[`backend/config.example.json`](../backend/config.example.json) on the first
start and fill in fresh random keys; the [setup wizard](installation.md#setup-wizard)
then stores the operating parameters.

What does **not** live in `config.json`:

- **Sign-in providers** (Active Directory, Microsoft Entra ID), the public base
  URL, users and group-to-role mappings are stored in the database and edited in
  the **Administration** workspace. See [authentication.md](authentication.md).
- **Device credentials** (global and per-device) are entered in the web UI and
  stored encrypted in the database.

## General rules

- **Alternative file:** the environment variable `SWITCHSTEWARD_CONFIG_FILE` selects a
  different JSON file before the process starts. It is the only application-specific
  environment variable; the Entra ID HTTP client additionally honours the standard
  `HTTPS_PROXY` variable. A relative value is resolved against `backend/`.
- **Relative paths** inside the file are resolved against the folder that contains
  the configuration file (for the default file: `backend/`).
- **Optional keys** have a default and may be omitted; required keys must be present.
  An invalid value stops the start with a message naming the key, for example
  `session.max_age_seconds muss zwischen 300 und 86400 liegen.`
- **Changes** take effect after a restart of the backend.
- **Protect the file:** it contains the key that encrypts the stored device
  credentials and the Entra client secret. Keep it out of version control, restrict
  its file permissions and include it in your [backups](installation.md#backups).
  If it is lost, stored credentials cannot be decrypted and must be entered again.

## Complete example

This is the template shipped as `backend/config.example.json`. The bootstrap step
fills `secrets.encryption_key` and `secrets.session_key`.

```json
{
  "installation": {
    "completed": false
  },
  "secrets": {
    "encryption_key": "",
    "session_key": null
  },
  "application": {
    "frontend_dir": "../frontend",
    "database_path": "data/switchsteward.db",
    "sqlite_timeout_seconds": 10,
    "api_max_body_bytes": 65536,
    "audit_log_limit": 200
  },
  "server": {
    "host": "127.0.0.1",
    "port": 8000,
    "log_level": "info",
    "tls": {
      "enabled": false,
      "generate_self_signed": false,
      "cert_file": null,
      "key_file": null
    }
  },
  "session": {
    "cookie_name": "switchsteward_session",
    "cookie_secure": false,
    "max_age_seconds": 3600,
    "login_max_failures": 5,
    "login_window_seconds": 900,
    "login_max_tracked_keys": 10000
  },
  "ssh": {
    "strict_host_keys": true,
    "known_hosts_file": null,
    "timeout_seconds": 10,
    "allow_legacy_algorithms": false
  },
  "wireless": {
    "allow_unverified_restconf_tls": false,
    "restconf_ca_cert_file": null,
    "netconf_strict_host_keys": true,
    "netconf_known_hosts_file": null,
    "netconf_allow_legacy_algorithms": false,
    "connect_timeout_seconds": 5,
    "read_timeout_seconds": 30,
    "cache_ttl_seconds": 30,
    "max_response_bytes": 10485760
  },
  "switch_api": {
    "ca_cert_file": null,
    "allow_unverified_tls": false,
    "timeout_seconds": 10
  },
  "logging": {
    "directory": "logs",
    "level": "info",
    "max_bytes": 10485760,
    "backup_count": 10
  }
}
```

## `installation`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `completed` | boolean | `true` if the section is missing | `false` starts the setup wizard instead of the application. The wizard sets it to `true`. Configurations without this section count as already set up. |

## `secrets`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `encryption_key` | string | required | Fernet key that encrypts device passwords, enable secrets and the Entra client secret in the database. Generated automatically. **Never change it on an existing installation**, or the stored secrets become unreadable. |
| `session_key` | string or `null` | generated | Key from which the application derives signing keys (revision tokens of edit dialogs, the Entra sign-in transaction cookie, WLAN preview tokens). Must be at least 32 bytes. If `null`, `encryption_key` is used. Changing it only invalidates open dialogs and running Entra sign-ins; sessions are stored server-side and are not affected. |

## `application`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `frontend_dir` | path | required | Directory with the web assets. Web updates require that it points to the `frontend/` folder of the installation. |
| `database_path` | path | required | SQLite database file. The setup wizard creates it; the folder is created if needed. |
| `sqlite_timeout_seconds` | integer 1–300 | required | How long a database access waits for a lock. |
| `api_max_body_bytes` | integer 1024–10485760 | required | Maximum size of an API request body. Release uploads for web updates have their own limit of 50 MiB. |
| `audit_log_limit` | integer 1–1000 | required | Number of most recent entries shown in the audit view of the GUI. It does not delete anything: the database keeps all audit entries. |

## `server`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | required | Bind address, for example `127.0.0.1` (local or behind a reverse proxy on the same host) or `0.0.0.0` (all interfaces). The setup wizard itself always binds to `127.0.0.1`. |
| `port` | integer 1–65535 | required | TCP port. |
| `log_level` | `critical`, `error`, `warning`, `info`, `debug`, `trace` | required | Level of the **console** output only. The log files are controlled by [`logging`](#logging). |

### `server.tls`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | required | Serve HTTPS directly. Requires `cert_file` and `key_file`. |
| `generate_self_signed` | boolean | `false` | With `enabled: true`, create a self-signed certificate and key at the configured paths if **both** files are missing. Existing files are never replaced. |
| `cert_file` | path or `null` | required | PEM certificate (chain). |
| `key_file` | path or `null` | required | PEM private key without passphrase. |

When TLS is enabled the application also sends `Strict-Transport-Security`.
See [installation.md](installation.md#https-and-reverse-proxy) for HTTPS and
reverse-proxy setups.

## `session`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `cookie_name` | string | required | Name of the session cookie. |
| `cookie_secure` | boolean | required | Send the session cookie only over HTTPS. Set to `true` whenever users reach the application over HTTPS (direct TLS or reverse proxy); the setup wizard does this automatically. |
| `max_age_seconds` | integer 300–86400 | required | Absolute session lifetime. Sessions are not extended by activity; after this time the user signs in again. |
| `login_max_failures` | integer 1–100 | required | Failed sign-in attempts allowed per client IP, sign-in method and user name within the window. Further attempts get HTTP 429. |
| `login_window_seconds` | integer 60–86400 | required | Length of the throttling window. |
| `login_max_tracked_keys` | integer 100–1000000 | required | Upper bound of tracked throttling keys (memory protection). The throttle state is kept in memory per server process. |

Sessions themselves are stored in the database; see
[authentication.md](authentication.md#sessions-and-revocation).

## `ssh`

Settings for SSH connections to switches (Cisco, Aruba AOS-CX, Aruba AOS-S, Netgear).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `strict_host_keys` | boolean | required | Verify the switch's SSH host key. Keep `true` in production. |
| `known_hosts_file` | path or `null` | required | OpenSSH `known_hosts` file with the trusted switch host keys. Created empty at start if it does not exist; add the keys of your switches afterwards. With `null`, the default known-hosts handling of the SSH library applies. |
| `timeout_seconds` | integer 1–300 | required | Connection and read timeout per switch session. |
| `allow_legacy_algorithms` | boolean | required | Re-enable outdated key exchange algorithms and `ssh-rsa` signatures. Applies process-wide to all switch connections; use only for an isolated legacy device. A warning is logged at start. |

## `wireless`

Settings for Cisco Catalyst 9800 wireless controllers. The whole section is
optional; missing keys use the defaults below. Details on transports and
permissions: [wlan-catalyst-9800.md](wlan-catalyst-9800.md).

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_unverified_restconf_tls` | boolean | `false` | Disable certificate and host name verification for RESTCONF (HTTPS). The CA file is ignored then. Allows man-in-the-middle attacks on controller credentials; use only in a trusted management network. |
| `restconf_ca_cert_file` | path or `null` | `null` | PEM file with the CA that signed the controller certificate. Without it the system CA store is used. |
| `netconf_strict_host_keys` | boolean | `true` | Verify the controller's SSH host key for NETCONF. |
| `netconf_known_hosts_file` | path or `null` | `null` | `known_hosts` file for NETCONF. For a non-standard port use the OpenSSH form `[wlc.example.org]:830 ssh-ed25519 …`. Created empty at start if it does not exist and host key checking is on. |
| `netconf_allow_legacy_algorithms` | boolean | `false` | Allow `ssh-rsa` signatures for NETCONF only (independent of `ssh.allow_legacy_algorithms`). |
| `connect_timeout_seconds` | integer 1–120 | `5` | Connection timeout. |
| `read_timeout_seconds` | integer 1–300 | `30` | Read timeout. |
| `cache_ttl_seconds` | integer 1–300 | `30` | In-memory cache lifetime of access point and client lists. |
| `max_response_bytes` | integer 65536–104857600 | `10485760` | Maximum size of one controller response. |

## `switch_api`

Settings for switches managed over HTTPS instead of SSH. Currently this is the
MikroTik RouterOS v7 driver (REST API). The section is optional.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `ca_cert_file` | path or `null` | `null` | PEM file with the CA that signed the switch certificates. Without it the system CA store is used. Host names are always verified, so the certificate must match the address configured for the switch. |
| `allow_unverified_tls` | boolean | `false` | Disable certificate and host name verification. Allows man-in-the-middle attacks on the switch credentials; a warning is logged at start. |
| `timeout_seconds` | integer 1–120 | `10` | Timeout per HTTPS request. |

The HTTPS client never follows redirects and ignores proxy environment variables.

## `logging`

The section is optional; missing keys use the defaults below.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `directory` | path | `"logs"` | Folder for `system.log` and `audit.log` (relative to the configuration folder, so `backend/logs` by default). Created with mode `0700` if missing. If it cannot be created or written, the server does not start. |
| `level` | `info`, `warning`, `error` | `"info"` | Minimum level written to `system.log`. Does not affect `audit.log`. |
| `max_bytes` | integer 1048576–1073741824 | `10485760` (10 MiB) | Size at which a log file is rotated. |
| `backup_count` | integer 1–100 | `10` | Number of rotated files kept per log (`system.log.1` … `system.log.N`). |

Web updates protect the configured log folder like other runtime paths: it must
not lie inside a path managed by the update.

## Logs

The application writes two files into `logging.directory`, in addition to the
console output:

| File | Content | Level |
| --- | --- | --- |
| `system.log` | What the server does: start/stop, HTTP requests, device connections and the commands sent to devices, sign-ins, warnings and errors. | `logging.level` |
| `audit.log` | One JSON object per line for every audited user action. The same records are stored in the database and shown in **Administration → Audit-Log**. | always all records |

Both files are UTF-8 and rotate independently with the same `max_bytes` and
`backup_count`. Python's `RotatingFileHandler` is used: when a file reaches
`max_bytes` it is renamed to `.1`, older files shift up, and the oldest beyond
`backup_count` is deleted. Rotation is per process; do not let several server
processes write to the same folder.

Administrators can read both logs in the GUI under **Administration**:
**System-Log** shows the newest 500 entries from the last 2 MiB of the current
`system.log` (newest first, continuation lines such as stack traces belong to their
entry), **Audit-Log** shows the newest database records. **Download** delivers a
ZIP archive with the current file and all rotated files (`system.log`,
`system.log.1` … or `audit.log`, `audit.log.1` …); each download is audited as
`download-system-log` or `download-audit-log`. Column widths of both tables can be
dragged and are remembered per browser; a double-click on a column border resets
them.

### `system.log` format

```
2026-10-07T14:03:11+0200 INFO switchsteward.http [3f9c0a1b2d4e] POST /api/switches 200 48ms user=alice ip=192.0.2.10
```

Fields: timestamp, level, logger name (`switchsteward.<module>`, plus `uvicorn.error`),
request ID in brackets (`-` outside a request), message. The request ID is also
returned to the browser in the `X-Request-ID` response header and stored with each
audit record, so a GUI error, its audit entry and its log lines can be correlated.
An unexpected server error answers HTTP 500 with the text
`Interner Fehler (Request-ID …).` (translated in the GUI) and logs the stack trace
with the same ID.

Contents per level:

- **INFO**: server start (version, configuration file, database path, TLS mode,
  active sign-in methods) and stop; one line per HTTP request
  (`method path status duration user ip`, **without query string**; static files
  and favicons are not logged); sign-ins, refused sign-ins and sign-outs; every
  device connection (switch, driver, host:port, and the session duration when it
  closes) and every command or REST/RESTCONF/NETCONF call sent to a device;
  successful LDAP binds (domain controller and user); loaded Entra discovery
  documents and signing keys (JWKS); saved sign-in settings (names of the changed
  keys only, never values); update steps.
- **WARNING**: insecure exceptions active at start (legacy SSH algorithms, disabled
  host key checking, unencrypted or unverified LDAP, unverified RESTCONF or switch
  API TLS); empty known-hosts files created at start; degraded optional data
  sources; throttled sign-ins; failed LDAP binds; mutating requests rejected with
  401 (no session); failed Entra sign-ins and failed refreshes of the Entra
  discovery document or signing keys.
- **ERROR**: device and connection errors; unavailable directory services; update
  failures; stored settings that cannot be read; unhandled exceptions with stack
  trace.

With `level: "warning"` the file only contains WARNING and ERROR lines; with
`"error"` only ERROR lines. Third-party libraries (`paramiko`, `netmiko`, `httpx`,
`httpcore`, `ldap3`) only log warnings and errors.

**Secrets are never logged.** In addition, a redaction filter on every handler
replaces values after `password`, `passwd`, `secret`, `token`, `authorization`,
`cookie` or `code` followed by `=` or `:` with `***`.

### `audit.log` format

One JSON object per line:

```json
{"ts": "2026-10-07T12:03:11+00:00", "username": "alice", "auth_provider": "local", "client_ip": "192.0.2.10", "target": "core-sw-01", "interface": "GigabitEthernet1/0/12", "action": "configure-interface", "detail": "mode=access, access_vlan=20", "status": "ok", "request_id": "3f9c0a1b2d4e"}
```

| Field | Meaning |
| --- | --- |
| `ts` | UTC timestamp (ISO 8601, seconds). |
| `username` | Acting user. Special actors: `cli` (emergency CLI), `system` (result of a web update written at the next start). For failed sign-ins: the entered user name. |
| `auth_provider` | Sign-in method of the actor: `local`, `ad` or `entra`. |
| `client_ip` | Client address as seen by the server (the proxy address behind a reverse proxy unless the proxy runs on the same host, see [installation.md](installation.md#https-and-reverse-proxy)). |
| `target` | Affected object: switch, controller, group, user name or sign-in provider. |
| `interface` | Switch port, if applicable. |
| `action` | Action name, see the [audit action catalog](architecture.md#audit-action-catalog). |
| `detail` | Short description (changed fields, reason codes such as `reason=invalid_credentials`, `http_status=409`). Never contains passwords or secrets. |
| `status` | `ok` or `error`. |
| `request_id` | Request ID, matching `system.log` and the `X-Request-ID` header. |

Every mutating API request is audited, including failed ones: if a request fails
before the route wrote its own record, a fallback records the route's action with
`status: "error"` and `detail: "http_status=<code>"`. Requests rejected with 403
are recorded as `access-denied`. Read-only requests are not audited; they appear
in `system.log` with the user name. Sign-in auditing is described in
[authentication.md](authentication.md#sign-in-audit).

A write error on `audit.log` (for example a full disk) does not abort the user's
request; the database record is authoritative.
