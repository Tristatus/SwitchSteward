# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub: open the
repository's *Security* tab and choose **Report a vulnerability** (GitHub
Security Advisory).

Do not open a public issue. Never include passwords, private keys, database
files, `config.json` or unredacted device output in a report. Describe the
affected version, the configuration options involved and the steps to
reproduce. You will receive an acknowledgement and, once a fix is available,
a coordinated disclosure in the [changelog](CHANGELOG.md).

## Security model

SwitchSteward is an administration tool for a trusted management network. It
holds credentials for network devices and can change their configuration, so
treat the host and its files as sensitive.

### Roles

| Role | Can |
| --- | --- |
| `admin` (Administrator) | Everything: inventory, credentials, connection tests, all switch and WLAN configuration, saving configurations, backups and restore, firmware and reloads, software updates and the **Administration** workspace (sign-in settings, users, group mappings, global credentials, operations settings, port profiles, audit log, system log). |
| `operator` (Operator) | Everything a viewer can read. On access ports that are not uplinks: description, access VLAN, voice VLAN, administrative state, PoE mode and power profile, speed/duplex; restart a port, power-cycle PoE, recover an err-disabled port, reset port counters, run a cable test. Changes that put an uplink or the management path at risk are refused. |
| `viewer` (Read only) | Read switch, VLAN, client, neighbor, layer-2, port-security, device, diagnostic and WLAN data and the list of backups. No changes, no connection tests, no backup contents, no device log, no Administration workspace (audit log, system log and credential metadata are administrator-only). |

Roles are enforced by the API; hiding UI elements is not an authorization
control. Device data such as MAC/IP addresses, host names and user names is
personal operational data; grant the viewer role accordingly.

### Authentication

- **Local accounts** are always available and cannot be disabled globally
  (individual accounts can). Passwords are hashed with `hashlib.scrypt`
  (N=2^15, r=8, p=1, 16-byte salt); unknown users are verified against a dummy
  hash to avoid timing differences. Passwords must be 12–1024 characters
  without control characters.
- **Active Directory** (optional) authenticates by LDAP bind. Use `ldaps://`
  with certificate validation; plain LDAP and unverified LDAPS are explicit
  "insecure exceptions" in the Administration workspace. A login name must
  resolve to exactly one user below the configured base DN and is rebound by
  that DN before groups are evaluated.
- **Microsoft Entra ID (OAuth 2.0 / OpenID Connect)** (optional) uses the
  authorization code flow with PKCE (S256), `state` and `nonce`. The id_token is
  validated (RS256 signature via the tenant's JWKS, audience, issuer, tenant,
  token version, expiry). Only interactive browser sign-in is supported; there
  is no bearer-token API access.
- Roles come from an explicit per-user role or from group → role mappings
  (admin before operator before viewer), otherwise from the provider's default
  role (none or viewer).
- Failed logins are throttled per client IP, provider and user name
  (`session.login_max_failures` within `session.login_window_seconds`).
- A lockout guard rejects changes (HTTP 409) that would leave no usable
  administrator path. The emergency CLI `python -m app.manage create-admin`
  restores access for anyone with shell access to the host.

Details: [docs/authentication.md](docs/authentication.md).

### Sessions and CSRF

- Sessions are stored server-side in SQLite. The cookie contains a random
  32-byte token; the database stores only its SHA-256 hash. Cookie attributes:
  `HttpOnly`, `SameSite=Strict`, `Secure` when `session.cookie_secure` is
  `true`, lifetime `session.max_age_seconds` (no sliding renewal).
- Disabling a user, changing a role, changing a password or disabling a
  provider revokes the affected sessions immediately. Group membership changes
  in AD/Entra take effect at the next sign-in.
- Every mutating API request except `POST /api/login` must carry the session's
  CSRF token in the `X-CSRF-Token` header (compared in constant time).
- Logging out ends the SwitchSteward session only; it does not sign the user
  out of Microsoft.

### HTTP hardening

- Strict security headers on every response, including rejected ones:
  `Content-Security-Policy` with `script-src 'self'` (no inline scripts),
  `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: same-origin`, `Cache-Control: no-store` for the API, and
  HSTS when served over HTTPS. `style-src` still allows `'unsafe-inline'` for
  existing `style=` attributes.
- Request bodies are limited by actually received bytes
  (`application.api_max_body_bytes`), not only by `Content-Length`. Update
  uploads have their own limit and are accepted only from administrators.
- The setup wizard listens on loopback only, checks the `Host` header and is
  locked after setup completes.
- Unhandled errors return a generic message with a request ID; details go to
  `system.log` only.

### Transport security to devices

- **SSH (switches):** keep `ssh.strict_host_keys` enabled and provide a
  trusted `ssh.known_hosts_file`. Keep `ssh.allow_legacy_algorithms` disabled
  unless an isolated legacy device requires it (see
  [Paramiko](#known-dependency-exception-paramiko)).
- **HTTPS (MikroTik REST):** certificates are validated; use
  `switch_api.ca_cert_file` for a private CA. `switch_api.allow_unverified_tls`
  disables validation and exposes the device credentials (HTTP Basic auth) to
  a man-in-the-middle; use it only in an isolated lab.
- **RESTCONF (Catalyst 9800):** use `wireless.restconf_ca_cert_file` for a
  private CA. `wireless.allow_unverified_restconf_tls` disables certificate and
  host-name validation with the same risk.
- **NETCONF (Catalyst 9800):** keep `wireless.netconf_strict_host_keys`
  enabled and provide `wireless.netconf_known_hosts_file` (non-default ports
  use the OpenSSH `[host]:port` notation). Keep
  `wireless.netconf_allow_legacy_algorithms` disabled; it is deliberately
  independent from the switch SSH setting.
- **LDAP:** see [Authentication](#authentication).
- Serve the web UI over HTTPS (directly or behind a reverse proxy) and set
  `session.cookie_secure` to `true`.

### Secrets

- Device credentials (global, per switch, per WLAN controller) and the Entra
  client secret are encrypted with the application key
  (`secrets.encryption_key`) and are never returned by the API. WLAN keys are
  accepted for writing only and never appear in responses, previews or the
  audit log.
- Logs never contain passwords, secrets, tokens, authorization codes or
  cookies; a redaction filter additionally masks `password=…`-style values,
  and request lines are logged without query strings.
- Keep `config.json`, the SQLite database, TLS private keys, known-hosts files
  and the log directory out of version control, readable only by the service
  account, and include them in backups.

### Audit

Every mutating API request is audited in the database and in `audit.log`
(JSON lines) with user, sign-in provider, client IP and request ID. Requests
rejected with 403 are recorded as `access-denied`; other failures before the
regular audit call are recorded by a fallback middleware. See
[docs/architecture.md](docs/architecture.md#audit-action-catalog).

## Known dependency exception: Paramiko

Netmiko 4.7 requires Paramiko below 5. Paramiko 4.0.0 is flagged by
CVE-2026-44405 / PYSEC-2026-2858 because it accepts SHA-1 `ssh-rsa`
signatures; no patched 4.x release exists. SwitchSteward explicitly disables
`ssh-rsa` for host keys and public-key authentication, which blocks the
vulnerable algorithm.

Setting `ssh.allow_legacy_algorithms` to `true` removes this mitigation for
switch connections and is therefore restricted to isolated legacy devices.
NETCONF uses the separate `wireless.netconf_allow_legacy_algorithms` setting
and stays protected unless that exception is enabled as well. Paramiko will be
upgraded as soon as Netmiko supports a fixed compatible release.

A dependency audit of `backend/requirements.txt` (for example with `pip-audit`)
reports this finding for Paramiko 4.0.0.

References: [Paramiko advisory](https://github.com/advisories/GHSA-r374-rxx8-8654),
[Netmiko 4.7 release](https://github.com/ktbyers/netmiko/releases/tag/v4.7.0).

## Known limitations

- Login throttling and caches are per process.
- The switch drivers for Aruba AOS-CX, Aruba AOS-S, Netgear and MikroTik are
  experimental and have not been validated against hardware; see
  [docs/switch-drivers.md](docs/switch-drivers.md).
- A failed CLI command stops the remaining commands of a port change, but
  commands that already succeeded are not rolled back. Use the timed rollback
  on Cisco IOS-XE and Aruba AOS-CX for risky changes.
- The audit table and audit.log are not pruned by age; the GUI lists the newest
  entries only.
- Change previews are kept in server memory: they expire on restart and must
  reach the server process that created them.
