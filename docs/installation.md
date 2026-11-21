# Installation and operation

SwitchSteward is a Python web application (FastAPI/Uvicorn) with a static
JavaScript frontend. It needs no frontend build step, no Node.js at runtime and no
separate database server (SQLite).

## Requirements

- Python 3.10 or newer (Windows, Linux or macOS).
- Access to a Python package index for the dependencies in
  `backend/requirements.txt` (first start and updates with changed dependencies).
- Network access from the server to the managed devices (SSH, HTTPS for MikroTik,
  RESTCONF/NETCONF for wireless controllers) and, if used, to the domain
  controllers and to Microsoft Entra ID.

Use a release archive (`switchsteward.zip` or `switchsteward.tar.gz`) or a
checkout of the repository. All commands below run in the `backend/` folder.

## Start scripts

### Windows (PowerShell)

```powershell
cd switchsteward\backend
.\start.ps1
```

If PowerShell refuses to run the script because of the execution policy, run once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### Linux / macOS

```bash
cd switchsteward/backend
bash start.sh
```

Both scripts do the same on every start:

1. Create the virtual environment `backend/venv` on the first run (Python 3.10+
   is required).
2. Complete or roll back an interrupted web update and select the Python
   environment of the installed version.
3. Install or update the dependencies from `requirements.txt`.
4. Create `backend/config.json` from `config.example.json` with fresh random keys
   if it does not exist (`python -m app.bootstrap_config`).
5. Start the application with `python -m app.run`.

On a new installation this opens the [setup wizard](#setup-wizard).

## Manual start

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m app.run
```

`python -m app.run` also creates a missing configuration. Use `python -m pip`
rather than `pip` on Windows.

`uvicorn app.main:app` works too, but then the setup wizard needs a manual process
restart after saving, and web updates cannot restart the server. Use the start
scripts or `python -m app.run` for production.

To use a configuration file other than `backend/config.json`, set
`SWITCHSTEWARD_CONFIG_FILE` before starting (see [configuration.md](configuration.md)).

For a permanent installation, run the start script or `python -m app.run` as a
service (systemd unit, Windows service wrapper or scheduled task) under a
dedicated account that may write to the installation folder (needed for web
updates), the database folder and the log folder.

## Setup wizard

On a new installation the server starts in setup mode and prints
`Erstinstallation im Browser öffnen: http://127.0.0.1:8000`. The wizard:

- listens on `127.0.0.1` only and accepts only local requests. On a server without
  desktop, use an SSH tunnel: `ssh -L 8000:127.0.0.1:8000 user@server`, then open
  `http://127.0.0.1:8000` on your workstation;
- is available in German and English (language switch in the header);
- keeps the device API unavailable until setup is complete and is locked afterwards.

Steps:

1. **Local administrator account**: user name and password (12–1024 characters).
   This is the first administrator; you sign in with it after setup. Active
   Directory and Microsoft Entra ID are configured later in
   **Administration** (see [authentication.md](authentication.md)).
2. **Web access**: bind address and port, and the connection mode:
   - *HTTP · local start*: unencrypted, for local commissioning only.
   - *HTTPS · generate certificate*: creates a self-signed certificate
     (browsers show a warning).
   - *HTTPS · existing certificate*: certificate file and private key file on the
     server.
   - *HTTPS via reverse proxy*: the application speaks HTTP, a proxy in front
     terminates TLS; enter the public HTTPS address.
3. **Complete installation**: database file (must not exist yet), optional global
   device credentials (user name, password, enable secret for switches), optional
   SSH and NETCONF known-hosts files. A summary is shown before saving.

File paths refer to the server; relative paths are resolved against the
configuration folder. All HTTPS modes set `session.cookie_secure: true`.

After **Save**, `app.run` starts the normal server with the chosen settings; the
wizard shows the target address. The wizard records a `setup-complete` audit entry
with the new administrator as actor.

## After setup

1. Sign in with the local administrator.
2. Open **Administration → Global credentials** and enter the user name, password and
   optional enable secret used for switches and wireless controllers (the enable
   secret is used for switches only). Individual devices can use their own
   credentials instead (**Credentials** at the device). Per-device credentials are
   a complete set and are never mixed with or replaced by the global ones;
   changing a device's address, port or type removes its own stored credentials.
   Passwords are stored encrypted and never returned to the browser.
3. Add the SSH host keys of your switches to the known-hosts file configured in
   `ssh.known_hosts_file` (and NETCONF controllers to
   `wireless.netconf_known_hosts_file`). Host key checking is on by default; an
   empty file is created at start and connections fail until the keys are added.
4. Create switch groups and switches: choose vendor, platform and model; see
   [switch-drivers.md](switch-drivers.md) for device prerequisites.
5. Optionally configure Active Directory or Entra ID and create group mappings
   ([authentication.md](authentication.md)).

Use a dedicated device service account with the least privileges your platform
allows instead of a full administrator account.

## HTTPS and reverse proxy

### Direct HTTPS

The wizard's HTTPS modes write the following settings; you can also set them by
hand:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8443,
    "log_level": "info",
    "tls": {
      "enabled": true,
      "generate_self_signed": false,
      "cert_file": "cert.pem",
      "key_file": "key.pem"
    }
  },
  "session": {
    "cookie_secure": true
  }
}
```

With `generate_self_signed: true` the server creates the pair at start if **both**
files are missing; a single missing file is never regenerated. To create a
self-signed pair manually:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=switchsteward"
```

Self-signed certificates trigger a browser warning and are only suitable for tests.
For production use a certificate from your PKI or a reverse proxy. Microsoft Entra
ID sign-in requires an `https://` address that users reach without warnings.

When TLS is active the server sends `Strict-Transport-Security`.

### Reverse proxy

Recommended for production: nginx, Traefik, IIS/ARR or similar terminates TLS and
forwards to the application on the same host.

- Let the application listen on `127.0.0.1` (`server.host`) with
  `server.tls.enabled: false`, and set `session.cookie_secure: true`.
- Forward the original `Host` header and `X-Forwarded-For` / `X-Forwarded-Proto`.
  Uvicorn trusts these headers only from `127.0.0.1` (its default), so a proxy on
  the same host makes the real client IP appear in logs, audit records and the
  login throttle. With a proxy on another host, all requests appear to come from
  the proxy address.
- Allow request bodies of at least 50 MiB on the update endpoint
  (`/api/system/updates`) if you use web updates.
- Allow generous read timeouts (for example 120 s): device operations such as a
  global client search across many switches can take a while.
- For Entra ID, set **Administration → Authentication → General → Public
  application address** to the proxy's public URL.

Example for nginx:

```nginx
server {
    listen 443 ssl;
    server_name switchsteward.example.org;
    ssl_certificate     /etc/ssl/certs/switchsteward.pem;
    ssl_certificate_key /etc/ssl/private/switchsteward.key;
    client_max_body_size 50m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Never expose the application directly to the internet; run it in an internal
management network or behind a VPN.

## Web update

Administrators can install new releases from the GUI.

1. Download `switchsteward.zip` or `switchsteward.tar.gz` from the project's
   release page. Only these release assets (built by `scripts/build_release.py`)
   are valid update packages; automatically generated source archives are not.
2. Open **Administration → Software update**, choose the archive and upload it
   (maximum 50 MiB). The server checks paths, file types, completeness and size
   limits and shows the installed and the uploaded version with the SHA-256
   checksum.
3. Click **Install version**. The server finishes running requests, installs the
   new version and restarts. Changed dependencies are installed into a new Python
   environment, which can take several minutes.
4. Reload the page when the GUI reports completion. The GUI polls for about three
   minutes; if there is no result yet, reload later and open **Administration → Software update**
   again — waiting alone means neither success nor failure.

Requirements and behaviour:

- The server must have been started with `start.sh`, `start.ps1` or
  `python -m app.run`, and the service account needs write access to the
  installation folder. `application.frontend_dir` must point to the shipped
  `frontend/` folder.
- At least 250 MiB of free space, plus space for backups, a test copy of the
  database and possibly a new Python environment.
- Configuration, database, certificates, keys, known-hosts files, logs and existing
  virtual environments are never overwritten. A configured runtime file inside a
  path managed by the update blocks the update.
- If installation or the start check fails, the previous version is restored. An
  interrupted file exchange is detected and rolled back at the next start.
- The result is audited as `install-update-result` (actor `system`) at the next
  start.
- The work folder `.updates/` in the installation root contains the candidate,
  backups, status data and possibly the active Python environment. Do not delete
  it as a whole.
- Release archives contain executable code. The checksum does not prove a
  publisher signature; install only releases from a trusted source.

Keep an external [backup](#backups) before every update; the automatic start
check does not replace testing future database migrations.

### Building a release archive

From a checkout of the repository:

```bash
python scripts/build_release.py
```

This creates `dist/switchsteward.zip` and `dist/switchsteward.tar.gz` with the
common root folder `switchsteward/`. The file list comes from
`backend/app/release_manifest.py`: documentation (`README.md`, `CHANGELOG.md`,
`SECURITY.md`, `LICENSE`, `VERSION`, `docs/*.md`), backend code, start scripts,
configuration template and web assets. Local configuration, databases, keys,
virtual environments, logs and caches are never included. Update `VERSION` and
`CHANGELOG.md` before building.

## Backups

Back up regularly and before every update:

| What | Why |
| --- | --- |
| `backend/config.json` (or your `SWITCHSTEWARD_CONFIG_FILE`) | Contains `secrets.encryption_key`. Without it, the stored device passwords, enable secrets and the Entra client secret cannot be decrypted. |
| Database (`application.database_path`, default `backend/data/switchsteward.db`) | Inventory, groups, encrypted credentials, users, sign-in settings, group mappings, sessions, audit log, WLAN status data. |
| TLS certificate and key, CA files, known-hosts files | Operator-provided trust anchors; not recreated with the same content. |
| Log folder (`logging.directory`) | Optional; `audit.log` duplicates the database audit table. |

Copy the SQLite database consistently: stop the server first, or use
`sqlite3 switchsteward.db ".backup switchsteward-backup.db"` while it runs. Store backups
of `config.json` securely; it is a secret.

## Automatically created files

| File | Behaviour |
| --- | --- |
| `backend/config.json` | Created from the template with random keys; the setup wizard stores the operating parameters. |
| `backend/venv/` | Created by the start scripts. |
| Database file and its folder | Created with the full schema when setup completes. |
| Configured known-hosts files | Created empty if missing; trusted device host keys must be added afterwards. |
| TLS certificate and key | Created for *HTTPS · generate certificate* if both are missing; existing files are never replaced. |
| Log folder with `system.log`, `audit.log` and rotated files | Created at start (default `backend/logs/`). |
| `.updates/` in the installation root | Work folder of the web update. |

CA certificates and existing private keys must be provided by the operator. An
incomplete TLS pair, or a lost configuration next to an existing database, is
never replaced by new keys that would not match.
