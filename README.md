# SwitchSteward

SwitchSteward is a self-hosted web application for the day-to-day operation of access
switches from Cisco, Aruba, Netgear and MikroTik and of Cisco Catalyst 9800 wireless
controllers. One vendor-neutral interface covers ports, VLANs, layer-2 and security
features, device settings, configuration backups, firmware and diagnostics. Every change
is shown as the exact command list before it is sent, checked for uplink risk, optionally
guarded by a timed rollback and recorded in an audit trail.

It is built for small and medium networks (tens to a few hundred devices) that need
controlled, auditable changes without a full network management system. SwitchSteward
runs on Python 3.10+ with FastAPI and SQLite. The interface is available in German and English, in a light
and a dark theme.

## Features

### Switches

| Area | Functions |
| --- | --- |
| Inventory | Switch groups; vendor → platform → model selection with automatic model detection; global or per-device credentials; search by name, IP, location, note or group. |
| Ports | Status, VLAN and PoE per port. Edit description, access/trunk mode, access, native, allowed and voice VLAN, edge port, speed/duplex, administrative state, PoE mode and power profile. Copy port settings and paste them onto other ports or switches; reusable port profiles; port restart, PoE power cycle, recovery of err-disabled ports. |
| VLANs | VLANs with name, status and the ports using them; create, rename, delete (deletion is refused while a port, a layer-3 interface or the switch itself depends on the VLAN); VLAN rollout to every switch of a group including the uplink trunks. |
| Layer 2 | Link aggregation (static, LACP); spanning tree (mode, bridge priority, MST region, port cost and priority); Cisco VTP (domain, version, mode, pruning, password, VTPv3 primary server takeover) and a VTP domain overview across all switches. |
| Port security | Port security with sticky MAC addresses, 802.1X and MAB with guest/auth-fail VLANs, BPDU/root/loop guard, storm control, DHCP snooping, dynamic ARP inspection, IP source guard. |
| Device settings | Hostname, banner, location and contact; NTP, time zone, DNS, syslog; SNMPv3 users; RADIUS/TACACS+ servers and login order; local users; SSH, Telnet and web access; VLAN interfaces, default gateway, DHCP relay, static routes; IPv4 ACLs; QoS trust and voice preset. |
| Configuration | Explicit **Save config** with save-state tracking and a running/startup comparison; automatic backups before and after saving and before a restore, deduplicated, with retention and optional password encryption; view, diff, download and restore. |
| Maintenance | Firmware image store, staging and activation, immediate or scheduled reload. |
| Diagnostics | Port counters, transceivers, environment, device log, cable test. |
| Visibility | Device summary with PoE budget; CDP/LLDP neighbours; connected clients (MAC table and ARP); global search for MAC addresses and device names across all switches. |

### Safe changes

- **Preview, then apply:** every write is built as a plan, shown with the exact (redacted) commands and sent unchanged only after confirmation: once, by the same session, within five minutes. The switch is read again before sending; a changed state invalidates the preview.
- **Uplink protection:** ports that carry the management connection or lead to other switches and routers are detected. Administrators must confirm the risk; operators are refused.
- **Timed rollback:** on Cisco IOS-XE and Aruba AOS-CX a change can be armed with an automatic revert that must be confirmed in time.
- **Capability model:** each driver and hardware model declares what it supports. Unsupported functions stay visible but are greyed out with the reason.
- **Validated input:** every value sent to a device is validated on the server, so input such as a port description cannot inject commands.

### Wireless (Cisco Catalyst 9800)

- Controller inventory with access points, radios and clients; server-side search, filters and paging over RESTCONF or NETCONF.
- Configuration over NETCONF: WLANs, policy, site, RF, AP join and FlexConnect profiles, tags, AP and radio settings, AP reboot and saving the controller configuration, each with preview, read-back and audit.

Details: [docs/wlan-catalyst-9800.md](docs/wlan-catalyst-9800.md).

### Access control and operation

- **Sign-in:** local accounts, Active Directory (LDAP bind) and Microsoft Entra ID (OpenID Connect, authorization code flow with PKCE); the directory providers can be enabled independently.
- **Roles:** *Administrator*, *Operator* (day-to-day changes on access ports that are no uplinks) and *Read only*, assigned per user or through directory group mappings. A lockout guard keeps at least one administrator path; an emergency CLI restores access.
- **Sessions:** server-side with immediate revocation, CSRF protection, login throttling and a strict Content Security Policy.
- **Secrets:** device credentials are stored encrypted, globally or per device, and are never returned by the API.
- **Accountability:** every change is audited (database and `audit.log`); `system.log` records requests, device connections and the commands sent. Both logs can be viewed and downloaded in the Administration workspace.
- **Operation:** setup wizard, built-in HTTPS or reverse proxy, web-based software update with automatic rollback, scheduled jobs, one-time download links and a built-in SFTP server through which switches fetch restores and firmware.

## Supported devices

| Vendor / platform | Transport | Status |
| --- | --- | --- |
| Cisco IOS and IOS-XE (Catalyst access switches) | SSH | Supported; reference driver. Timed rollback on IOS-XE only. |
| Aruba AOS-CX | SSH | Experimental, not validated against hardware. No PoE power profiles, no VTP. |
| Aruba AOS-S (ProVision) | SSH | Experimental, not validated against hardware. No PoE power profiles, timed rollback, QoS or VTP. |
| Netgear fully managed (M4250, M4300, M4350, M5300, M7100) | SSH | Experimental, not validated against hardware. No PoE power profiles, timed rollback or VTP. |
| MikroTik RouterOS v7 | HTTPS (REST API) | Experimental, not validated against hardware. Changes are persistent immediately (no save step); no PoE budget or power profiles, restore, timed rollback, port security, ARP inspection, IP source guard, cable test or VTP. |
| Cisco Catalyst 9800 wireless controllers | RESTCONF / NETCONF | Supported (IOS XE 17.12). RESTCONF is read-only; configuration requires NETCONF. |

Not supported, because they offer no usable management interface for this tool: Netgear
Smart/Plus/Insight switches, MikroTik SwOS (CSS series) and Aruba Instant On. The full
capability matrix, device prerequisites and the commands used are in
[docs/switch-drivers.md](docs/switch-drivers.md).

## Quick start

Requirements: Python 3.10 or newer on Windows, Linux or macOS.

```bash
git clone https://github.com/Tristatus/SwitchSteward.git
cd SwitchSteward/backend
bash start.sh            # Windows (PowerShell): .\start.ps1
```

The script creates a virtual environment, installs the dependencies, generates
`backend/config.json` with random keys and starts the **setup wizard** on
<http://127.0.0.1:8000> (local access only; use an SSH tunnel on a headless server). The
wizard asks for:

1. a local administrator account (password of at least 12 characters),
2. bind address, port and HTTP/HTTPS mode (including reverse proxy),
3. the database file and, optionally, global device credentials and known-hosts files.

After saving, the server restarts with these settings. Sign in, enter the device
credentials, add the SSH host keys of your devices and create your switches. Active
Directory and Entra ID are configured later under **Administration**.

Details: [docs/installation.md](docs/installation.md).

## Documentation

| Document | Content |
| --- | --- |
| [docs/installation.md](docs/installation.md) | Start scripts, manual start, setup wizard, HTTPS and reverse proxy, web update, release archives, backups |
| [docs/configuration.md](docs/configuration.md) | Complete `config.json` reference, system and audit logs |
| [docs/authentication.md](docs/authentication.md) | Roles, local accounts and emergency access, Active Directory, Microsoft Entra ID app registration, group mappings, sessions |
| [docs/switch-drivers.md](docs/switch-drivers.md) | Driver architecture, capability matrix, vendor prerequisites, adding a driver |
| [docs/wlan-catalyst-9800.md](docs/wlan-catalyst-9800.md) | Wireless controller integration |
| [docs/architecture.md](docs/architecture.md) | Modules, request flow, data model, frontend, internationalization, release manifest, audit action catalog |
| [SECURITY.md](SECURITY.md) | Security model, known limitations and how to report vulnerabilities |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Security notes

- Run SwitchSteward in an internal management network or behind a VPN, never directly on the internet. Use HTTPS (built-in or reverse proxy) and `session.cookie_secure: true` in production.
- `backend/config.json` contains the key that encrypts all stored device credentials. Keep it out of version control, restrict its permissions and back it up; without it the stored credentials cannot be decrypted.
- Use dedicated device service accounts with the least privileges your platform allows.
- SSH host keys are verified and legacy SSH algorithms are disabled by default. Insecure exceptions (legacy SSH, unverified TLS, unencrypted LDAP) must be enabled explicitly and are logged as warnings at every start.
- All drivers except Cisco IOS/IOS-XE are experimental. Test them on a lab device before production use.

See [SECURITY.md](SECURITY.md) for the full security model.

## Release archives

```bash
python scripts/build_release.py     # dist/switchsteward.zip and dist/switchsteward.tar.gz
```

The archives are the packages accepted by **Administration → Software update**; source
archives generated by GitHub are not. Run the script from the repository root; it needs
only the Python standard library.

## Contributing

Bug reports and pull requests are welcome on GitHub. To add a switch driver, follow
[docs/switch-drivers.md](docs/switch-drivers.md#adding-a-driver). German is the source
language of all UI texts; English translations live in `frontend/i18n.en.js` and
`backend/app/i18n_en.py`.

## License

SwitchSteward is free software: you can redistribute it
and/or modify it under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the [LICENSE](LICENSE) file for the full text.
