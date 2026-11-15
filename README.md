# NetInventory

Agentless inventory and insights for a Windows AD network. It finds domain controllers, PCs,
switches and routers, works out which switch port each PC is plugged into, and reports on what needs
attention: OS out of support, missing patches, outdated software, full disks, stale AD accounts,
the last user on each device and the devices each user has signed in to.

```
            ┌──────────── LDAP(S) ───────────► Domain controllers  (computers, DCs, sites, FSMO)
            │──────────── WinRM ─────────────► DC Security logs    (4768 Kerberos / 4624 logons)
 NetInventory ─────────── WinRM ─────────────► Each PC             (OS, patches, software, disks, NICs, logons)
 (FastAPI)  │──────────── SNMP v2c/v3 ───────► Switches / routers  (MAC tables, LLDP/CDP, ARP, ports)
     │
     └── PostgreSQL ── v_* views ──► dashboard, report builder, CSV, Power BI / Excel / Metabase
```

## Quick start (demo data)

```bash
cp config.example.toml config.toml && cp .env.example .env   # edit both
docker compose up -d --build
docker compose exec app python -m netinv demo                # optional: load sample data
# open http://<server>:8080
```

Without Docker you need Python 3.11+ and PostgreSQL: `pip install -r requirements.txt`, then
`python -m netinv serve`. For a quick look, `DATABASE_URL=sqlite:///netinv.db python -m netinv demo`
also works.

## Windows installer

`installer/` builds a single `NetInventory-Setup-<version>.exe`. On any Windows 10/11 machine with internet access:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build.ps1
# -> installer\output\NetInventory-Setup-0.1.0.exe
```

The build needs no admin rights and no installed Python. It downloads the embeddable Python and
the app's packages (also kept as offline wheels), PostgreSQL binaries, WinSW, the VC++ runtime and
Inno Setup, then runs a smoke test with the bundled Python before compiling.

What the installer does on the server:
- **Wizard:** install folder, then a choice between a bundled PostgreSQL and an existing server
  (connection details), then the web port and dashboard password.
- **Dependency checks, with fixes where possible:** Windows version and 64-bit, PowerShell 5.1,
  VC++ 2015-2022 runtime (installed if missing), Python packages (reinstalled from the bundled
  wheels if any fail to import), web port already in use, database reachable.
- **Bundled database:** initialises a PostgreSQL cluster in `C:\ProgramData\NetInventory\pgdata`
  on localhost:5442 with a random password, and registers it as the `NetInventory-PostgreSQL` service.
- **App service:** registers the `NetInventory` service (automatic, delayed start, restarts on failure),
  writes `C:\ProgramData\NetInventory\config.toml` (only Administrators and SYSTEM can read it),
  opens the web port in the firewall for the Domain and Private profiles, and waits until the dashboard answers.
- **Start menu:** Open dashboard, Edit configuration, Restart service, Load demo data, Logs folder.
- **Upgrades** keep the existing config and database. **Uninstall** removes the services and firewall
  rule but leaves `C:\ProgramData\NetInventory`, so delete that folder by hand to wipe everything.

Setup logs are written to `C:\ProgramData\NetInventory\logs\install.log`.

## Updates

Source lives in the private `userxx09-afk/lan` repo. Every push to `main` runs `.github/workflows/ci.yml`: it tests
the app, builds the installer on a Windows runner (version `<VERSION file>.<build number>`, e.g. `0.3.14`) and
publishes it to the public `userxx09-afk/prod` repo as release `lan-v<version>` and the rolling release
`lan-latest` (installer: `https://github.com/userxx09-afk/prod/releases/download/lan-latest/NetInventory-Setup.exe`).
Publishing needs the `PROD_REPO_TOKEN` secret, the same one the other apps use.

Installed servers read `lan-latest/latest.json` once a day. **Settings > Software updates** (and a badge next to the
logo) shows when a newer version is out; **Install update** downloads it, checks its SHA-256 against `latest.json`,
and runs setup silently as SYSTEM. Setup stops the services, replaces the program, keeps `config.toml`, `secret.key`,
the database and the port, updates the schema, and starts everything again; the dashboard is back in a minute or two.
The log is in `C:\ProgramData\NetInventory\logs\update-<version>.log`. Running the new installer by hand does the same.

`config.toml`:
```toml
[update]
check_hours = 24        # 0 turns the check off
auto_install = false    # true installs new versions without waiting for a click
```

## What runs, and how often

| Job | Source | Default interval | What it gives you |
|---|---|---|---|
| `ad` | LDAP to any DC | 60 min | Every computer object, OS, `lastLogonTimestamp`, enabled state, DCs with site, GC and FSMO roles |
| `snmp` | SNMP to switches and routers | 15 min | Ports, MAC table, LLDP/CDP neighbours, ARP (IP to MAC) |
| `pcs` | WinRM to each PC | 4 h | OS build, hardware, serial, disks, NICs, installed software, hotfixes, pending reboot, local logons |
| `pcs_updates` | WinRM to each PC | daily | Same as `pcs` plus the Windows Update search for pending updates (slow) |
| `dc_logons` | WinRM to each DC | 30 min | Kerberos and network logons, matched to PCs by IP |

Run any job by hand with `python -m netinv collect <job|all>`, or from the Collectors buttons on the Overview page.

## How the port mapping works

1. The forwarding table of every switch gives MAC to port (Q-BRIDGE-MIB, falling back to BRIDGE-MIB,
   and per-VLAN `community@vlan` / `vlan-N` context on Cisco IOS).
2. A port with an LLDP or CDP neighbour, or more than `uplink_mac_threshold` MACs, counts as an uplink
   and is ignored, so a PC maps to its access port and not to every trunk along the way.
3. The MAC is linked to a PC through the NIC list collected over WinRM, and to an IP through router ARP tables.
4. A MAC on an access port that doesn't match a known PC shows up under **Unknown devices on switch ports**
   (printers, phones, unmanaged switches, anything that shouldn't be there).

## Credentials and what to scan (Settings tab)

Add credentials and scan targets in **Settings** instead of editing `config.toml` (the `[ad]`, `[winrm]` and `[snmp]`
sections are only used while no scan target exists).

- **Credentials:** *Windows / AD* accounts are used for LDAP and for WinRM to PCs and DCs. *SNMP v2c* (community)
  and *SNMP v3* (user, SHA auth key, AES privacy key) are used for switches and routers. Secrets are encrypted with a
  key in `secret.key` next to `config.toml`, and are never sent back to the browser. Back up `secret.key`: without it, stored
  credentials have to be entered again. **Test** tries a credential against one DC, PC or switch.
- **Scan targets**, each with its own list of credentials that are tried in order:
  - *AD domain* (`corp.example.com`): every computer, user and DC in the domain.
  - *AD computer path* (`OU=Workstations,DC=corp,DC=example,DC=com`): only computers in that OU are imported and scanned.
  - *AD user path* (`OU=Staff,DC=…`): only users in that OU are imported.
  - *IP range* (`10.0.0.0/24`, `10.1.0.1-10.1.0.50`): network gear is polled over SNMP, and Windows PCs that answer
    WinRM on 5985 are scanned too.
  If no domain controller is given, NetInventory tries the domain name (DNS finds a DC) and then DCs seen in earlier scans.
- **Schedule:** minutes between scans of each kind.

**LDAPS:** NetInventory connects on 636 first and falls back to 389. Unlock works on either, but **password resets need LDAPS**,
and DCs that enforce LDAP signing need it for everything. Any DC with a certificate from AD CS (or another trusted
certificate) already listens on 636.

**Rights for user actions** (unlock, reset password, must change password, enable/disable): delegate them to the
scan account on the user OUs (Delegation of Control wizard > *Reset user passwords and force password change at next logon*,
plus write `lockoutTime` and `userAccountControl`), or add a second Windows credential with those rights to the AD target.
Every action is written to the audit log (Reports > Logons > Actions taken in NetInventory).

## DameWare Mini Remote Control

The **Remote control** buttons on a computer page, a user page (connects to the user's last PC) and a user's
computer list open `dameware://connect/?host=PC&mode=windows`. A small launcher on each technician PC turns that into
`DWRCC.exe -c: -m:PC -a:1 -x` (the technician's own Windows logon) or, with *Saved host entry* chosen in
Settings, `DWRCC.exe -c: -m:PC -h:` (the credentials saved for that host in DameWare).

Install the launcher:
- On one PC: tick *Install the DameWare launcher on this PC* in the installer, or run
  `tools\dameware\Install-DameWareHandler.ps1` as administrator.
- On many PCs by GPO: copy `Open-DameWare.ps1` to `C:\ProgramData\NetInventory\` with a Files preference and import
  `dameware-handler.reg` with a Registry preference (both are in `tools\dameware`; a Start menu shortcut opens the folder).

Optional per-PC registry values under `HKLM\SOFTWARE\NetInventory`: `DameWarePath` (if `DWRCC.exe` isn't found
automatically), `DameWareExtraArgs`, and `DameWareAllowedSuffixes` (for example `.corp.example.com`). The launcher accepts only
single-label computer names, private IP addresses and names ending in an allowed suffix, so a link from another web page
can't point DameWare (and the technician's Windows logon) at an outside host. Links never contain passwords.
Check the switches against your DameWare version with `DWRCC.exe -?`. Browsers ask before opening the link; to skip the
prompt for the NetInventory site, use the Edge/Chrome policy *AutoLaunchProtocolsFromOrigins*.

## Setup checklist for your environment

**Service account** (for example `CORP\svc-netinv`):
- Reading AD needs only a normal domain user.
- For PCs, add it to the local Administrators group with GPO (Restricted Groups or Group Policy Preferences > Local Users and Groups).
- For DCs, add it to the built-in **Event Log Readers** group, plus **Remote Management Users** for WinRM. It does not need Domain Admins.

**WinRM on PCs** with one GPO linked to the workstation OU:
- Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management > WinRM Service > *Allow remote server management through WinRM*: Enabled. Set the IPv4 filter to `*` or your subnets.
- Computer Configuration > Policies > Windows Settings > Security Settings > System Services > *Windows Remote Management*: Automatic.
- Windows Defender Firewall: allow inbound TCP 5985 (or 5986 for HTTPS) from the NetInventory server only.

**Audit policy on DCs** so logon events exist. Default Domain Controllers Policy > Advanced Audit Policy:
- *Account Logon > Audit Kerberos Authentication Service*: Success.
- *Logon/Logoff > Audit Logon*: Success.

**SNMP on switches:** set up a read-only community or a v3 user restricted to the server's IP, and turn on LLDP (and CDP on Cisco).
Put core routers and L3 switches in `targets` as well, because the IP-to-MAC mapping comes from their ARP tables.

**Linux/Docker host with Kerberos:** `auth = "negotiate"` works with NTLM out of the box. Kerberos needs `/etc/krb5.conf`
mounted into the container.

## Reports and analytics

- **Dashboard alerts:** about 30 checks grouped *High priority* (unsupported OS, WinRM access denied, under 1 GB free,
  no antivirus, SMART disk warnings, locked-out users), *Important* (unreachable, low disk, warranty, antivirus off or out of date,
  not patched in 35 days, pending updates, outdated software, unknown devices on switch ports) and *Informational* (not on the
  newest build seen for that Windows version, reboot pending, stale AD computers and users, passwords that never expire).
  Click a count to see the computers or users behind it and export them. Thresholds are in `[insights]` in `config.toml`.
- **Standard reports:** about 50 ready-made reports (Active Directory, Assets, Operating system, Software, Network, Logons)
  with Excel/CSV/XML export. Most open in the report builder to change fields or filters.
- **Users:** every AD user with filters (enabled, disabled, locked out), and a user page with general, organization and
  account details, the computers they logged on to, groups, logon events and the audit trail, plus actions: remote control
  to their last PC, unlock, reset password, must change password, enable and disable.
- **Computers grid:** a filter box on every column, sorting, paging, and multi-select with bulk actions
  (rescan, Wake on LAN, add to or remove from group, set state). Exports to Excel, CSV or XML cover
  the selected rows, or every filtered row when nothing is selected.
- **Asset page:** an action sidebar (ping, remote desktop .rdp, copy `\\PC\c$` or `admin$` path,
  Wake on LAN, rescan, reboot with confirmation) and tabs for Summary, Software, Updates, Switch location
  history, Logons, History (software, OS, hardware and port changes between scans) and Comments.
  Groups, custom fields, state, location, purchase date and warranty end can be edited on the page.
- **Report builder:** pick a dataset, tick the fields you want, add filters (date filters accept `30d` to mean 30 days ago), sort, then **Save** or **Export CSV**.
- **BI tools:** point Power BI, Excel (Get Data > PostgreSQL) or Metabase at the database and use the views:

| View | One row per |
|---|---|
| `v_devices` | PC, with OS, hardware, last user, IP, switch and port, disk, patch state |
| `v_port_map` | MAC: the access port it is on now |
| `v_user_devices` | user and device pair, with last logon and count |
| `v_logons` | raw logon event |
| `v_software`, `v_updates`, `v_disks` | install, update or disk per PC |
| `v_switch_ports`, `v_network_devices`, `v_domain_controllers` | port, switch, DC |

Give BI tools a read-only Postgres role: `GRANT SELECT ON ALL TABLES IN SCHEMA public TO bi_reader;`.

## Agentless limits

- PCs that are off, or laptops away from the office, only update when they are next reachable over WinRM.
  The **In AD but not inventoried** list shows which ones are missing.
- The Windows Update search is slow over WinRM, so it runs daily. If you run WSUS, it can be added as a source.
- Installed software comes from the machine-wide Add/Remove Programs keys. Per-user installs (some Teams, Zoom
  and Chrome installs) aren't included in agentless mode.

## Optional agent (later)

`agent/Send-Inventory.ps1` collects exactly the same data and POSTs it to `/api/ingest/endpoint` using the
`ingest_token`. Run it as a scheduled task on laptops that are rarely on the network. Nothing else changes,
because both paths go through `netinv/ingest.py`.

## Layout

```
netinv/
  main.py            FastAPI app: dashboard, reports API, report builder, ingest endpoints
  db.py              SQLAlchemy models (devices, disks, software, updates, logons, switches, ports, MACs, ARP)
  correlate.py       SQL views that join everything (the reporting layer)
  reports.py         prebuilt reports, insights (EOL, disk, patches, outdated software), safe query builder
  ingest.py          shared payload format for the WinRM pull and the future agent
  jobs.py            collector jobs and built-in scheduler
  scanning.py        runs scan targets (AD domain / OU paths, IP ranges) with stored credentials
  alerts.py          dashboard alert rules (High / Important / Informational)
  library.py         standard report library
  secrets.py         encryption for stored credentials
  actions.py         ping, Wake on LAN, rescan, reboot, .rdp files
  collectors/ad.py   LDAP: computers, users, groups, DCs, FSMO; unlock / password reset / enable / disable
  collectors/winrm.py  PowerShell remoting: PCs and DC logs
  collectors/snmp.py   switches and routers
  demo.py            sample data
  static/            dashboard (plain HTML/JS, no build step)
agent/Send-Inventory.ps1   optional push agent
tools/dameware/            dameware:// launcher, installer script and GPO .reg for technician PCs
installer/                 Windows installer (Inno Setup) and its build script
```
