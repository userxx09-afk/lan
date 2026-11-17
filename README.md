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
- **Wizard:** install folder, data folder (`C:\ProgramData\NetInventory` by default: config, logs,
  HTTPS certificate, encryption key), then a choice between a bundled PostgreSQL (with its own
  folder, `<data folder>\pgdata` by default, and port, 5442 by default) and an existing server
  (connection details), then the web port and dashboard password. The data and database folders
  must be new or empty (or hold data from an earlier NetInventory install, which is kept), because
  setup restricts them to Administrators and SYSTEM. They can be on another drive, but not inside
  or around the install folder.
- **Port checks:** when you click Next on a port page, setup checks whether another program is
  already listening on that port. If one is, it names the program, leaves it alone, and offers the
  next free port (or lets you type another). NetInventory's own processes from the same install
  folder don't count, so reinstalling over a running copy works. Upgrades keep the ports already in use.
- **Dependency checks, with fixes where possible:** Windows version and 64-bit, PowerShell 5.1,
  VC++ 2015-2022 runtime (installed if missing), Python packages (reinstalled from the bundled
  wheels if any fail to import), web and database ports already in use (checked again in case something grabbed them after the wizard), database reachable.
- **Bundled database:** initialises a PostgreSQL cluster in the database folder
  on localhost (port 5442 unless you chose another) with a random password, and registers it as the `NetInventory-PostgreSQL` service.
- **App service:** registers the `NetInventory` service (automatic, delayed start, restarts on failure),
  writes `config.toml` in the data folder (only Administrators and SYSTEM can read it),
  opens the web port in the firewall for the Domain and Private profiles, and waits until the dashboard answers.
- **Start menu:** Open dashboard, Edit configuration, Restart service, Load demo data, Logs folder.
- **Upgrades** skip the wizard pages and keep the install folder, data folder, database folder,
  ports and config. **Uninstall** stops and removes both services, the scheduled tasks and the firewall
  rule, and deletes everything setup put in the install folder. It then asks whether to delete the
  data and database folders too (default: keep them, so a reinstall picks up where it left off).

Setup logs are written to `logs\install.log` in the data folder (`C:\ProgramData\NetInventory` by default).

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
The log is in `logs\update-<version>.log` in the data folder. Running the new installer by hand does the same.

`config.toml`:
```toml
[update]
check_hours = 24        # 0 turns the check off
auto_install = false    # true installs new versions without waiting for a click
```

## Sign-in and security

- **HTTPS:** setup creates a self-signed certificate (`tls.crt` / `tls.key` in the data folder) and the
  dashboard runs on `https://<server>:<port>/`. Browsers warn about a self-signed certificate. To stop that, go to
  Settings > HTTPS certificate: download the certificate and trust it on PCs by GPO (Trusted Root Certification
  Authorities), or create a request for AD CS (`certreq -submit -attrib "CertificateTemplate:WebServer" ...`) and install
  the certificate it returns, or upload a .pfx. NetInventory never sends HSTS. If Edge or Chrome says a server "uses HSTS"
  and offers no way past the warning, it remembered HSTS from another site that used the same server name: delete the name
  under `edge://net-internals/#hsts` (or `chrome://net-internals/#hsts`), Delete domain security policies.
- **Scanning exclusions:** Settings > Scanning exclusions lists IP addresses or ranges, host names (wildcards), AD OUs
  and MAC addresses that every scan skips, and Windows events (source + ID, e.g. `Microsoft-Windows-DistributedCOM 10009`)
  that are never stored. Common DCOM/WMI noise events are excluded by default. Changes are in the audit log.
- **Local admin:** the account chosen during setup. Its password is stored as a PBKDF2 hash (`python -m netinv hashpw`
  makes one).
- **AD sign-in:** in **Settings > Sign-in** enter the domain and an AD group (name or DN). Members of the group, nested
  groups included, sign in with their own AD account (`user`, `DOMAIN\user` or `user@domain`). Every sign-in and action
  is audited under that user. **Test** checks an AD account without signing in.
- **Break-glass:** after the first successful AD sign-in NetInventory writes `local-login.disabled` in the data folder,
  which turns the local admin off. If AD or the group is unavailable, or the group was set wrong, delete that file on the
  server and sign in as the local admin again. It is written again at the next AD sign-in.
- **Lockout:** 5 failed sign-ins for one username, or 20 from one address, within 15 minutes block sign-in for 15 minutes.
- **Sessions:** 12 hours, or 2 hours idle, in an HttpOnly, SameSite=Strict, Secure cookie.
- **Stored credentials:** encrypted with a key that Windows DPAPI protects for this machine (`secret.key.dpapi`). Copying
  the file to another server doesn't decrypt anything, so after a rebuild the scan credentials have to be entered again.

## App versions and one-click fixes

**Software tab.** Every program found on the PCs is matched to the public winget catalog. NetInventory downloads that
catalog from Microsoft once a day (`cdn.winget.microsoft.com`, about 4 MB, into `catalog` in the data folder).
Programs are matched by their uninstall key / MSI product code first, then by name and publisher. Each install shows as
*current*, *outdated* (with the latest version), *not in catalog* or *ignored*. Per-user installs (in a user's profile)
are included. When the matching gets one wrong, add a rule in **Settings > App catalog**:
- *Use this winget package*: pick the right package (for example the 32-bit or 64-bit Reader).
- *Treat this version as up to date*: for software you deliberately keep on an older version.
- *Ignore*: never report it as behind.

Reports > Software has *Outdated apps* reports, and the Dashboard lists apps behind the latest version.

**Fixes** (PC page > Fix, the Updates tab, and the Software tab). Each one asks for confirmation and goes to the audit
log and the PC's History:
- *Install Windows updates*: installs what Windows Update offers that PC (its WSUS server if a GPO sets one). It never
  restarts the PC.
- *Update app*: `winget upgrade --id <package> --exact` as SYSTEM, for machine-wide installs. *Update N* on the
  Software tab does it on every PC that is behind (up to 500 at a time). Needs App Installer (winget) on the PC, which
  Windows 10/11 have; Windows Server and LTSC usually don't.
- *Start a stopped service*: Microsoft Defender Antivirus, Windows Update or BITS. Services disabled by policy are left alone.
- *Schedule a reboot*: in 5 minutes or tonight at the hour set in Settings (02:00 by default), with a notice to the
  signed-in user; *Cancel scheduled reboot* undoes it.

Windows doesn't allow installs straight from a remote session, so updates run from a one-off scheduled task
("NetInventory fix ...") as SYSTEM, which writes its result to `C:\ProgramData\NetInventory\fix` on the PC.
NetInventory picks the result up and adds it to the PC's History. Nothing installs automatically.

## Deployment log and queue (Software > Deployments)

Every push from NetInventory (app updates with winget, installing Windows updates, starting a service, reboots) is a
row in the deployment log, also shown on the PC's **Deployments** tab: what, who, when, how many tries and the result
(*succeeded*, *failed* with the reason, *expired*, *cancelled*). Pushes to many PCs are queued and sent a few at a time
(default 8). A PC that can't be reached keeps its push **waiting** and gets it when it is back online, retried every
10 minutes and as soon as its dot turns green, until the deadline (default 7 days), then it is marked *expired*.
Waiting pushes can be cancelled; failed ones retried.

## Live PC tools (a PC's page)

Over WinRM, live, on demand:
- **Processes**: name, PID, user, CPU %, memory, threads, session, start time, path (hover for the command line);
  **End** a process. Windows system processes (lsass, csrss, svchost, …) can't be ended from here.
- **Services**: state, start type, account; start, stop, restart, or set Automatic / Automatic (delayed) / Manual /
  Disabled. Services Windows or NetInventory itself depend on (WinRM, RPC, LSA, …) can't be stopped or disabled.
- **Software**: besides *Update*, **Uninstall** (MSI with `msiexec /x`, others only if they have a silent
  uninstaller; anything else is refused rather than left half-removed) and **Repair** (MSI). These go through the
  deployment queue, so they wait for an offline PC and their result lands in the deployment log.

- **Registry**: browse HKLM, HKU (each user's hive by SID) and HKCR; create, edit (String, Expandable string,
  DWORD, QWORD, Multi-string) and delete values, create keys, delete keys (three or more levels deep). The old value
  is recorded with every change. SAM, SECURITY and the Lsa key are read-only here.
- **Printers & drives**: the PC's printers (status, waiting jobs, driver, port, shared); print a test page, clear a
  queue, remove a printer, and add a shared printer for every user of the PC (`printui /ga`, appears at their next
  sign-in). Below: the mapped drives and recently used shares of each signed-in user.
- **Local accounts**: members of the local Administrators group (add a DOMAIN\user or group, remove one) and the
  local user accounts (enabled, admin, last sign-in; enable/disable). The built-in Administrator, Domain Admins and
  the account NetInventory signs in with can't be removed or disabled from here.

- **Sessions**: everyone signed in (console or Remote Desktop) with state, idle time and sign-in time; send a
  session a message, disconnect it, or log it off.
- **Command**: run one PowerShell or cmd command and see its output (not interactive; stopped after 30–100 s).
- **WMI**: browse namespaces and classes and see a class's instances and properties, or run a WQL query
  (SELECT / ASSOCIATORS OF / REFERENCES OF only, so it can't change anything). Examples and copy-as-CSV included.
- **Files**: browse any local drive of the PC; view a text file or log (the last 512 KB, even while another
  program has it open), download a file, upload files (several at once), new folder, rename, delete. Transfers go over
  WinRM, up to 200 MB per file and 4 at a time (they share the bandwidth). Windows, Program Files and the drive roots
  can't be renamed, deleted or written to from here.
- **Security**: BitLocker per volume, TPM, Secure Boot, UAC, firewall profiles, Microsoft Defender (real-time,
  tamper protection, signature age, last scans, recent detections) and the antivirus registered with Windows. Start a
  Defender quick or full scan, update signatures. **Show BitLocker recovery keys** reads them from AD with the saved
  Windows credential (each look is audit-logged). **Group Policy results** shows `gpresult /r` for the computer and
  the signed-in user; **Group Policy update** runs `gpupdate /force`.
- **Install Windows updates** asks what to do if an update needs a restart: ask the user to restart (pop-up),
  restart 5 minutes after installing (with a countdown), or nothing (the PC shows "reboot pending").
- **Active Directory**: the computer object read live (DN, enabled, description, location, managed by, groups);
  edit description or location, move to another OU, add to or remove from a group, enable or disable the account,
  and rename the computer (on the PC and in AD; takes effect at its next restart). Uses the saved Windows credential.
- **Performance**: CPU, memory, disk activity, free space per drive, busiest processes and network throughput,
  refreshed every 10 s while the tab is open.
- **Event logs**: any log (System, Application, Security, …) filtered by level, time span, source, event ID and
  text; click a row for the whole message, a source or ID to filter on it.
- **Tasks & startup**: scheduled tasks (yours, or Windows' too) with last result and next run; run, end, enable,
  disable (Windows' own tasks can't be stopped or disabled). Startup programs from the Run keys and Startup folders;
  remove one (a removed shortcut is kept in ProgramData\NetInventory\startup-removed).
- **Shares & variables**: shared folders with their share permissions; share a folder (Read/Change/Full for an
  account) or stop sharing (admin shares, NETLOGON and SYSVOL are left alone). System and per-user environment
  variables; add, edit, delete (Path, ComSpec, windir and the like can't be deleted, and a Path without System32 is refused).
- **Network**: adapters (IP, gateway, DNS, DHCP, speed, MAC), TCP/UDP connections and listening ports with the
  program behind each; flush DNS, register in DNS, release and renew DHCP, Group Policy update.
- **Devices**: Device Manager's list with driver version, date and provider; devices with a problem code first.
- **Screenshot of the user's screen** (left side): captures every signed-in user's screen (all monitors) and shows it
  in the browser with a Save link. The user always gets a notice ("Your IT department took a screenshot of your
  screen"); the image isn't kept on the server, and each one is audit-logged.
- **Audit report** (left side): one printable page (print or save as PDF) with everything stored about the PC:
  summary, disks, adapters, switch port, software, updates, users and logons, deployments, History and comments.
  *Include live checks* also asks the PC for its local administrators, security state, shares, startup programs
  and automatic services that aren't running.
- **Power** (left side): restart or shut down now or after a delay with a notice to the user, cancel a pending
  shutdown, hibernate, sleep, lock the screen, log off everyone. **Send a pop-up message** to everyone on the PC, one
  session, or (from a user's page) that user on their last PC; one way, shown with `msg.exe`.

Every change is confirmed first and written to the audit log and the PC's History. Text typed in the browser is
sent to the PC as data (base64-encoded), never pasted into the script as code.

## Configure many PCs at once (Computers > Configure…, Groups > Configure)

Pick computers in the list (or a group) and apply one change to all of them: power (restart or shut down with a
notice, hibernate, lock, log off everyone), a pop-up message, Windows updates (with the restart choice), a service
action, a registry value, local Administrators membership, a printer for every user, a system environment
variable, Group Policy update / DNS, Defender scan or signatures, or an AD change (description, location, move to
OU, group, enable/disable). It goes through the deployment queue like scripts and app updates: a few PCs at a time,
offline PCs get it when they're back, and each PC's result is in Software > Deployments and its History. The same
checks apply per PC as on its page (for example WinRM is never stopped), and a refused PC fails with the reason.

## Scripts (Software > Scripts)

Keep a library of PowerShell or command prompt scripts, and run one, or a one-off command, on:
- one PC: *Run a script or command* on its page;
- the PCs you select in Computers: *Run script* above the list;
- every PC in a group, or a typed list of names: *Run…* next to a script.

Scripts run as SYSTEM, hidden, with a time limit (1-240 minutes), through the deployment queue: a few PCs at a time,
and offline PCs get it when they come back online. Exit code 0 counts as success. Each run's output (the last 3,500
characters) and exit code are in Software > Deployments (click the name to see the output and exactly what ran) and
the PC's History. The script's text is copied into each push when it's queued, so editing or deleting the script
later never changes what an approved push runs; *Retry* runs the same text again. Saving and running scripts are in
the audit log, with a fingerprint (SHA-256) of the text.

## Groups (Groups tab)

Make groups without picking PCs in the Computers list. A group is defined by conditions, by a list of names, or both:

| Condition | Example | Matches |
|---|---|---|
| IP address or range | `10.1.20.0/24`, `10.1.20.10-80`, `10.1.20.5` | any of the PC's addresses |
| Host name | `LAB-*`, `KIOSK??` | wildcards `*` and `?`; plain text = contains |
| Hardware model / Manufacturer | `OptiPlex 70*`, `HP*` | contains, or wildcards |
| AD OU | `corp.example.com/Sites/Office/PCs` or a DN | that OU and the OUs under it |
| Operating system / State | `Windows 11`, `Stock` | |
| Other field... | `av_name` is `*Defender*`, `ram_gb` less than `8`, `warranty_end` less than `2027-01-01`, `model` is empty | any column of the Computers list (the report builder's fields): is, is not, less / more than (numbers, dates), empty, not empty |

Combine them with *all of these match* or *any of these matches*; commas in one box mean "any of these", and each
condition can be *is not* (handy to leave one PC out). The editor shows how many PCs match as you type.

Members follow the inventory: rule-based membership is recalculated after every scan, every 5 minutes (agent
reports, edits) and whenever the group is saved or used. *Always include these computers* keeps named PCs in the group
whatever the rules say. A PC in a group only because of its rules shows a "rules" chip on its page instead of ×.
Groups tagged by hand from the Computers list still work and show as "by hand". Click a group's name to see its
computers with OS, IP address, model, OU and last user.

Use a group as a target: *Run script* and *Push agent* on the Groups tab (or the group choice in the script dialog),
*Show in Computers* to act on its PCs with the usual buttons, and in a scan job (Settings > Scan schedule) *Only PCs
in this group* limits PC inventory and Windows update scans to its members. Renaming a group carries its scan jobs
along; a group a scan job uses can't be deleted until the job is changed.

## Dashboard drill-down

Every number on the Dashboard opens the matching list: the KPI tiles (computers, inventoried, not inventoried,
mapped to a port, users, DCs, network devices), each row of *Operating systems* (exact OS and version), and each alert,
whose list can be opened in the Computers list to select those PCs and act on them. A chip above the list says what
it's narrowed to; × shows all computers again.

Reports work the same way. In a summary report (Computers by OS and version, by build, by manufacturer and model,
by group, enabled/disabled, duplicate serials, software titles and versions, outdated or unknown apps, installs by
catalog status, devices per switch) click a row or its count to open the Computers list narrowed to exactly those PCs.
A report that lists computers (and the report builder's results) has **Show in Computers list** to open all of them.
PCs that were only read from AD (no WinRM or agent inventory yet) get their version (23H2, 24H2...) from the build
number in AD's `operatingSystemVersion`; a PC whose AD account has no OS shows as *(not reported)*.

## What runs, and how often

These are the collectors. **Scan jobs** (Settings > Scan schedule) decide when they run and on which targets;
the defaults below are the jobs an upgrade from 0.6 starts with.

| Collector | Source | Default interval | What it gives you |
|---|---|---|---|
| `ad` | LDAP to any DC | 60 min | Every computer object, OS, `lastLogonTimestamp`, enabled state, DCs with site, GC and FSMO roles |
| `snmp` | SNMP to switches and routers | 15 min | Ports, MAC table, LLDP/CDP neighbours, ARP (IP to MAC) |
| `pcs` | WinRM to each PC | 4 h | OS build, hardware, serial, disks, NICs, installed software, hotfixes, pending reboot, local logons |
| `pcs_updates` | WinRM to each PC | daily | Same as `pcs` plus the Windows Update search for pending updates (slow) |
| `dc_logons` | WinRM to each DC | 30 min | Kerberos and network logons, with the computer each came from (see below) |

**Which computer a DC logon came from.** A DC's events name the DC, not the user's PC: network logons (4624) often
put the DC's own name in *Workstation name*, and Kerberos (4768) has only the client IP. NetInventory ignores the
DC's own name and works out the PC from the event: its workstation name when that is a real PC, otherwise the IP,
matched to a PC's adapter in the Computers list, then to the routers' ARP tables (IP to MAC to PC), then reverse
DNS. A user's **Logons** tab shows that PC as *computer* (linked to its page when it's in the inventory) and the DC
as *domain controller*; the PC's own Logons tab and the user's Computers tab use the same match. The IP match uses
today's addresses, so a DHCP address that has since moved to another PC can point at the wrong one.

**How the DC logon scan reads the logs:** over WinRM (TCP 5985, PowerShell remoting) to each domain controller the AD
import found, with the same Windows credentials as the PC scan. On the DC it runs `Get-WinEvent` on the Security log for
events 4768 (Kerberos ticket) and 4624 type 3 (network logon) since the last pull (7 days the first time). It does not
use remote Event Log RPC. The account needs WinRM access to the DC and read access to the Security log: a Domain
Admin, or a member of the DC's *Remote Management Users* and *Event Log Readers* groups. Each DC's own error (WinRM
refused, not reachable, or "connected as X but reading the Security log failed") is in the run's result.

Run any collector by hand with `python -m netinv collect <job|all>`, or from the Collectors buttons on the Overview page.

### Scan jobs (Settings > Scan schedule)

Each job has a name, a scope (some scan targets, or all of them), the collectors to run, and a schedule: *repeatedly*
(every N minutes or hours, optionally only between two hours and on some weekdays), *once a day* at a time, or *only by
hand*. For example: the front office OU every 30 minutes during the day, everything else daily at 02:00.

Load controls: *PCs scanned at once over WinRM* per job (default 16), and *at most N jobs at once* for the whole server
(default 1). A job never overlaps itself, and jobs over the limit wait in a queue, first in line first. Exclusions apply
to every job. **Run now**, enable/disable, last and next run and a per-job **History** are in the table.

### Live status and uptime

The dot next to each PC is live: **green** when it answered the last up check (or was just scanned), **red** when it
didn't (hover for since when), **orange** when it hasn't been checked yet. The up check runs every 5 minutes (Settings,
Scan schedule; 0 = off): one ICMP echo per PC (no admin rights needed on Windows), then a TCP knock on 445/135/3389/5985
if ping is blocked. A refused connection counts as up, unless the network rejects everything, which NetInventory detects
by knocking on an address that can't exist. **Uptime** (since the last boot reported by a scan) is a column in the
Computers list and is shown at the top of each PC's page; offline PCs show *offline* instead.

### Scanning view

The **Scanning** tab (or the *Scanning…* pill next to the name at the top, shown while anything runs) lists:
- running jobs with their steps, PCs done of total, failures, the PCs being scanned right now, the time elapsed and an ETA
  (from the PC rate, or from the job's last run), with **Cancel** (PCs already in progress finish, the rest are skipped);
- the queue, with an estimated start for each job, **Move to front** and **Remove**;
- scheduled jobs coming up, and recently finished runs with their counts, errors and whether they were cancelled.
- while PCs or DCs fail, **why**: the failures grouped by reason (for example *2849 × Access denied: ...*), and the
  latest failures by computer. Every PC's last error is also on its page and in Reports, *Last scan times*.

A scan with nothing to do (no target of that kind, no Windows credential on its targets, or targets left out of the
schedule) shows **skipped** with the reason, never *ok*. A scan where every PC or DC failed shows **failed**.

**Server log:** Start menu, NetInventory, *Logs folder* (`<data folder>\logs`): `NetInventory.err.log` has every
scan's per-host warnings (`WinRM <host> failed: ...`, `DC <host> logon pull failed: ...`).

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
  and *SNMP v3* (user, SHA auth key, AES privacy key) are used for switches and routers. **This server's own account**
  is always on the list: the Windows account the NetInventory service runs as, with no password stored (WinRM signs
  in with Negotiate/Kerberos, LDAP with Kerberos). Run the service as a domain account with admin rights on the PCs
  (services.msc, NetInventory, Log On) to use it; under SYSTEM, other machines see the server's computer account. Secrets are encrypted (see
  *Sign-in and security*) and are never sent back to the browser. **Test** tries a credential against one DC, PC or switch.
- **Scan targets**, each with its own list of credentials that are tried in order. A target's *Include in scheduled
  scans* box only affects scheduled runs: **Scan now** and a job's **Run now** scan every target with its credentials.
  To pause scanning, untick *Enabled* on the job in Scan schedule.
  - *Whole AD domain* (`corp.example.com`): the computers, the users, or both (tick boxes), plus the DCs.
  - *AD OU of computers*: only computers in that OU and below are imported and scanned; no users.
  - *AD OU of users*: only user accounts in that OU and below are imported; no computers.

  An OU can be typed the way Active Directory Users and Computers shows it, `corp.example.com/Sites/Office/PCs`, or as a
  DN, `OU=PCs,OU=Office,OU=Sites,DC=corp,DC=example,DC=com`. The *searches* column shows the exact LDAP search base used.
  (Before 0.7 an OU path typed as an AD domain scanned the whole domain; those targets are turned into OU targets on upgrade.)
  - *IP range* (`10.0.0.0/24`, `10.1.0.1-10.1.0.50`): tick what runs on it. *Ping sweep* finds the addresses that are up
    and marks known PCs online or offline. *SNMP* polls switches and routers (needs an SNMP credential). *WinRM sweep*
    finds Windows PCs on port 5985 so the PC inventory scans them (needs a Windows credential). Only ticked methods run.
    A scan job can narrow this further with its own *On IP ranges, run* boxes.
  If no domain controller is given, NetInventory tries the domain name (DNS finds a DC) and then DCs seen in earlier scans.
- **Scan schedule:** see *Scan jobs* above.

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

## NetInventory Agent (optional)

For laptops and PCs that WinRM can't reach. Settings > **NetInventory Agent** has the download, the enrollment token,
the certificate pin and the list of enrolled PCs (approve, revoke, *Inventory now*).

What it is: three PowerShell scripts in `C:\Program Files\NetInventory Agent` and one scheduled task,
*NetInventory Agent*, that runs every 5 minutes and at startup as **LOCAL SERVICE** (no admin rights). Each run sends a
small heartbeat (boot time, signed-in user, IPv4 addresses), which turns the PC's dot green and keeps uptime current.
When the server answers that an inventory is due (every 24 hours by default, or after *Rescan*/*Inventory now*), the same
run sends the inventory: the same data as the WinRM scan (generated from it by `tools/gen_agent.py`). As LOCAL SERVICE it
skips what needs admin rights (pending Windows updates, per-user apps, the Security log); install with `RUNAS=SYSTEM`
to collect those too.

Security:
- **Outbound only**: HTTPS to the NetInventory server. Nothing listens on the PC; no firewall rule is added.
- **Pinned server**: with `PIN` (the SHA-256 shown in Settings) the agent talks only to a server presenting that
  certificate, even a self-signed one; without it, the certificate must be trusted by Windows.
- **Per-PC secret**: the enrollment token is used once, to get the PC's own random secret, stored DPAPI-encrypted in
  `%ProgramData%\NetInventory Agent` (readable only by SYSTEM, Administrators and the task account). The server keeps the
  token only as a hash and each secret encrypted. Rotating the token doesn't affect enrolled PCs.
- **Signed requests**: HMAC-SHA256 over the time, a one-time nonce, the path and the body; 5-minute window, no replays.
  An agent can only report for the computer it enrolled as.
- **Approval**: by default PCs that are in AD are approved automatically; others, a second agent claiming an enrolled
  PC's name, or a PC whose agent was revoked wait for approval. *Revoke* stops a PC at once.
- The server never sends code: its only answer is "inventory due" or not.

Deploy:
- **From the dashboard** (easiest): select PCs in Computers and click **Push agent** (or *Install or update the agent* on a
  PC's page). It goes through the deployment queue over WinRM with the scan credential: the server sends the agent MSI that
  ships with it (no download on the PC), installs it as SYSTEM, runs it once and only reports success once the PC has
  enrolled with this server. Each PC gets a one-time enrollment ticket (good once, for that PC, for a day) and is
  approved automatically; the site token isn't used. Failures show the agent's own error (certificate pin, firewall,
  name). *Remove the agent instead* uninstalls it and revokes it. The **Agent** column shows active / silent (no report
  for an hour) / installing / pending / push failed.
- Download: the MSI is served by NetInventory itself (Settings > Agent) and is on the server in `<install dir>\agent-msi`
  for a GPO share.
- Script or Intune: `msiexec /i NetInventory-Agent.msi /qn SERVER=https://netinv.corp.local:8080 TOKEN=nia_... PIN=<sha256> [RUNAS=SYSTEM]`
  (Settings shows the exact command when you create a token).
- GPO: assign the MSI under *Computer Configuration > Policies > Software Settings > Software installation*, and set
  the strings `Server`, `EnrollToken` and `Pin` in `HKLM\SOFTWARE\Policies\NetInventory\Agent` with *Preferences >
  Windows Settings > Registry* (policy values override the MSI's).
- A PowerShell execution policy of *AllSigned* enforced by GPO blocks the (unsigned) scripts; *RemoteSigned* is fine.
- Check a PC: `powershell -File "C:\Program Files\NetInventory Agent\NetInventoryAgent.ps1" -Mode Test` as admin;
  the log is `%ProgramData%\NetInventory Agent\agent.log`.
- Uninstall the MSI to remove the task, the secret and the log; then *Revoke* or *Remove* the PC in Settings.

`agent/Send-Inventory.ps1` (the older one-shot script using the shared `ingest_token`) still works but has no pinning
or per-PC secret; prefer the agent.

## Layout

```
netinv/
  main.py            FastAPI app: dashboard, reports API, report builder, ingest endpoints
  db.py              SQLAlchemy models (devices, disks, software, updates, logons, switches, ports, MACs, ARP)
  correlate.py       SQL views that join everything (the reporting layer)
  reports.py         prebuilt reports, insights (EOL, disk, patches, outdated software), safe query builder
  ingest.py          shared payload format for the WinRM pull and the future agent
  jobs.py            collectors, scan jobs, queue and built-in scheduler
  progress.py        live progress of running scans (Scanning view)
  reach.py           up/down checks for the live status dot
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
agent/Send-Inventory.ps1   older one-shot push script (prefer netinv/agent)
  netinv/agent/              the NetInventory Agent scripts (MSI: installer/agent)
tools/dameware/            dameware:// launcher, installer script and GPO .reg for technician PCs
installer/                 Windows installer (Inno Setup) and its build script
```
