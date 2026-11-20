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
  the certificate it returns, or install a certificate you already have. *Format* offers: **Detect from the file**,
  **PFX / PKCS#12** (.pfx/.p12 with its password), **Certificate for the request made here** (.cer/.crt/.pem in PEM or
  DER, or a .p7b chain), **Certificate + separate private key** (.crt/.cer/.pem + .key: PKCS#8, RSA or EC, encrypted
  keys take a password), **One PEM file with certificate and key**, and on Windows **From this server's certificate
  store** (Local Computer > Personal, key must be exportable). Intermediate/CA certificates can be added as an optional
  chain file (.pem bundle, .crt or .p7b). *Check* shows the subject, names, validity, chain and whether the key matches
  (plus warnings: wrong server name, no Server Authentication usage, expiring soon, chain missing) before anything is
  changed; *Install certificate* checks again, keeps the old files as tls.crt.bak / tls.key.bak, and restarts the service. NetInventory never sends HSTS. If Edge or Chrome says a server "uses HSTS"
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
- **Sessions:** 12 hours, or 2 hours idle, in an HttpOnly, SameSite=Strict, Secure cookie that ends when the browser
  closes. Signing in on a browser where someone else is still signed in ends their session first.
- **Nothing carries over between people (0.29):** what one person chose in the browser (open tab, Logs tab and so on)
  is cleared at sign-in and sign-out, and API answers are sent `no-store` so the next person can't page back to them.
  Per-person settings are kept per user on the server: the Computers columns, and the DameWare sign-in mode
  (Settings > DameWare is now "your own setting"; the old shared value is the default for anyone who hasn't chosen).
  Scan schedules, credentials, groups and the rest of Settings stay shared.
- **Admins (0.44):** only admins see the Settings page and can change server-wide settings (sign-in, credentials, scan
  targets and schedule, exclusions, retention, agents, remote control, HTTPS, Jira, wireless, updates, app catalog rules,
  deployment queue). Name them in **Settings > Sign-in > Admins**: admin usernames, an AD group (nested membership counts)
  and/or a NetInventory user group. While none of these are set, everyone who can sign in is an admin, so upgrading changes
  nothing. The local admin account is always an admin (the break-glass file above is the way back in if the list is ever
  wrong), and Settings refuses to save an admin list that would leave out the person saving it. Admin rights are worked out
  at sign-in; when the list changes, other people's sessions are checked again on their next click (live in AD with the
  scan credential; if AD can't be asked they lose Settings until they sign in again). Only admins can edit or delete the
  user groups used for sign-in or admins, so nobody can add themselves from the Groups tab. Non-admins still pick their own
  DameWare mode by clicking their name at the top right.
- **Per-user state (0.44):** saved reports in the report builder belong to whoever saved them and only they see them,
  unless they tick *Share with everyone*. Reports saved before 0.44 stay shared; only an admin can change or delete a
  shared report someone else saved, and nobody can overwrite another person's report by saving one with the same name.
  The browser's own autofill history is turned off for every search and filter box, so one person's searches aren't
  offered to the next. An open page that finds the browser is now signed in as someone else (or signed out) starts over,
  and Back after signing out reloads instead of showing the last person's page.
- **Stored credentials:** encrypted with a key that Windows DPAPI protects for this machine (`secret.key.dpapi`). Copying
  the file to another server doesn't decrypt anything, so after a rebuild the scan credentials have to be entered again.

## Logs (Logs tab, 0.29)

- **Audit log:** every sign-in, failed sign-in, sign-out and session timeout, and every change made in NetInventory
  (settings, sign-in setup, groups, credentials, scan targets and jobs, deployments and fixes, scripts, AD changes, PC
  tools, agents, Jira, certificates, updates...), with who, when (shown in your local time), the IP address it came
  from and what changed. Changes that have no entry of their own are still recorded with the request (passwords,
  tokens and keys masked as `***`) and the result. Filter by kind (sign-ins / changes / failures), time, person,
  action, IP and text; **Export CSV** downloads what the filters show. The audit log is never trimmed.
- **Server log:** NetInventory's own log (scans, collectors, DC and WinRM errors, updates), kept in the database for
  30 days. Filter by level, part (logger), time and text.
- **Scans and collectors:** every scan job and collector run with its result; *Failed runs only* finds problems.
- **Log files on the server:** the files in `<data folder>\logs` (the service's `NetInventory.out.log` /
  `NetInventory.err.log`, setup and update logs): view the end of one or download it.

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

Scripts run hidden, with a time limit (1-240 minutes), through the deployment queue: a few PCs at a time,
and offline PCs get it when they come back online. Exit code 0 counts as success. Each run's output (the last 3,500
characters) and exit code are in Software > Deployments (click the name to see the output and exactly what ran) and
the PC's History. The script's text is copied into each push when it's queued, so editing or deleting the script
later never changes what an approved push runs; *Retry* runs the same text again. Saving and running scripts are in
the audit log, with a fingerprint (SHA-256) of the text.

### Run mode: who a script runs as (0.26)

Each script has a **Run mode** (edit it in Software > Scripts), like a deployment package's:

| Run mode | Runs as on the PC | Notes |
|---|---|---|
| **Select on deployment** (default) | asked each time you deploy | the Run as list starts on *Currently logged on user*; you can also pick any saved Windows credential |
| Currently logged on user | the person signed in, with their own rights (not elevated) | a scheduled task in their session; if nobody is signed in, the push waits (like an offline PC) until someone signs in or the queue deadline passes |
| Scanning credentials | the account that signs in over WinRM (the scan targets' ticked accounts) | runs with that account's password, so it can reach file shares |
| System account | the PC's SYSTEM account | full rights on the PC, no network identity except the computer account (how every script ran before 0.26) |

Picking a saved credential when deploying signs in *and* runs as that account. Picking *This server's own account*
runs it without a stored password (S4U), so it has no access to file shares. The Run as column in Software >
Deployments, and the deployment's name, show who each push ran as. *Retry* uses the same account again.
Scripts saved before 0.26 are set to *Select on deployment*.

The other deployments (app updates, uninstall/repair, Windows updates, services, reboots, Configure…, Push agent)
have a **Sign in with** choice in their dialog: the scanning credentials (default), any saved Windows credential, or
this server's own account. Installs and Windows updates still run as SYSTEM on the PC, because Windows only allows
that; the account only signs in to start them. Configure… changes and power actions run with the rights of the
account picked. Active Directory changes keep using the saved AD credential.

## Groups (Groups tab)

Make groups without picking PCs in the Computers list. A group is defined by conditions, by a list of names, or both:

| Condition | Example | Matches |
|---|---|---|
| IP address or range | `10.1.20.0/24`, `10.1.20.10-80`, `10.1.20.5` | any of the PC's addresses |
| Host name | `LAB-*`, `KIOSK??` | wildcards `*` and `?`; plain text = contains |
| Hardware model / Manufacturer | `OptiPlex 70*`, `HP*` | contains, or wildcards |
| AD OU | `corp.example.com/Sites/Office/PCs` or a DN | that OU and the OUs under it |
| AD group (security group) | `BitLocker PCs`, `IT-*` or a DN | members of that AD group, groups inside it included |
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

### User groups

A group can hold AD users instead of computers (*New group* > *Holds: Users*). Conditions: user name, display name,
department, job title, office, company, **AD OU** (ADUC path or DN, sub-OUs included), **AD group** (name, wildcard
or DN; nested groups count, and `Domain Users` matches everyone), account (Enabled / Disabled / Locked) and any
column of the Users list. *Always include these users* adds people by name. Members follow AD after each import.

What a user group is for:
- *Show in Users*: the Users list filtered to the group (the Users list also has a Groups column).
- *Account actions*: unlock, enable, disable or "must change password" for everyone in the group, one by one in AD,
  each change in the audit log.
- *Run script on their PCs* / *Configure their PCs*, and scan jobs: a user group used as a computer target means the
  computers its users signed in to in the last 30 days.
- **Sign-in access**: Settings > Sign-in > *Or members of this user group* lets that group sign in to NetInventory,
  alongside (or instead of) the AD group. The group's conditions are checked against the user's live AD entry at each
  sign-in, so moving someone into the OU or AD group gives access straight away.

AD group conditions use the groups stored by the AD import (0.23 and later), so run the AD import once after updating.

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
| `dc_logons` | WinRM to each DC and DHCP server, DNS | 30 min | Kerberos, NTLM and network logons with the computer each came from; DHCP leases and DNS records (see below) |

**Which computer a DC logon came from.** A DC's events name the DC, not the user's PC: network logons (4624) often
put the DC's own name in *Workstation name*, and Kerberos (4768), the bulk of domain sign-ins, has only the client IP.
NTLM events do name the client: 4624 type 3 in *Workstation name* and 4776 (read since 0.28) in *Workstation*.
NetInventory ignores the DC's own name and works out the PC, in this order:

1. the workstation name in the event itself, when it is a real PC;
2. the PC that held that IP **in DHCP at the time of the event** (DHCP audit log and leases, below);
3. the PC another event from the same IP named within 8 hours (an NTLM logon gives the name, a Kerberos one the IP);
4. a PC whose adapter has that IP today, then the routers' ARP tables (IP to MAC to PC);
5. a PC whose DNS A/AAAA record is that IP, then reverse DNS (PTR).

Hover the computer on a Logons tab to see which step matched it (`matched_by` in the `v_logons` view). Steps 4 and 5
use today's addresses, so they can be wrong for old events after a DHCP move; steps 1 to 3 can't.

**DHCP leases and DNS (0.28).** With each DC logons run, NetInventory reads every Windows DHCP server over WinRM: the
active IPv4 leases (IP, MAC, host name) and the DHCP audit log (`DhcpSrvLog-*.log`, the last 7 days), which says which
PC had which address when. The servers are the ones authorized in AD, or the list in Settings, What to scan, *DHCP
servers*. The scan account needs WinRM on those servers and to be in their **DHCP Users** group (reading the audit log
also needs read access to `%SystemRoot%\System32\dhcp`, which admins have). It then looks up every enabled AD
computer in DNS (A and AAAA). Both go into `ip_sightings` and give a PC that WinRM never reached an IP and MAC in the
Computers list (column *IP from*: inventory, DHCP or DNS).

**How the DC logon scan reads the logs:** over WinRM (TCP 5985, PowerShell remoting) to each domain controller the AD
import found, with the same Windows credentials as the PC scan. On the DC it runs `Get-WinEvent` on the Security log for
events 4768 (Kerberos ticket), 4624 type 3 (network logon) and 4776 (NTLM validation) since the last pull (7 days the first time). It does not
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

**Sign in with** on a scan job picks the Windows account it uses for AD, PC inventory and DC logons: *Scanning
credentials* (each target's ticked accounts, the default) or one saved account (or this server's own account).
*Run now* asks which account to use for that run only, starting on the job's own setting. The job's result says
which account it signed in as. SNMP keeps its community strings.

### One-time scan (0.30)

**One-time scan…** (Scanning tab, and Settings next to *Scan everything now*) scans something once, now, without
saving a scan target or a scan job. Type one or more of: an IP address, a range (`10.0.2.10-60`) or CIDR, a computer
name, a username (`jsmith`, `CORP\jsmith` or `jsmith@corp.example.com`), an AD OU (as ADUC shows it, or a DN) or a
whole domain. *It is* works out what each value is (the dialog shows what it found before you start), or set it by hand.

Tick the scans: *Ping*, *SNMP*, *PC inventory over WinRM* (an IP range is swept on 5985 first), *Pending Windows
updates too*, *Active Directory details* (a computer or user by name is looked up on its own, not the whole domain) and
*Logons from domain controllers*. A username with PC inventory also scans the 5 computers that user signed in to most
recently. **Sign in with** is the same picker as scan jobs: the scanning credentials (the accounts ticked on your saved
targets), one saved account, or this server's own account; SNMP credentials can be picked too.

Results go into the inventory like any scan. The run shows live on the Scanning tab (with **Cancel**), then in
*Recently finished* as *One-time scan* with what was scanned, who started it and the account it signed in as. The audit
log has *scan.once* when it starts and *scan.once.done* with the result. It doesn't wait in the job queue. Exclusions
still apply.

### Switch ports and computers (0.31)

The SNMP switch scan reads each switch's MAC address table (Q-BRIDGE / BRIDGE-MIB, per VLAN on Cisco) and its LLDP/CDP
neighbours. A computer is tied to a port by **MAC address**: the MACs from its own inventory (agent or WinRM), else the
MAC in its DHCP lease, so PCs only read from AD are found too. The computer page shows the switch, port (click it),
VLAN and how the MAC was matched; the *Switch location* tab lists every access port the PC was seen on.

The **neighbor** is what LLDP/CDP says is on the other end, and it is classified from its capabilities: another switch,
a router or an access point makes the port an **uplink** (its MACs are not plugged in there, so they are left out),
as does a port with more MACs than `uplink_mac_threshold` (default 6). An **IP phone** neighbour does not: the PC behind
the phone is mapped to that port and shown as *behind phone*. A PC that sends LLDP itself links to that computer.
Click a switch under *Network devices* (or pick it in the drop-down) to list only its ports. Network → *Switch ports* has the port type, VLAN, neighbour (linked to the computer or polled switch) and the
computers on each port; click a port to see every MAC learned on it, which computer owns it and, for uplinks, which
access port that computer is really on. Ports keep their old type until the next switch scan.

### MAC tables per switch (0.34)

*Network devices* now shows how many MACs each switch gave on its last scan and how (Q-BRIDGE-MIB, BRIDGE-MIB or Cisco
per-VLAN BRIDGE-MIB), or why it gave none: a red **0** with the reason, such as the SNMP view not including BRIDGE-MIB
(1.3.6.1.2.1.17) or a walk that timed out. Cisco IOS / IOS-XE switches are now always read VLAN by VLAN
(`community@vlan`, or the SNMPv3 context `vlan-N`, which needs `snmp-server group <g> v3 priv context vlan- match prefix`);
before, a switch that answered anything for VLAN 1 was read for VLAN 1 only. Switches that don't serve
dot1dBasePortIfIndex are read with bridge port = ifIndex.

### Port status and last active (0.33)

*Switch ports* shows each port's link as a **green up**, **red down** (enabled, but nothing plugged in or the device is
off) or **grey disabled** (shut down on the switch) pill. For a port that isn't up, **last active** says when it last had
a link, so you can tell a PC that was just switched off (*recent*, within 24 hours) from a desk that has been empty for
weeks (*unused 30+ days*). It comes from the switch's ifLastChange (the moment the link went down), the last scan that
saw the port up, and the newest MAC learned on it, so ports polled before 0.33 get a time from their MAC history on the
next scan. A port that has been down since the switch restarted, with nothing seen on it before, shows *not since switch
restart*. The *Switch ports down* report lists them oldest first.

**Plugged in** lists what is on each access port, best name first: the computer (linked), else the name the device
asked DHCP for, else its IP (switch/router ARP table or DHCP lease), else just its MAC. A phone is listed first with
the PC behind it underneath. MACs show their maker where it is in a short built-in list (phones, printers, cameras,
NAS, Raspberry Pi, VMs...) or *random MAC* for a privacy address; hover a device for its MAC and IP.

Since 0.38 *Switch ports* loads nothing until you pick a switch in the drop-down or click one under *Network devices*,
so big networks open fast. *Plugged in* and the new **MACs** column are read straight from that switch's own MAC table
(the MACs it learned on each access port), so a device shows on every switch that sees it at the edge. A device not
seen at the last scan is shown greyed with when it was last seen. A summary line above the table says how many MACs
were found on access ports at the last scan, how many before, and how many on uplinks; if it reads 0 on access ports
the switch is only learning MACs on uplinks (check the VLAN/community settings), and any error from the stored port
map is shown there too.

The separate *Port map* tab is gone (it repeated *Switch ports*). Its one extra, finding a device without knowing its
switch, is the **Find a PC, IP or MAC on any switch** box at the top of *Switch ports*: it lists every access port the
device was seen on, newest first, and clicking the switch opens its ports. MACs can be typed with colons, dashes or none.

Since 0.42 *Plugged in* starts from exactly the rows the port map holds for that switch (the same data the old *Port
map* tab showed) and only adds older sightings from the switch's MAC table; the summary line says how many port map
devices the switch has, and anything that doesn't line up with a listed port is shown under the table instead of being
dropped. The dashboard page now links `app.js` and `style.css` with a content hash, so after an update the browser
always loads the new script instead of a copy it cached from the previous version.

Since 0.43 Cisco switches are always read per VLAN, even when they also answer Q-BRIDGE-MIB. Some IOS-XE releases
answer Q-BRIDGE-MIB for VLAN 1 only (the uplinks and the odd VLAN 1 printer), which used to stop the per-VLAN walk and
left access ports on every other VLAN empty. The *MAC table (last scan)* note under *Network devices* shows both
sources, for example `412 MACs via Cisco per-VLAN BRIDGE-MIB (6 VLANs) + Q-BRIDGE-MIB (29)`.
Each device in *Plugged in* now reads name first (the computer, else its DHCP name), then its IP beside it, and shows
the MAC only when neither a name nor an IP is known.

Since 0.45 MACs the switch holds as static (port-security sticky MACs, `switchport port-security mac-address`) are kept;
they come back as *mgmt* or *other* rather than *learned*, and were dropped before, which left access ports with
port-security empty while the trunks still showed MACs. On Cisco the VLANs read are VTP-MIB's list plus every access
and voice VLAN configured on a port (so VTP transparent mode or a view without VTP-MIB still works), bridge ports map to
interfaces through any VLAN's table, and the *MAC table (last scan)* note names any VLAN that returned no MACs, which
usually means the community doesn't answer as `community@VLAN` or the SNMPv3 group lacks `context vlan- match prefix`.

### Wi-Fi: which access point (0.33)

Scanned PCs and the agent now report how they are connected (the adapter the default route uses: **wired** or
**Wi-Fi**) and, on Wi-Fi, the network (SSID), signal and the BSSID of the access point. The computer page shows
*Connection* and *Access point* with when it was last seen there and, when the AP is plugged into a polled switch,
that switch port. The *Switch location* tab lists every AP the PC has been on, newest first, since laptops move.
Computers list columns: Connection, Wi-Fi network, Access point, Wi-Fi last seen. On Windows 11 24H2 and later the
SSID/BSSID need location services turned on; without it the PC still reports that it is on Wi-Fi.

A BSSID is named from the wireless controller's AP list, or from a switch port whose LLDP/CDP neighbour is an access
point with a nearby MAC (vendors number BSSIDs up from the AP's MAC), so it works without a controller when the APs
send LLDP.

**Settings > Wireless controller** (optional, read only) adds every Wi-Fi client, phones and printers included, and
names the APs: **UniFi Network** (address, a local read-only account, site; UniFi OS consoles and the classic 8443
controller), **Cisco Meraki** (Dashboard API key, optional organization ID) or a **Cisco WLC** (AireOS or Catalyst 9800,
read over SNMP with the saved SNMP credentials). It is polled every 15 minutes by default; *Test connection* and *Poll
now* are on the same panel. The password or key is stored encrypted and never shown again.


### Faster on large networks, data retention (0.35)

The Computers list, dashboard, switch pages and user pages stay fast as switch MAC tables, logons and Wi-Fi history
fill up. On a test network of 3,000 PCs, 60 switches, 330,000 MAC sightings and 2 million logon events (PostgreSQL),
the first page of computers went from 65 s to 0.02 s and the server's peak memory from 280 MB to about 120 MB.

- **Stored port map.** Where each MAC is plugged in (`v_port_map`) is kept in a `port_map` table and recomputed when
  switch, NIC, ARP or DHCP data changes (within 20 s, at the next page load that needs it, and every 15 minutes anyway).
  Before, every computer row recomputed it for every switch column. `v_port_map` keeps its columns, so BI tools and
  saved reports work as before.
- **Indexes** for the lookups the views do: logons by computer/user and time, DHCP and DNS sightings by host and MAC,
  MAC and ARP history by MAC. The first start after the upgrade adds them (a few seconds to a minute on a big logon table).
- Last user, last computer and logon counts read the logon table by index instead of grouping every logon.
- Matching DC logons to computers works in batches and only re-checks the last 14 days, instead of loading every
  unmatched logon into memory on each start and each DC import.
- The dashboard no longer loads every installed program to count outdated software; standard reports show the first
  20,000 rows (export for all).

**Settings > Data retention** sets how long the fastest-growing history is kept; older rows are removed once a day
(*Clean up now* runs it at once). Defaults: logon events 180 days, MAC sightings and ARP entries not seen for 90 days,
Wi-Fi AP history 180 days, computer change history 2 years, scan runs 90 days, finished pushes 1 year. 0 keeps a table
forever. Current data (where a MAC is now, a PC's details) and the audit log are never removed.

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

Install the launcher (Settings > DameWare has **Download the launcher (zip)** and each file on its own; the zip
fills in the server's DNS domains as allowed suffixes and has a README.txt with these steps):
- On one PC: unzip, double-click `Install.cmd` and click Yes (or tick *Install the DameWare launcher on this PC* in the
  NetInventory installer, or run `Install-DameWareHandler.ps1` as administrator).
- On many PCs by GPO: put the unzipped folder on a share (for example NETLOGON) and add `Install-DameWareHandler.ps1` as
  a computer startup script; it runs as SYSTEM and is safe to repeat. Or, with no script, copy `Open-DameWare.ps1` to
  `C:\ProgramData\NetInventory\` with a Files preference and set the keys from `dameware-handler.reg` with Registry
  preferences. The files ship in `netinv\dameware` (on the server also in `<install dir>\tools\dameware`, which a Start
  menu shortcut opens).

Optional per-PC registry values under `HKLM\SOFTWARE\NetInventory`: `DameWarePath` (if `DWRCC.exe` isn't found
automatically), `DameWareExtraArgs`, and `DameWareAllowedSuffixes` (for example `.corp.example.com`). The launcher accepts only
single-label computer names, private IP addresses and names ending in an allowed suffix, so a link from another web page
can't point DameWare (and the technician's Windows logon) at an outside host. Links never contain passwords.
Check the switches against your DameWare version with `DWRCC.exe -?`. Browsers ask before opening the link; to skip the
prompt for the NetInventory site, use the Edge/Chrome policy *AutoLaunchProtocolsFromOrigins*.

## Jira (Settings > Jira)

Create a Jira issue from a computer, a user or a dashboard alert, and see the related issues on the **Jira** tab of
each computer and user page. Works with Jira Cloud (`https://yourcompany.atlassian.net`).

Setup: in Settings > Jira enter the site, a Jira account's e-mail and an API token
(id.atlassian.com > Security > API tokens). A dedicated service account that can create issues in the right
projects works best; issues are created as that account. Pick a default project (*Find* lists the projects the account
can create in) and issue type, save, then click *Test connection*. The token is encrypted on the server like the scan
credentials and never shown again. The server needs outbound HTTPS to `*.atlassian.net`.

- **Create Jira issue** (computer page, user page, alert drawer) opens a dialog prefilled with the inventory facts:
  computer, OS, IP, model, serial, last user and switch port, or the user's name, e-mail, department and last PC, or
  the alert and the computers in it. Edit anything before clicking OK. Nothing is sent to Jira until then, and no
  passwords, keys or recovery keys are ever included. Each create is in the audit log.
- Every issue gets the labels `netinv`, `netinv-<computer>` and/or `netinv-user-<username>` (alerts also
  `netinv-alert-<rule>`) and a web link back to the NetInventory page.
- The **Jira** tab lists the 25 most recently updated issues with those labels, issues the user reported (found by
  their e-mail, which covers service desk requests), and, unless turned off in Settings, issues that mention the
  computer or user name anywhere. *Open this search in Jira* opens the same JQL in Jira.

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
  the selected rows, or every filtered row when nothing is selected. A **Domain** drop-down narrows the list to one
  AD domain (taken from each PC's AD distinguished name, else its DNS suffix). **Columns…** adds, removes and reorders
  the list's columns from any field of the report builder's computer dataset (serial, RAM, domain, warranty, antivirus...);
  every column gets its own filter box, and the choice is saved per signed-in user (*Reset to default* undoes it).
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

## Remote control (NetInventory Remote, 0.36)

A **second, separate agent** for remote control from the dashboard. The NetInventory Agent above stays report-only;
NetInventory Remote does nothing but screen sharing with mouse and keyboard, and only when a session is asked for.

**Using it.** On a PC's page click **Remote control** (or the *Remote control* tab for its status and session history).
A window opens; give an optional reason (Settings can require one), tick *View only* if you only need to look, and
click Connect. The toolbar has Ctrl+Alt+Del, Win, Alt+Tab, a display picker, picture quality, fit/actual size and
full screen. Close the window or click **End session** to disconnect.

**Who can connect, and when the user is asked** (Settings > Remote control):
- *Who can use it*: optional AD security group. Empty = anyone who can sign in to NetInventory.
- *Connect without asking*: AD security group whose members connect directly. Everyone else's request pops up on
  the PC for the signed-in user ("<technician> wants to see and control this computer… Allow?"); the default answer
  is No, and no answer within 30 seconds (configurable) is No. Nested groups count. Membership is checked live in AD
  at each request with the scan credential; if AD can't be asked, the user is asked (and with an allowed group set, the
  request is refused). The local admin account always asks.
- Nobody signed in at the PC: connect (default) or refuse. A locked PC whose user doesn't answer is refused.
- Sessions end after 8 hours, or 30 minutes without input (both configurable).
- Per-PC policy (GPO, `HKLM\SOFTWARE\Policies\NetInventory\Remote`, DWORDs): `AlwaysAsk=1` always asks the user,
  whatever the technician's group (for HR, finance, executives); `Disabled=1` turns remote control off on that PC.

**What the user at the PC sees.** The question (unless the technician is in the direct group), then for the whole
session a bar at the top of the screen: *Remote control by <technician> (NetInventory)* with an **End session**
button. Requests, answers, starts and ends are also written to the PC's Application event log (source *NetInventory Remote*).

**Installing.** Computers > select PCs > **Push remote control**, or **Install or update remote control** on a PC's
page: over WinRM like other deployments, with a one-time ticket per PC (approved at once). It counts as done when the
PC has connected to the server. For GPO/Intune: Settings > Remote control > download `NetInventory-Remote.msi` and
`msiexec /i NetInventory-Remote.msi /qn SERVER=https://server:port TOKEN=nra_... PIN=<sha256>` (a separate token from
the inventory agent's). PCs installed that way are approved by the *New PCs* rule; a second PC claiming a name that
already has an agent always waits for approval. *Revoke* disconnects a PC at once.

**Security design.**
- Nothing listens on the PC: the service (`NetInventoryRemote`, LocalSystem) keeps one outbound WebSocket over TLS 1.2+
  to the server, which can't be reached from anywhere else. No inbound firewall rule, no port scan surface.
- The server's certificate is pinned (SHA-256). No proxy, no redirects. The PC's own secret (from enrollment) is kept
  DPAPI-encrypted in `%ProgramData%\NetInventory Remote`, readable only by SYSTEM and Administrators, and signs the
  connection (HMAC-SHA256 over time, nonce and path; replays and >5 min clock skew are refused).
- The server can only *ask* for a session. Consent is decided on the PC (with the PC's policy winning over the server).
- Each session has two random one-time tokens (viewer and PC), good for 2 minutes. The viewer's WebSocket also needs
  the same signed-in user and a same-origin request (no cross-site WebSocket hijacking); basic auth can't start sessions.
- The screen is captured by a helper process started for that one session in the user's Windows session (so it also
  works on the sign-in screen and UAC prompts), with its token passed over a pipe, never on the command line.
- The server re-builds every viewer message from checked values: only mouse (in-screen coordinates), key codes,
  wheel, display and quality pass; view-only sessions pass no input; at most 600 messages a second.
  **No clipboard, no file transfer, no command channel**: the agent has no code that could run anything.
- One session per PC; any signed-in user can end any session from Settings > Remote control.
- Everything is in the audit log (`rc.request`, `rc.consent`/`rc.denied`, `rc.start`, `rc.cad`, `rc.end`,
  `rc.refused`, `rc.settings`, `rc.agent.*`) and in the session list with who, which PC, how it was allowed, the user at
  the PC, the reason, the duration and why it ended.
- The exe and the MSI are Authenticode-signed by CI (Code signing, below); the push reports the MSI's signature status on the PC.

**Why our own small agent instead of VNC, RustDesk or MeshCentral.** VNC servers (UltraVNC, TightVNC) listen on a port,
have a long CVE history (memory corruption in the protocol parsers) and weak built-in authentication. RustDesk and
MeshCentral are good, but each brings its own server, relay, accounts and update channel to run and patch, plus
features (file transfer, terminal, clipboard) we'd then have to lock down. RDP shadowing needs inbound 3389 and can't
apply "group may skip the prompt" per technician. NetInventory Remote is under 1,800 lines of Go: memory-safe, one
static 7 MB exe with two dependencies (`golang.org/x/sys` from the Go team, and `coder/websocket`), using Windows'
own APIs for everything sensitive (WTSSendMessage for the question, DPAPI, SendInput, SendSAS), and it reuses the
server's existing sign-in, TLS certificate, audit log, push queue and code signing. Only what remote control needs.

**Limits.** Screen pictures are JPEG tiles of what changed (GDI capture): fine for support work on a LAN or VPN,
not for video. Only the console session (not other RDP sessions on a server). Ctrl+Alt+Del needs *SoftwareSASGeneration*
allowing services; the MSI sets it to 1 when it isn't set. Check a PC: `%ProgramData%\NetInventory Remote\agent.log`
(as admin) and `Get-Service NetInventoryRemote`.

## Code signing (0.28)

CI signs the agent scripts (`netinv/agent/*.ps1`, `agent/Send-Inventory.ps1`), the agent MSI, the remote control
agent (`NetInventoryRemote.exe` and `NetInventory-Remote.msi`) and the server installer with Authenticode when the repository has two secrets: `CODESIGN_PFX_BASE64` (the code-signing .pfx,
base64-encoded) and `CODESIGN_PFX_PASSWORD`. The certificate must have the Code Signing purpose (EKU
1.3.6.1.5.5.7.3.3): a TLS or wildcard certificate can't sign code. An internal AD CS *Code Signing* certificate works;
domain PCs already trust the CA, and a GPO adds the certificate to **Trusted Publishers** so `AllSigned` execution
policies and SmartScreen/AppLocker rules accept the agent. Signatures are timestamped, so they stay valid after the
certificate expires. Without the secrets the build is published unsigned, with a warning on the run.
`installer\sign.ps1 <files>` signs by hand with the same variables.

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
netinv/dameware/           dameware:// launcher, installer script and GPO .reg for technician PCs
installer/                 Windows installer (Inno Setup) and its build script
```
