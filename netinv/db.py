"""Data model. SQLite by default; set database.url to a Postgres URL to scale up."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def norm_mac(mac: str | None) -> str | None:
    """Normalise any MAC format to aa:bb:cc:dd:ee:ff."""
    if not mac:
        return None
    hexchars = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(hexchars) != 12:
        return None
    return ":".join(hexchars[i:i + 2] for i in range(0, 12, 2))


def norm_host(name: str | None) -> str | None:
    if not name:
        return None
    return name.split(".")[0].strip().upper() or None


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- endpoints
class Device(Base):
    """A domain computer / PC. Merged from AD, the endpoint agent and the network."""
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))
    # From AD
    ad_dn: Mapped[str | None] = mapped_column(Text)
    ad_enabled: Mapped[bool | None] = mapped_column(Boolean)
    ad_os: Mapped[str | None] = mapped_column(String(128))
    ad_os_version: Mapped[str | None] = mapped_column(String(64))
    ad_last_logon: Mapped[datetime | None] = mapped_column(DateTime)
    ad_created: Mapped[datetime | None] = mapped_column(DateTime)
    ad_seen: Mapped[datetime | None] = mapped_column(DateTime)
    # From the agent
    os_caption: Mapped[str | None] = mapped_column(String(128))
    os_build: Mapped[str | None] = mapped_column(String(32))
    os_display_version: Mapped[str | None] = mapped_column(String(32))
    manufacturer: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    serial: Mapped[str | None] = mapped_column(String(128))
    cpu: Mapped[str | None] = mapped_column(String(255))
    ram_gb: Mapped[float | None] = mapped_column(Float)
    last_boot: Mapped[datetime | None] = mapped_column(DateTime)
    current_user: Mapped[str | None] = mapped_column(String(128))
    pending_updates: Mapped[int | None] = mapped_column(Integer)
    pending_reboot: Mapped[bool | None] = mapped_column(Boolean)
    last_patch_installed: Mapped[datetime | None] = mapped_column(DateTime)
    agent_last_report: Mapped[datetime | None] = mapped_column(DateTime)
    # How the PC is connected (its default-route adapter): wired or wireless, and for Wi-Fi the network and access
    # point it was last on, from the PC's own scan/agent or from the wireless controller.
    connection: Mapped[str | None] = mapped_column(String(16))
    wifi_ssid: Mapped[str | None] = mapped_column(String(64))
    wifi_bssid: Mapped[str | None] = mapped_column(String(17))
    wifi_signal: Mapped[int | None] = mapped_column(Integer)        # percent
    wifi_ap: Mapped[str | None] = mapped_column(String(128))        # access point name, when we can tell
    wifi_seen: Mapped[datetime | None] = mapped_column(DateTime)
    agent_version: Mapped[str | None] = mapped_column(String(16))
    gpu: Mapped[str | None] = mapped_column(String(255))
    # Lifecycle / asset management (edited in the UI)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, default=utcnow)
    purchase_date: Mapped[datetime | None] = mapped_column(DateTime)
    warranty_end: Mapped[datetime | None] = mapped_column(DateTime)
    asset_location: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str | None] = mapped_column(String(32), default="Active")  # Active | Stock | Retired ...
    last_switch_port: Mapped[str | None] = mapped_column(String(255))  # for "moved to another port" history
    # Scan health and security posture
    scan_error: Mapped[str | None] = mapped_column(Text)
    scan_error_kind: Mapped[str | None] = mapped_column(String(32))   # access_denied | unreachable | other
    scan_error_time: Mapped[datetime | None] = mapped_column(DateTime)
    av_name: Mapped[str | None] = mapped_column(String(255))
    av_enabled: Mapped[bool | None] = mapped_column(Boolean)
    av_up_to_date: Mapped[bool | None] = mapped_column(Boolean)
    ad_description: Mapped[str | None] = mapped_column(Text)
    ad_location: Mapped[str | None] = mapped_column(String(255))
    ad_managed_by: Mapped[str | None] = mapped_column(Text)
    ad_groups: Mapped[str | None] = mapped_column(Text)      # JSON list of memberOf DNs, lower case (direct only)
    # Live status (reach.py, agent heartbeats): None = never checked
    online: Mapped[bool | None] = mapped_column(Boolean)
    online_checked: Mapped[datetime | None] = mapped_column(DateTime)
    online_changed: Mapped[datetime | None] = mapped_column(DateTime)   # when it last went online/offline
    online_via: Mapped[str | None] = mapped_column(String(16))          # ping | tcp | agent | winrm | dns

    nics: Mapped[list[DeviceNic]] = relationship(back_populates="device", cascade="all, delete-orphan")
    disks: Mapped[list[Disk]] = relationship(back_populates="device", cascade="all, delete-orphan")
    software: Mapped[list[Software]] = relationship(back_populates="device", cascade="all, delete-orphan")
    physical_disks: Mapped[list[PhysicalDisk]] = relationship(back_populates="device", cascade="all, delete-orphan")
    updates: Mapped[list[UpdateItem]] = relationship(back_populates="device", cascade="all, delete-orphan")


class DeviceNic(Base):
    __tablename__ = "device_nics"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    description: Mapped[str | None] = mapped_column(String(255))
    device: Mapped[Device] = relationship(back_populates="nics")


class Disk(Base):
    __tablename__ = "disks"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    drive: Mapped[str] = mapped_column(String(8))
    size_gb: Mapped[float] = mapped_column(Float)
    free_gb: Mapped[float] = mapped_column(Float)
    device: Mapped[Device] = relationship(back_populates="disks")


class PhysicalDisk(Base):
    """Physical drives with their health (Get-PhysicalDisk / SMART predict-failure)."""
    __tablename__ = "physical_disks"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    model: Mapped[str | None] = mapped_column(String(255))
    serial: Mapped[str | None] = mapped_column(String(128))
    media: Mapped[str | None] = mapped_column(String(32))
    size_gb: Mapped[float | None] = mapped_column(Float)
    health: Mapped[str | None] = mapped_column(String(32))          # Healthy | Warning | Unhealthy
    predict_failure: Mapped[bool | None] = mapped_column(Boolean)
    device: Mapped[Device] = relationship(back_populates="physical_disks")


class Software(Base):
    __tablename__ = "software"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    publisher: Mapped[str | None] = mapped_column(String(255))
    install_date: Mapped[str | None] = mapped_column(String(16))
    product_code: Mapped[str | None] = mapped_column(String(255))   # uninstall key name (MSI product code)
    scope: Mapped[str | None] = mapped_column(String(8))            # machine | user
    # Filled in by catalog.reconcile from the winget catalog
    catalog_id: Mapped[str | None] = mapped_column(String(128))
    latest_version: Mapped[str | None] = mapped_column(String(64))
    sw_status: Mapped[str | None] = mapped_column(String(12))       # current | outdated | unknown | ignored
    match_method: Mapped[str | None] = mapped_column(String(16))
    device: Mapped[Device] = relationship(back_populates="software")


class SoftwareRule(Base):
    """App catalog rule from Settings: ignore an app, map it to a winget package, or set the wanted version."""
    __tablename__ = "software_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    match: Mapped[str] = mapped_column(String(200))     # regex on the program name, case-insensitive
    action: Mapped[str] = mapped_column(String(16))     # ignore | package | target
    value: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[str | None] = mapped_column(String(64))
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UpdateItem(Base):
    """Installed hotfixes and pending Windows updates reported by the agent."""
    __tablename__ = "updates"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    kb: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # installed | pending
    severity: Mapped[str | None] = mapped_column(String(32))
    installed_on: Mapped[datetime | None] = mapped_column(DateTime)
    device: Mapped[Device] = relationship(back_populates="updates")


# --------------------------------------------------------------------------- AD / logons
class DomainController(Base):
    __tablename__ = "domain_controllers"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), unique=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))
    os: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))
    site: Mapped[str | None] = mapped_column(String(128))
    is_gc: Mapped[bool | None] = mapped_column(Boolean)
    fsmo_roles: Mapped[str | None] = mapped_column(String(255))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)


class LogonEvent(Base):
    """Raw interactive / remote logons (4624) pulled from DC or workstation Security logs."""
    __tablename__ = "logon_events"
    __table_args__ = (UniqueConstraint("source", "username", "time", "ip", "logon_type"),
                      # last user of a PC / last PC of a user without grouping every logon (v_devices, v_users)
                      Index("ix_logon_host_time", "hostname", "time"),
                      Index("ix_logon_user_time", "username", "time"),
                      Index("ix_logon_user_host", "username", "hostname"),
                      Index("ix_logon_ip_time", "ip", "time"))
    id: Mapped[int] = mapped_column(primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime, index=True)
    username: Mapped[str] = mapped_column(String(128), index=True)
    hostname: Mapped[str | None] = mapped_column(String(64), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))
    logon_type: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str | None] = mapped_column(String(64))  # which DC / agent reported it
    # How the computer was found (correlate.resolve_logon_hosts): event (WorkstationName in the event itself),
    # dhcp (DHCP lease for that IP at that time), named (another event from that IP named the PC), nic, arp,
    # dns (A/AAAA record of a PC), ptr (reverse DNS). None = stored by a version before 0.28.
    host_via: Mapped[str | None] = mapped_column(String(8))


class IpSighting(Base):
    """An IP address seen for a computer, from somewhere other than the PC's own inventory:
    DHCP leases and the DHCP audit log (source dhcp:<server>) and DNS A/AAAA lookups of AD computers (dns).
    first_seen..last_seen is when the binding held (for the DHCP audit log: the first grant to the last renewal)."""
    __tablename__ = "ip_sightings"
    __table_args__ = (UniqueConstraint("ip", "hostname", "source"),
                      Index("ix_ipsight_host_src", "hostname", "source", "last_seen"),
                      Index("ix_ipsight_mac_src", "mac", "source", "last_seen"))
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(64), index=True)
    mac: Mapped[str | None] = mapped_column(String(17), index=True)
    source: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires: Mapped[datetime | None] = mapped_column(DateTime)      # DHCP lease expiry (UTC), when known


# --------------------------------------------------------------------------- network
class NetworkDevice(Base):
    __tablename__ = "network_devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True)
    sysname: Mapped[str | None] = mapped_column(String(255))
    sysdescr: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(64))
    uptime_s: Mapped[int | None] = mapped_column(Integer)
    last_polled: Mapped[datetime | None] = mapped_column(DateTime)
    poll_error: Mapped[str | None] = mapped_column(Text)
    poll_note: Mapped[str | None] = mapped_column(Text)            # MACs found and how, or why none (last poll)
    ports: Mapped[list[SwitchPort]] = relationship(back_populates="switch", cascade="all, delete-orphan")


class SwitchPort(Base):
    __tablename__ = "switch_ports"
    __table_args__ = (UniqueConstraint("switch_id", "ifindex"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    switch_id: Mapped[int] = mapped_column(ForeignKey("network_devices.id", ondelete="CASCADE"), index=True)
    ifindex: Mapped[int] = mapped_column(Integer)
    name: Mapped[str | None] = mapped_column(String(64))
    alias: Mapped[str | None] = mapped_column(String(255))
    oper_up: Mapped[bool | None] = mapped_column(Boolean)
    admin_up: Mapped[bool | None] = mapped_column(Boolean)         # False = shut down / disabled on the switch
    # When the link last changed state (ifLastChange): for a down port, when it went down. The switch's boot time
    # when it has not changed since the switch started.
    last_change: Mapped[datetime | None] = mapped_column(DateTime)
    changed_since_boot: Mapped[bool | None] = mapped_column(Boolean)
    # Last time we know the link was up: seen up at a poll, went down at last_change, or a MAC learned on it.
    last_up: Mapped[datetime | None] = mapped_column(DateTime)
    speed_mbps: Mapped[int | None] = mapped_column(Integer)
    neighbor: Mapped[str | None] = mapped_column(String(255))  # LLDP/CDP neighbour, if any
    neighbor_port: Mapped[str | None] = mapped_column(String(255))
    # What the LLDP/CDP neighbour says it is: switch, router, ap, phone, computer, other or unknown (no capabilities sent).
    # Switches, routers and APs make the port an uplink; a phone or a PC that speaks LLDP is the device on the port.
    neighbor_kind: Mapped[str | None] = mapped_column(String(16))
    neighbor_mac: Mapped[str | None] = mapped_column(String(17))   # LLDP chassis ID, when it is a MAC
    neighbor_ip: Mapped[str | None] = mapped_column(String(64))    # LLDP management / CDP address
    neighbor_descr: Mapped[str | None] = mapped_column(Text)       # LLDP system description / CDP platform
    vlan: Mapped[int | None] = mapped_column(Integer)              # untagged (access) VLAN of the port, when the switch says
    mac_count: Mapped[int] = mapped_column(Integer, default=0)
    is_uplink: Mapped[bool] = mapped_column(Boolean, default=False)
    switch: Mapped[NetworkDevice] = relationship(back_populates="ports")


class MacSighting(Base):
    """A MAC address seen in a switch forwarding table on a given port."""
    __tablename__ = "mac_sightings"
    __table_args__ = (UniqueConstraint("mac", "port_id"), Index("ix_macsight_mac_seen", "mac", "last_seen"),
                      Index("ix_macsight_seen", "last_seen"))
    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("switch_ports.id", ondelete="CASCADE"), index=True)
    vlan: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    port: Mapped[SwitchPort] = relationship()


class WirelessAp(Base):
    """An access point, from the wireless controller (UniFi, Meraki, Cisco WLC)."""
    __tablename__ = "wireless_aps"
    __table_args__ = (UniqueConstraint("source", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32))                 # unifi | meraki | cisco
    key: Mapped[str] = mapped_column(String(64))                    # MAC or serial: the controller's id for it
    name: Mapped[str | None] = mapped_column(String(128))
    mac: Mapped[str | None] = mapped_column(String(17))             # wired (Ethernet) MAC
    radio_mac: Mapped[str | None] = mapped_column(String(17))       # base radio MAC (Cisco)
    bssids: Mapped[str | None] = mapped_column(Text)                # comma-separated, when the controller lists them
    ip: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(64))
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WifiSighting(Base):
    """A Wi-Fi client seen on an access point: one row per client MAC and AP, first..last time seen there.
    From the PC itself (source pc) or the wireless controller (source unifi / meraki / cisco)."""
    __tablename__ = "wifi_sightings"
    __table_args__ = (UniqueConstraint("mac", "ap_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)        # the client's Wi-Fi MAC
    hostname: Mapped[str | None] = mapped_column(String(64), index=True)   # when the PC reported it itself
    client_name: Mapped[str | None] = mapped_column(String(128))    # what the controller calls the client
    ip: Mapped[str | None] = mapped_column(String(64))
    ssid: Mapped[str | None] = mapped_column(String(64))
    bssid: Mapped[str | None] = mapped_column(String(17))
    ap_key: Mapped[str] = mapped_column(String(128))                # AP name, else the BSSID
    ap_name: Mapped[str | None] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class ArpEntry(Base):
    """IP-to-MAC bindings from router / L3 switch ARP tables."""
    __tablename__ = "arp_entries"
    __table_args__ = (UniqueConstraint("ip", "mac"), Index("ix_arp_mac_seen", "mac", "last_seen"))
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    mac: Mapped[str] = mapped_column(String(17), index=True)
    source: Mapped[str | None] = mapped_column(String(64))
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class PortMapRow(Base):
    """Where each MAC is plugged in now: v_port_map's rows, worked out by portmap.refresh() from the MAC tables, NICs and
    DHCP leases whenever those change. Kept as a table because computing it means ranking every MAC sighting, which is
    far too slow to redo inside every Computers-list, switch-port and dashboard query."""
    __tablename__ = "port_map"
    __table_args__ = (Index("ix_portmap_host_seen", "hostname", "last_seen"), Index("ix_portmap_port", "switch_ip", "port"))
    mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    switch_name: Mapped[str | None] = mapped_column(String(255))
    switch_ip: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[str | None] = mapped_column(String(64))
    port_alias: Mapped[str | None] = mapped_column(String(255))
    vlan: Mapped[int | None] = mapped_column(Integer)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime)
    ip: Mapped[str | None] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(64))
    matched_by: Mapped[str | None] = mapped_column(String(16))
    device_kind: Mapped[str | None] = mapped_column(String(16))
    phone: Mapped[str | None] = mapped_column(String(255))
    dhcp_ip: Mapped[str | None] = mapped_column(String(64))
    dhcp_name: Mapped[str | None] = mapped_column(String(64))


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    collector: Mapped[str] = mapped_column(String(32))
    started: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished: Mapped[datetime | None] = mapped_column(DateTime)
    ok: Mapped[bool | None] = mapped_column(Boolean)
    message: Mapped[str | None] = mapped_column(Text)
    ran_by: Mapped[str | None] = mapped_column(String(200))       # "0.12.70 on SRV01, pid 1234" (see instance.py)


class DeviceGroup(Base):
    """Free-form group/tag membership, e.g. "Finance", "Kiosks", "Replace 2027"."""
    __tablename__ = "device_groups"
    __table_args__ = (UniqueConstraint("device_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    dynamic: Mapped[bool | None] = mapped_column(Boolean, default=False)   # added by a group's rules (groups.py)


class UserGroup(Base):
    """A user's membership of a NetInventory user group (by hand, or dynamic = added by the group's rules)."""
    __tablename__ = "user_groups"
    __table_args__ = (UniqueConstraint("user_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("ad_users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    dynamic: Mapped[bool | None] = mapped_column(Boolean, default=False)


class AdGroup(Base):
    """An AD group from the last AD import: lets group conditions follow nested membership and offer a picker."""
    __tablename__ = "ad_groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    dn: Mapped[str] = mapped_column(Text, unique=True)                # lower case
    name: Mapped[str | None] = mapped_column(String(255))            # cn
    sam: Mapped[str | None] = mapped_column(String(255))             # sAMAccountName
    type: Mapped[str | None] = mapped_column(String(64))             # "Security - global"
    description: Mapped[str | None] = mapped_column(Text)
    member_of: Mapped[str | None] = mapped_column(Text)              # JSON list of parent group DNs, lower case
    seen: Mapped[datetime | None] = mapped_column(DateTime)


class GroupDef(Base):
    """A rule-based computer or user group: members are the PCs (or AD users) matching its conditions (groups.py)."""
    __tablename__ = "group_defs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str | None] = mapped_column(String(16), default="computers")   # computers | users (NULL = computers)
    description: Mapped[str | None] = mapped_column(Text)
    match: Mapped[str] = mapped_column(String(8), default="all")      # all | any
    conditions: Mapped[str] = mapped_column(Text)                     # JSON list of {field, value, not}
    member_count: Mapped[int | None] = mapped_column(Integer)
    refreshed: Mapped[datetime | None] = mapped_column(DateTime)
    who: Mapped[str | None] = mapped_column(String(128))
    updated: Mapped[datetime | None] = mapped_column(DateTime, default=utcnow)


class CustomField(Base):
    __tablename__ = "custom_fields"
    __table_args__ = (UniqueConstraint("device_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    value: Mapped[str | None] = mapped_column(Text)


class Comment(Base):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    author: Mapped[str | None] = mapped_column(String(128))
    text: Mapped[str] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ChangeEvent(Base):
    """What changed on a device between scans (software added/removed, OS build, RAM, port moves...)."""
    __tablename__ = "change_events"
    __table_args__ = (Index("ix_change_dev_time", "device_id", "time"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))  # software_added, software_removed, os, hardware, action...
    detail: Mapped[str] = mapped_column(Text)


class AdUser(Base):
    __tablename__ = "ad_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)   # sAMAccountName, lower case
    domain: Mapped[str | None] = mapped_column(String(128))
    display_name: Mapped[str | None] = mapped_column(String(255))
    first_name: Mapped[str | None] = mapped_column(String(128))
    last_name: Mapped[str | None] = mapped_column(String(128))
    initials: Mapped[str | None] = mapped_column(String(16))
    upn: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    title: Mapped[str | None] = mapped_column(String(255))
    department: Mapped[str | None] = mapped_column(String(255))
    company: Mapped[str | None] = mapped_column(String(255))
    office: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(64))
    mobile: Mapped[str | None] = mapped_column(String(64))
    manager: Mapped[str | None] = mapped_column(String(255))
    dn: Mapped[str | None] = mapped_column(Text)
    sid: Mapped[str | None] = mapped_column(String(128))
    logon_script: Mapped[str | None] = mapped_column(String(255))
    home_directory: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    locked: Mapped[bool | None] = mapped_column(Boolean)
    password_never_expires: Mapped[bool | None] = mapped_column(Boolean)
    password_last_set: Mapped[datetime | None] = mapped_column(DateTime)
    last_logon: Mapped[datetime | None] = mapped_column(DateTime)
    bad_pwd_count: Mapped[int | None] = mapped_column(Integer)
    created: Mapped[datetime | None] = mapped_column(DateTime)
    changed: Mapped[datetime | None] = mapped_column(DateTime)
    groups: Mapped[str | None] = mapped_column(Text)   # JSON list of {name, type}
    group_dns: Mapped[str | None] = mapped_column(Text)   # JSON list of memberOf DNs, lower case (direct only)
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime)


class Credential(Base):
    """Stored credentials for scanning. Secrets are encrypted at rest (see secrets.py) and never sent to the browser."""
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(16))        # windows | snmp2 | snmp3
    username: Mapped[str | None] = mapped_column(String(255))   # DOMAIN\user, or SNMPv3 user
    secret: Mapped[str | None] = mapped_column(Text)            # encrypted: password / community / v3 auth key
    secret2: Mapped[str | None] = mapped_column(Text)           # encrypted: SNMPv3 privacy key
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScanTarget(Base):
    """What to scan: an AD domain, an AD computer or user OU path, or an IP range."""
    __tablename__ = "scan_targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(24))        # ad_domain | ad_computer_path | ad_user_path | ip_range
    value: Mapped[str] = mapped_column(Text)             # domain fqdn, OU DN, or "10.0.0.0/24" / "10.0.0.1-10.0.0.50"
    server: Mapped[str | None] = mapped_column(String(255))   # optional DC to talk to
    credential_ids: Mapped[str | None] = mapped_column(String(255))  # comma list, tried in order
    collect: Mapped[str | None] = mapped_column(String(64))   # AD domain: "computers,users"; IP range: "ping,snmp,winrm"
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_min: Mapped[int] = mapped_column(Integer, default=240)
    last_run: Mapped[datetime | None] = mapped_column(DateTime)
    last_result: Mapped[str | None] = mapped_column(Text)
    last_ok: Mapped[bool | None] = mapped_column(Boolean)


class ScanJob(Base):
    """A scheduled scan: which targets, which collectors, when, and how hard (see jobs.py)."""
    __tablename__ = "scan_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    target_ids: Mapped[str | None] = mapped_column(String(512))     # comma list of scan_targets ids; empty = all targets
    collectors: Mapped[str] = mapped_column(String(128))            # comma list: ad, snmp, pcs, pcs_updates, dc_logons
    every_min: Mapped[int | None] = mapped_column(Integer)          # repeat every N minutes, or
    at_time: Mapped[str | None] = mapped_column(String(5))          # run once a day at HH:MM (server local time)
    days: Mapped[str] = mapped_column(String(7), default="0123456") # weekdays it may run, Monday = 0
    window_start: Mapped[int | None] = mapped_column(Integer)       # only start between these hours (local), e.g. 18-6
    window_end: Mapped[int | None] = mapped_column(Integer)
    max_parallel: Mapped[int | None] = mapped_column(Integer)       # PCs scanned at once over WinRM (default 16)
    ip_methods: Mapped[str | None] = mapped_column(String(64))      # IP ranges: "ping,snmp,winrm"; empty = each target's own
    group_name: Mapped[str | None] = mapped_column(String(128))     # PC scans: only the computers in this group
    cred_id: Mapped[int | None] = mapped_column(Integer)            # Windows sign-in for this job: None = each target's
                                                                    # ticked credentials, 0 = the server's own account
    last_run: Mapped[datetime | None] = mapped_column(DateTime)     # UTC
    last_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_result: Mapped[str | None] = mapped_column(Text)
    last_seconds: Mapped[int | None] = mapped_column(Integer)
    ran_by: Mapped[str | None] = mapped_column(String(200))       # which NetInventory process wrote last_result,
    ran_at: Mapped[datetime | None] = mapped_column(DateTime)      # and when (UTC); older versions set neither


class Agent(Base):
    """An enrolled NetInventory Agent (agentapi.py). The secret signs every request; it's stored encrypted."""
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(64), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))
    machine_guid: Mapped[str | None] = mapped_column(String(64))
    secret_enc: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")    # active | pending | revoked
    note: Mapped[str | None] = mapped_column(String(255))                 # why it's pending
    enrolled: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(16))
    run_as: Mapped[str | None] = mapped_column(String(64))
    last_inventory: Mapped[datetime | None] = mapped_column(DateTime)
    want_inventory: Mapped[bool] = mapped_column(Boolean, default=True)


class RcAgent(Base):
    """An enrolled remote control agent (NetInventory Remote, rcontrol.py): separate from the inventory agent, with
    its own identity and secret. The secret signs its control connection; it's stored encrypted."""
    __tablename__ = "rc_agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(64), index=True)
    fqdn: Mapped[str | None] = mapped_column(String(255))
    machine_guid: Mapped[str | None] = mapped_column(String(64))
    secret_enc: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")    # active | pending | revoked
    note: Mapped[str | None] = mapped_column(String(255))
    enrolled: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(32))
    console_user: Mapped[str | None] = mapped_column(String(128))
    always_ask: Mapped[bool | None] = mapped_column(Boolean)                  # the PC's own policy forces the question
    disabled: Mapped[bool | None] = mapped_column(Boolean)                    # the PC's own policy turns sessions off


class RcSession(Base):
    """One remote control session (or attempt): who, which PC, how it was allowed, and how it ended."""
    __tablename__ = "rc_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    sid: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(64), index=True)
    tech: Mapped[str] = mapped_column(String(128))
    tech_ip: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str | None] = mapped_column(String(255))
    direct: Mapped[bool] = mapped_column(Boolean, default=False)            # allowed to connect without asking
    view_only: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(16), default="asking")      # asking | connecting | connected | denied | failed | ended
    consent: Mapped[str | None] = mapped_column(String(32))                 # accepted | direct | denied | timeout | nouser-allowed ...
    pc_user: Mapped[str | None] = mapped_column(String(128))
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started: Mapped[datetime | None] = mapped_column(DateTime)
    ended: Mapped[datetime | None] = mapped_column(DateTime)
    end_reason: Mapped[str | None] = mapped_column(String(255))
    bytes_sent: Mapped[int | None] = mapped_column(Integer)


class Deployment(Base):
    """One push to one PC (app update, Windows updates, service start, reboot): the queue and the log (fixes.py).
    status: queued (waiting for its turn, or for the PC to come online) | sending | running | success | failed |
    expired (the PC stayed offline past the deadline) | cancelled"""
    __tablename__ = "deployments"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str | None] = mapped_column(String(255))          # winget package id, service, reboot timing
    label: Mapped[str] = mapped_column(String(255))
    who: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    message: Mapped[str | None] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started: Mapped[datetime | None] = mapped_column(DateTime)
    finished: Mapped[datetime | None] = mapped_column(DateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_try: Mapped[datetime | None] = mapped_column(DateTime)
    expires: Mapped[datetime | None] = mapped_column(DateTime)
    task: Mapped[str | None] = mapped_column(String(128))            # scheduled task name on the PC while running
    check_until: Mapped[datetime | None] = mapped_column(DateTime)
    payload: Mapped[str | None] = mapped_column(Text)               # a script: the exact text that was approved and runs
    cred_id: Mapped[int | None] = mapped_column(Integer)            # sign in with: None = the scan targets' credentials,
                                                                    # 0 = this server's own Windows account, else a credential
    run_mode: Mapped[str | None] = mapped_column(String(16))        # scripts: who it runs as on the PC (fixes.RUN_MODES);
                                                                    # None = SYSTEM (pushes queued before 0.26)


class Script(Base):
    """A saved PowerShell or command prompt script that can be run on one PC or many (fixes.py, action "script")."""
    __tablename__ = "scripts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    language: Mapped[str] = mapped_column(String(16), default="powershell")      # powershell | cmd
    body: Mapped[str] = mapped_column(Text)
    timeout_min: Mapped[int] = mapped_column(Integer, default=30)
    run_mode: Mapped[str | None] = mapped_column(String(16))        # select (ask when deploying, also None) | user |
                                                                    # account (the signing-in account) | system
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    who: Mapped[str | None] = mapped_column(String(64))


class ScanExclusion(Base):
    """Something every scan skips (IP, host name, AD OU, MAC), or a Windows event that isn't stored."""
    __tablename__ = "scan_exclusions"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))        # event | ip | host | ou | mac
    value: Mapped[str] = mapped_column(String(512))
    note: Mapped[str | None] = mapped_column(String(255))
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(64))


class ServerInstance(Base):
    """Every running NetInventory server process, with a heartbeat (see instance.py). Shows in Settings, so a
    second or leftover process (an old version still running against the same database) can't hide."""
    __tablename__ = "server_instances"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    version: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(128))
    pid: Mapped[int] = mapped_column(Integer)
    code_path: Mapped[str | None] = mapped_column(String(512))
    started: Mapped[datetime] = mapped_column(DateTime)            # UTC
    last_seen: Mapped[datetime] = mapped_column(DateTime, index=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)


class AuditLog(Base):
    """Sign-ins and sign-outs, and every change made from the UI (settings, groups, credentials, AD changes, deployments...)."""
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255))
    result: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(64))             # address the request came from (filled in by logs.py)


class ServerLog(Base):
    """The server's own log (scans, collectors, DC errors...), kept in the database for the Logs page. See logs.py."""
    __tablename__ = "server_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    level: Mapped[str] = mapped_column(String(16), index=True)
    logger: Mapped[str | None] = mapped_column(String(128))
    message: Mapped[str | None] = mapped_column(Text)


def get_setting(db, key: str, default: str | None = None) -> str | None:
    row = db.get(Setting, key)
    return row.value if row and row.value is not None else default


def set_setting(db, key: str, value: str | None) -> None:
    row = db.get(Setting, key) or Setting(key=key)
    row.value = value
    db.add(row)


class SavedReport(Base):
    """A report built in the report builder: dataset + fields + filters, saved by name.
    owner = who saved it; only they see it unless shared. Reports from before 0.44 have no owner and are shared."""
    __tablename__ = "saved_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    spec: Mapped[str] = mapped_column(Text)  # JSON {dataset, fields, filters, sort, desc}
    owner: Mapped[str | None] = mapped_column(String(128), index=True)
    shared: Mapped[bool | None] = mapped_column(Boolean)
    created: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


_engine = None
SessionLocal = sessionmaker(expire_on_commit=False)


def init_db(url: str) -> None:
    global _engine
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
    else:
        # A small pool: the server runs in one process, and every idle Postgres connection costs memory on both sides.
        kwargs = {"pool_size": 5, "max_overflow": 10, "pool_recycle": 1800, "pool_pre_ping": True}
    _engine = create_engine(url, **kwargs)
    SessionLocal.configure(bind=_engine)
    Base.metadata.create_all(_engine)
    _add_missing_columns()
    _add_missing_indexes()


def _add_missing_columns() -> None:
    """Light auto-migration for upgrades: add columns that newer versions introduced."""
    from sqlalchemy import inspect as sa_inspect, text
    insp = sa_inspect(_engine)
    with _engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in existing:
                    ddl = col.type.compile(dialect=_engine.dialect)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {ddl}'))


def _add_missing_indexes() -> None:
    """create_all() only makes indexes for new tables: add the ones newer versions declared on existing tables.
    The first start after an upgrade builds them (a few seconds on a large logon table)."""
    import logging
    from sqlalchemy import inspect as sa_inspect
    insp = sa_inspect(_engine)
    for table in Base.metadata.sorted_tables:
        have = {i["name"] for i in insp.get_indexes(table.name)}
        for idx in table.indexes:
            if idx.name not in have:
                logging.getLogger(__name__).info("adding index %s on %s", idx.name, table.name)
                idx.create(_engine, checkfirst=True)
