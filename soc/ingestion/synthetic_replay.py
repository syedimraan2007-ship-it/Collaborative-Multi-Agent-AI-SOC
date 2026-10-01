"""
Synthetic Telemetry Replay and Scenario Generator.
Produces deterministic, reproducible event streams for offline testing, benchmarks, and live SOC demos.
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict
from uuid import uuid4

from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


def generate_ssh_bruteforce_scenario(
    attacker_ip: str = "198.51.100.45",
    victim_ip: str = "10.0.1.50",
    victim_host: str = "srv-app-prod01",
    fail_count: int = 7,
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    events: List[CanonicalSecurityEvent] = []

    for i in range(fail_count):
        ev_time = base_time + timedelta(seconds=i * 8)
        events.append(
            CanonicalSecurityEvent(
                source_type="wazuh",
                source_product="wazuh-agent",
                event_timestamp=ev_time,
                hostname=victim_host,
                source_ip=attacker_ip,
                destination_ip=victim_ip,
                source_port=40000 + i,
                destination_port=22,
                protocol="tcp",
                username="root",
                event_category=EventCategory.AUTHENTICATION,
                event_action="login_attempt",
                event_outcome=EventOutcome.FAILURE,
                severity=3,
                tags=["ssh", "auth_failed", "bruteforce"],
                metadata={"reason": "Permission denied (publickey,password)"},
            )
        )
    return events


def generate_password_spray_scenario(
    attacker_ip: str = "203.0.113.88",
    victim_ip: str = "10.0.1.10",
    victim_host: str = "dc01.corp.internal",
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=4)
    users = ["admin", "jsmith", "bwayne", "sconnor", "tstark", "pparker"]
    events: List[CanonicalSecurityEvent] = []

    for i, user in enumerate(users):
        ev_time = base_time + timedelta(seconds=i * 15)
        events.append(
            CanonicalSecurityEvent(
                source_type="sysmon",
                source_product="microsoft-sysmon",
                event_timestamp=ev_time,
                hostname=victim_host,
                source_ip=attacker_ip,
                destination_ip=victim_ip,
                destination_port=445,
                protocol="smb",
                username=user,
                event_category=EventCategory.AUTHENTICATION,
                event_action="login_attempt",
                event_outcome=EventOutcome.FAILURE,
                severity=3,
                tags=["kerberos", "smb", "spray"],
            )
        )
    return events


def generate_auth_fail_then_success_scenario(
    attacker_ip: str = "185.220.101.5",
    victim_ip: str = "10.0.1.20",
    victim_host: str = "finance-db01",
    target_user: str = "db_admin",
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=6)
    events: List[CanonicalSecurityEvent] = []

    # 4 failed attempts
    for i in range(4):
        ev_time = base_time + timedelta(seconds=i * 12)
        events.append(
            CanonicalSecurityEvent(
                source_type="linux",
                source_product="sshd",
                event_timestamp=ev_time,
                hostname=victim_host,
                source_ip=attacker_ip,
                destination_ip=victim_ip,
                destination_port=22,
                protocol="tcp",
                username=target_user,
                event_category=EventCategory.AUTHENTICATION,
                event_action="login_attempt",
                event_outcome=EventOutcome.FAILURE,
                severity=3,
                tags=["ssh", "auth_failure"],
            )
        )

    # 1 success immediately after
    success_time = base_time + timedelta(seconds=65)
    events.append(
        CanonicalSecurityEvent(
            source_type="linux",
            source_product="sshd",
            event_timestamp=success_time,
            hostname=victim_host,
            source_ip=attacker_ip,
            destination_ip=victim_ip,
            destination_port=22,
            protocol="tcp",
            username=target_user,
            event_category=EventCategory.AUTHENTICATION,
            event_action="login_success",
            event_outcome=EventOutcome.SUCCESS,
            severity=4,
            tags=["ssh", "compromise", "credential_access"],
        )
    )
    return events


def generate_port_scan_scenario(
    attacker_ip: str = "192.0.2.140",
    victim_ip: str = "10.0.1.15",
    victim_host: str = "dmz-gateway",
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=3)
    scanned_ports = [21, 22, 23, 25, 80, 443, 8080, 8443]
    events: List[CanonicalSecurityEvent] = []

    for i, port in enumerate(scanned_ports):
        ev_time = base_time + timedelta(seconds=i * 2)
        events.append(
            CanonicalSecurityEvent(
                source_type="suricata",
                source_product="suricata-ids",
                event_timestamp=ev_time,
                hostname=victim_host,
                source_ip=attacker_ip,
                destination_ip=victim_ip,
                source_port=50000 + i,
                destination_port=port,
                protocol="tcp",
                event_category=EventCategory.NETWORK,
                event_action="connection_attempt",
                event_outcome=EventOutcome.FAILURE,
                severity=2,
                tags=["port_scan", "reconnaissance"],
            )
        )
    return events


def generate_suspicious_dns_scenario(
    host_ip: str = "10.0.1.105",
    hostname: str = "workstation-hr04",
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)
    # High entropy DGA domain
    dga_domain = "x9z3kq0m7v2w8p1b4r5y6c.tunnel.blackhole-c2.top"
    return [
        CanonicalSecurityEvent(
            source_type="suricata",
            source_product="suricata-ids",
            event_timestamp=base_time,
            hostname=hostname,
            source_ip=host_ip,
            destination_ip="8.8.8.8",
            destination_port=53,
            protocol="udp",
            domain=dga_domain,
            query_type="A",
            event_category=EventCategory.DNS,
            event_action="dns_query",
            event_outcome=EventOutcome.SUCCESS,
            severity=4,
            tags=["dga", "dns_tunneling", "c2"],
        )
    ]


def generate_lolbin_execution_scenario(
    hostname: str = "finance-laptop02",
    username: str = "jdoe",
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=1)
    return [
        CanonicalSecurityEvent(
            source_type="sysmon",
            source_product="microsoft-sysmon",
            event_timestamp=base_time,
            hostname=hostname,
            username=username,
            process_name="powershell.exe",
            process_id=4812,
            parent_process_id=2040,
            process_command_line="powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
            process_hash="SHA256=2A980B22F9E870428800188941BC380295DA7812108D8E9D5082E47BE5074213",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            event_outcome=EventOutcome.SUCCESS,
            severity=5,
            tags=["lolbin", "powershell_encoded", "execution"],
        )
    ]


def generate_unusual_c2_beacon_scenario(
    internal_ip: str = "10.0.1.77",
    c2_ip: str = "198.51.100.99",
    c2_port: int = 4444,
) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=2)
    events: List[CanonicalSecurityEvent] = []

    for i in range(4):
        ev_time = base_time + timedelta(seconds=i * 20)
        events.append(
            CanonicalSecurityEvent(
                source_type="suricata",
                source_product="suricata-ids",
                event_timestamp=ev_time,
                hostname="srv-backup-01",
                source_ip=internal_ip,
                destination_ip=c2_ip,
                source_port=49152 + i,
                destination_port=c2_port,
                protocol="tcp",
                event_category=EventCategory.NETWORK,
                event_action="connection_attempt",
                event_outcome=EventOutcome.SUCCESS,
                severity=4,
                tags=["c2", "beaconing", "reverse_shell"],
            )
        )
    return events


def generate_benign_traffic_scenario(count: int = 15) -> List[CanonicalSecurityEvent]:
    base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    events: List[CanonicalSecurityEvent] = []

    for i in range(count):
        ev_time = base_time + timedelta(seconds=i * 15)
        events.append(
            CanonicalSecurityEvent(
                source_type="wazuh",
                source_product="wazuh-agent",
                event_timestamp=ev_time,
                hostname="desktop-staff-12",
                source_ip=f"10.0.2.{10 + (i % 5)}",
                destination_ip="142.250.190.46",  # google.com
                source_port=52000 + i,
                destination_port=443,
                protocol="tcp",
                username="alice",
                event_category=EventCategory.NETWORK,
                event_action="http_traffic",
                event_outcome=EventOutcome.SUCCESS,
                severity=1,
                tags=["benign", "web_browsing"],
            )
        )
    return events
