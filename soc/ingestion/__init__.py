from soc.ingestion.base import BaseIngestionAdapter
from soc.ingestion.wazuh_adapter import WazuhAdapter
from soc.ingestion.suricata_adapter import SuricataAdapter
from soc.ingestion.sysmon_adapter import SysmonAdapter
from soc.ingestion.linux_adapter import LinuxAuthAdapter
from soc.ingestion.synthetic_replay import (
    generate_ssh_bruteforce_scenario,
    generate_password_spray_scenario,
    generate_auth_fail_then_success_scenario,
    generate_port_scan_scenario,
    generate_suspicious_dns_scenario,
    generate_lolbin_execution_scenario,
    generate_unusual_c2_beacon_scenario,
    generate_benign_traffic_scenario,
)

__all__ = [
    "BaseIngestionAdapter",
    "WazuhAdapter",
    "SuricataAdapter",
    "SysmonAdapter",
    "LinuxAuthAdapter",
    "generate_ssh_bruteforce_scenario",
    "generate_password_spray_scenario",
    "generate_auth_fail_then_success_scenario",
    "generate_port_scan_scenario",
    "generate_suspicious_dns_scenario",
    "generate_lolbin_execution_scenario",
    "generate_unusual_c2_beacon_scenario",
    "generate_benign_traffic_scenario",
]
