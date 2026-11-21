"""Driver registry: one entry per supported ``switches.device_type``.

Adding a driver = a new module with a ``SwitchDriver`` subclass plus one entry here.
"""

from .aruba_aoscx import ArubaAosCxDriver
from .aruba_aoss import ArubaAossDriver
from .base import SwitchDriver
from .cisco.driver import CiscoDriver
from .mikrotik import MikrotikDriver
from .netgear import NetgearDriver

DRIVERS: dict[str, SwitchDriver] = {
    driver.id: driver
    for driver in (
        CiscoDriver("cisco_ios", "Cisco IOS"),
        CiscoDriver("cisco_xe", "Cisco IOS-XE"),
        MikrotikDriver(),
        ArubaAosCxDriver(),
        ArubaAossDriver(),
        NetgearDriver(),
    )
}


def get_driver(device_type: str | None) -> SwitchDriver | None:
    return DRIVERS.get(device_type or "")


def list_drivers() -> list[SwitchDriver]:
    """Drivers in display order (vendor, then label)."""
    return sorted(DRIVERS.values(), key=lambda driver: (driver.vendor.casefold(), driver.label.casefold()))
