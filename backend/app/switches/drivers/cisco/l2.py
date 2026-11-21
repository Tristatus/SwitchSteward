"""Cisco EtherChannel and spanning tree parsers/command builders."""

import re

from ....i18n import t
from ...errors import InvalidInputError
from ...validation import parse_vlan_list, vlan_ranges
from . import parsers

UNSUPPORTED_VALUE = "Diese Einstellung wird vom Switch nicht unterstützt: {value}"
LAG_MODE_UNKNOWN = "Der Modus von LAG {lag} konnte nicht gelesen werden."
CHANNEL_CONFIG_PROBE = "show running-config | include ^interface|channel-group"

LAG_MODES = {"static": "on", "lacp_active": "active", "lacp_passive": "passive"}
_CHANNEL_MODES = {value: key for key, value in LAG_MODES.items()}
_MEMBER_STATES = {"P": "bundled", "D": "down", "H": "standby", "s": "suspended"}
STP_MODES = {"pvst": "pvst", "rapid_pvst": "rapid-pvst", "mstp": "mst"}
_DEVICE_STP_MODES = {"pvst": "pvst", "rapid-pvst": "rapid_pvst", "mst": "mstp"}
_ROLES = {"root": "root", "desg": "designated", "altn": "alternate", "back": "backup", "mstr": "master",
          "disb": "disabled"}
_STATES = {"fwd": "forwarding", "blk": "blocking", "lrn": "learning", "lis": "listening", "dis": "disabled"}


# --- EtherChannel -----------------------------------------------------------------------


def parse_channel_config(output: str) -> dict[str, tuple[int, str]]:
    """``channel-group`` lines per interface key: (group, Cisco mode keyword)."""
    result = {}
    current = None
    for line in (output or "").splitlines():
        match = re.match(r"^interface\s+(\S+)", line)
        if match:
            current = parsers.interface_key(match.group(1))
            continue
        match = re.match(r"^\s+channel-group\s+(\d+)\s+mode\s+(\S+)", line)
        if match and current:
            result[current] = (int(match.group(1)), match.group(2))
    return result


def parse_etherchannel_summary(output: str, channel_config: dict[str, tuple[int, str]]) -> list[dict]:
    """``show etherchannel summary`` rows (continuation lines carry further members)."""
    lags: list[dict] = []
    current = None
    started = False
    for line in (output or "").splitlines():
        if re.match(r"^-{4,}\+", line):
            started = True
            continue
        if not started or not line.strip():
            continue
        row = re.match(r"^(\d+)\s+(Po\d+)\(([A-Za-z]+)\)\s+(\S+)(.*)$", line)
        if row:
            flags, protocol = row.group(3), row.group(4)
            lag_id = int(row.group(1))
            current = {
                "id": lag_id,
                "interface": f"Port-channel{lag_id}",
                "mode": "static" if protocol == "-" else None,
                "members": [],
                "status": "up" if "U" in flags else "down",
                "_protocol": protocol,
            }
            lags.append(current)
            rest = row.group(5)
        elif current is not None and line[:1].isspace():
            rest = line
        else:
            current = None
            continue
        for name, flag in re.findall(r"(\S+?)\(([A-Za-z]+)\)", rest):
            current["members"].append({"interface": name, "state": _MEMBER_STATES.get(flag)})
    for lag in lags:
        protocol = lag.pop("_protocol")
        if protocol.upper() == "LACP":
            modes = {
                channel_config.get(parsers.interface_key(member["interface"]), (None, None))[1]
                for member in lag["members"]
            }
            mode = modes.pop() if len(modes) == 1 else None
            lag["mode"] = _CHANNEL_MODES.get(mode) if mode in ("active", "passive") else None
    return lags


def lag_mode_keyword(mode: str) -> str:
    try:
        return LAG_MODES[mode]
    except KeyError:
        raise InvalidInputError(t(UNSUPPORTED_VALUE, value=mode)) from None


def switchport_lines(running_interface: str) -> list[str]:
    """``switchport`` lines of a ``show running-config interface`` section (VLAN config of the LAG)."""
    return [line.strip() for line in (running_interface or "").splitlines() if line.startswith(" switchport")]


# --- Spanning tree ----------------------------------------------------------------------


def parse_mode(summary: str) -> str | None:
    match = re.search(r"Switch is in (\S+) mode", summary or "")
    return _DEVICE_STP_MODES.get(match.group(1).lower()) if match else None


def _instance_number(name: str) -> int:
    return int(re.sub(r"^\D+", "", name))


def parse_bridge(output: str) -> list[dict]:
    """``show spanning-tree bridge``: configured bridge priority per VLAN or MST instance."""
    result = []
    for match in re.finditer(r"^(VLAN|MST)(\d+)\s+\d+\s+\(\s*(\d+),", output or "", re.MULTILINE):
        key = "vlan" if match.group(1) == "VLAN" else "instance"
        result.append({key: int(match.group(2)), "priority": int(match.group(3))})
    return result


def parse_root(output: str) -> list[dict]:
    """``show spanning-tree root``; an empty root port with cost 0 means this switch is the root."""
    roots = []
    for match in re.finditer(
        r"^(?:VLAN|MST)(\d+)\s+(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\d+)"
        r"\s+\d+\s+\d+\s+\d+[ \t]*(\S+)?[ \t]*$",
        output or "", re.MULTILINE,
    ):
        cost = int(match.group(4))
        port = match.group(5)
        roots.append({
            "vlan_or_instance": int(match.group(1)),
            "root_bridge": f"{match.group(2)} {match.group(3).lower()}",
            "root_port": port,
            "root_cost": cost,
            "is_root": port is None and cost == 0,
        })
    return roots


def parse_mst_configuration(output: str) -> dict | None:
    name = re.search(r"^Name\s+\[(.*)\]\s*$", output or "", re.MULTILINE)
    if name is None:
        return None
    revision = re.search(r"^Revision\s+(\d+)", output, re.MULTILINE)
    instances = []
    in_table = False
    for line in output.splitlines():
        if re.match(r"^Instance\s+Vlans mapped", line):
            in_table = True
            continue
        match = re.match(r"^(\d+)\s+(\S+)\s*$", line) if in_table else None
        if match and int(match.group(1)) != 0:
            instances.append({"id": int(match.group(1)), "vlans": match.group(2)})
    return {"name": name.group(1), "revision": int(revision.group(1)) if revision else 0, "instances": instances}


def parse_ports(output: str) -> list[dict]:
    """Interface tables of ``show spanning-tree`` (one block per VLAN or MST instance)."""
    ports = []
    current = None
    for line in (output or "").splitlines():
        header = re.match(r"^(?:VLAN|MST)(\d+)\s*$", line)
        if header:
            current = int(header.group(1))
            continue
        match = re.match(r"^(\S+)\s+(Root|Desg|Altn|Back|Mstr|Disb)\s+(\S+)\s+(\d+)\s+(\d+)\.\d+", line)
        if match and current is not None:
            state = match.group(3).lower()
            ports.append({
                "interface": match.group(1),
                "instance_or_vlan": current,
                "cost": int(match.group(4)),
                "priority": int(match.group(5)),
                "role": _ROLES[match.group(2).lower()],
                "state": _STATES.get(state, "broken" if state.startswith("bkn") else state),
            })
    return ports


def mst_mapping(instances: list[dict]) -> dict[int, frozenset[int]]:
    result = {}
    for instance in instances:
        selection = parse_vlan_list(instance["vlans"])
        result[instance["id"]] = frozenset(selection) if isinstance(selection, tuple) else frozenset()
    return result


def vlan_text(vlans) -> str:
    return ",".join(vlan_ranges(tuple(sorted(vlans))))
