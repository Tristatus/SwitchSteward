"""Cisco PoE: per-port state, configured limits, switch-wide budgets and per-port power profiles.

Budget: ``Available`` is the complete allocatable budget, not the remaining
budget; ``Used`` includes reservations and is not a real-time power reading.
Port limits and powered-device classes cannot establish switch capabilities.
"""

import re
from decimal import Decimal

from ....i18n import t
from ... import transport
from ...errors import InvalidInputError, SwitchConnectionError, append_warning
from ...validation import validate_choice
from ..base import empty_poe_detail
from .models import CATALOG
from .parsers import (
    OUTPUT_INTERFACE_RE,
    ensure_show_output,
    interface_key,
    raise_on_ios_authorization_error,
    unsupported_command_errors,
)

POE_STANDARD_WATTS = {
    "default": 0,
    "802.3af": 15.4,
    "802.3at": 30,
    "802.3bt-type3": 60,
    "802.3bt-type4": 90,
    "cisco-upoe": 60,
}
# Display names of the catalog standard IDs (device summary ``standards``).
STANDARD_LABELS = {
    "802.3af": "IEEE 802.3af (PoE)",
    "802.3at": "IEEE 802.3at (PoE+)",
    "802.3bt-type3": "IEEE 802.3bt Typ 3 (PoE++)",
    "802.3bt-type4": "IEEE 802.3bt Typ 4 (PoE++)",
    "cisco-upoe": "Cisco UPOE",
}
_BUDGET_FIELDS = ("max_watts", "used_watts", "remaining_watts")


# --- Port state and configuration ---------------------------------------------------


def parse_power_inline(output: str) -> dict[str, dict]:
    """Parse IOS/IOS XE budget rows, including repeated stack-member tables.

    Power is the supplied/allocated budget reported by IOS (static allocation
    may remain nonzero with no attached device), not a real-time measurement.
    Cisco command reference and table examples:
    https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960l/software/15-2_7_e/command_reference/b_1527_2960l_cr/interface_and_hardware_commands.html
    """
    ensure_show_output(output, "show power inline")
    ports = {}
    found_header = False
    in_table = False
    for line in output.splitlines():
        if re.fullmatch(r"\s*Interface\s+Admin\s+Oper\s+Power\s+Device\s+Class\s+Max\s*", line, re.I):
            found_header = in_table = True
            continue
        if re.match(r"\s*Interface\s+", line, re.I):
            # Per-port output can append an AdminPowerMax/AdminConsumption table.
            in_table = False
        parts = line.split()
        if not in_table or not parts or not OUTPUT_INTERFACE_RE.fullmatch(parts[0]):
            continue
        if len(parts) < 7:
            raise SwitchConnectionError(t("Die PoE-Tabelle enthaelt eine unvollstaendige Portzeile."))
        port, admin, status, used = parts[:4]
        maximum = parts[-1]
        admin = admin.casefold()
        if admin not in {"auto", "static", "off", "never", "n/a", "--"}:
            raise SwitchConnectionError(t("Die PoE-Tabelle enthaelt einen unbekannten Administrationsmodus."))
        values = []
        for value in (used, maximum):
            if value.casefold() in {"n/a", "--", "-"}:
                values.append(None)
            elif re.fullmatch(r"\d{1,6}(?:\.\d{1,3})?", value):
                values.append(float(value))
            else:
                raise SwitchConnectionError(t("Die PoE-Tabelle enthaelt einen unlesbaren Leistungswert."))
        key = interface_key(port)
        if key in ports:
            raise SwitchConnectionError(t("Die PoE-Tabelle enthaelt einen Port mehrfach."))
        supported = admin not in {"n/a", "--"}
        ports[key] = {
            "poe_supported": supported,
            "poe_mode": ("never" if admin == "off" else admin) if supported else None,
            "poe_status": status.casefold() if supported else None,
            "poe_used_watts": values[0] if supported else None,
            "poe_max_watts": values[1] if supported else None,
        }
    if not found_header:
        raise SwitchConnectionError(t("Die Ausgabe von 'show power inline' hat ein unbekanntes Tabellenformat."))
    return ports


def read_optional_poe(session: transport.SshSession) -> dict[str, dict] | None:
    """Keep interface data available when a switch cannot report PoE; ``None`` = unknown."""
    command = "show power inline"
    try:
        output = transport.send_show(session.conn, command)
    except transport.SSH_TIMEOUT_ERRORS:
        session.broken = True
        append_warning(session.warnings, t("Die PoE-Abfrage lief in ein Zeitlimit; PoE-Werte bleiben unbekannt."))
        return None
    raise_on_ios_authorization_error(output, command)
    if unsupported_command_errors(output):
        append_warning(session.warnings, t("Die Firmware unterstuetzt die PoE-Abfrage nicht."))
        return None
    try:
        # A port absent from a complete, recognized table does not provide PoE.
        return parse_power_inline(output)
    except SwitchConnectionError:
        append_warning(session.warnings, t("Die PoE-Werte konnten nicht sicher gelesen werden."))
        return None


def port_poe_detail(ports: dict[str, dict] | None, interface: str) -> dict:
    return (ports or {}).get(interface_key(interface), empty_poe_detail(None if ports is None else False))


def configured_poe_limit(running_output: str, interface: str) -> float | None:
    command = f"show running-config interface {interface}"
    ensure_show_output(running_output, command)
    names = re.findall(r"^[ \t]*interface[ \t]+(\S+)[ \t]*\r?$", running_output, re.MULTILINE)
    if len(names) != 1 or interface_key(names[0]) != interface_key(interface):
        raise SwitchConnectionError(
            t("Die laufende Konfiguration passt nicht zum angefragten Interface {interface}.", interface=interface)
        )
    mode_lines = re.findall(
        r"^[ \t]*(power inline (?:auto|static|never)\b[^\r\n]*)", running_output, re.MULTILINE,
    )
    if not mode_lines:
        return None
    match = re.fullmatch(r"power inline (?:(?:auto|static)(?: max (\d{1,6}))?|never)\s*", mode_lines[0])
    if len(mode_lines) != 1 or match is None:
        raise SwitchConnectionError(t("Die konfigurierte PoE-Leistungsgrenze konnte nicht sicher gelesen werden."))
    return int(match.group(1)) / 1000 if match.group(1) else None


def poe_milliwatts(watts: float) -> int:
    """Convert a safe IOS limit, also allowing an unchanged pre-existing limit."""
    if isinstance(watts, bool) or not isinstance(watts, (int, float)):
        raise InvalidInputError(t("Das PoE-Limit muss als Zahl in Watt angegeben werden."))
    value = Decimal(str(watts))
    if not value.is_finite() or (value != 0 and not Decimal(4) <= value <= Decimal(90)):
        raise InvalidInputError(t("Das PoE-Limit muss 0 (Geraetestandard) oder 4 bis 90 Watt betragen."))
    milliwatts = value * 1000
    if milliwatts != milliwatts.to_integral_value():
        raise InvalidInputError(t("Das PoE-Limit darf hoechstens drei Nachkommastellen haben."))
    return int(milliwatts)


def validate_poe_settings(mode: str | None, standard: str | None) -> int | None:
    """Validate the selected power profile before opening SSH; hardware is checked fresh."""
    if mode is not None:
        if not isinstance(mode, str):
            raise InvalidInputError(t("Ungueltiger PoE-Modus."))
        validate_choice(mode, {"auto", "static", "never"}, "PoE-Modus")
    if standard is None:
        return None
    if not isinstance(standard, str) or standard not in POE_STANDARD_WATTS:
        raise InvalidInputError(t("Unbekannter PoE-Standard."))
    if mode not in {"auto", "static"}:
        raise InvalidInputError(t("Ein PoE-Standard erfordert den PoE-Modus auto oder static."))
    return poe_milliwatts(POE_STANDARD_WATTS[standard])


# --- Hardware models ---------------------------------------------------------------


def standards_of(model: str | None) -> tuple[str, ...] | None:
    """Catalog PoE standard IDs of a hardware PID; ``None`` = not documented."""
    profile = CATALOG.match(model)
    return profile.poe_standards if profile is not None else None


def stack_members(version_output: str) -> tuple[bool, dict[str, str | None]]:
    """Stack inventory of ``show version`` (member -> PID; conflicting rows stay unknown).

    Includes the selected member's '*' marker. Returns whether the table exists.
    """
    members: dict[str, str | None] = {}
    in_table = False
    found_table = False
    for line in version_output.splitlines():
        if re.match(r"^\s*Switch\s+Ports\s+Model\b", line, re.IGNORECASE):
            in_table = found_table = True
            continue
        if not in_table:
            continue
        match = re.match(r"^\s*\*?\s*(\d+)\s+\d+\s+(\S+)", line)
        if match:
            member, model = str(int(match[1])), match[2].upper()
            members[member] = None if member in members and members[member] != model else model
        elif line.strip() and not re.fullmatch(r"[-*\s]+", line):
            in_table = False
    return found_table, members


def hardware_models(version_output: str, model: str | None) -> list[str]:
    models = [model.upper()] if model else []
    models.extend(re.findall(r"^\s*Model (?:number|name)\s*:\s*(\S+)", version_output, re.MULTILINE | re.IGNORECASE))
    models.extend(re.findall(r"^\s*cisco\s+((?:WS-)?C\d[^\s(]*)\s*\(", version_output, re.MULTILINE | re.IGNORECASE))
    models.extend(value for value in stack_members(version_output)[1].values() if value)
    return list(dict.fromkeys(value.upper() for value in models))


# --- Switch-wide budget --------------------------------------------------------------


def _empty_budget() -> dict:
    return dict.fromkeys(_BUDGET_FIELDS)


def _budget(tokens: list[str], warnings: list[str]) -> dict:
    if len(tokens) > 3:
        warnings.append(t("PoE-Budget enthält ein unbekanntes Tabellenformat."))
        return _empty_budget()
    values = []
    for token in (tokens + [""] * 3)[:3]:
        if not re.fullmatch(r"\d+(?:\.\d+)?", token):
            values.append(None)
        else:
            number = Decimal(token)
            # Prevent arbitrarily long CLI values from becoming infinity in JSON.
            values.append(float(number) if number <= Decimal("1e12") else None)
    if any(value is None for value in values):
        warnings.append(t("PoE-Budget enthält fehlende oder ungültige Werte."))
    elif abs(values[0] - values[1] - values[2]) > 0.21:
        warnings.append(t("PoE-Budget ist widersprüchlich; die Leistungswerte bleiben unbekannt."))
        values = [None] * 3
    return dict(zip(_BUDGET_FIELDS, values, strict=True))


def _merge_record(records: dict, key: str, record: dict, warnings: list[str]) -> None:
    if key not in records:
        records[key] = record
    elif records[key] != record:
        records[key] = _empty_budget()
        warnings.append(t("Widersprüchliche wiederholte PoE-Budgetangaben bleiben unbekannt."))


def _read_budgets(output: str | None, warnings: list[str]) -> tuple[dict, list[dict], bool]:
    # Reference: Cisco 2960-X command reference, show power inline. Table rows
    # n/a n/a n/a identify modules without PoE and do not reduce a stack budget.
    # https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_7_e/command_reference/b_1527_2960x_cr/interface_and_hardware_commands.html
    if not output or re.search(r"^\s*%", output, re.MULTILINE):
        warnings.append(t("PoE-Budget konnte nicht ausgelesen werden."))
        return _empty_budget(), [], False
    aggregate = {}
    modules = {}
    without_poe = set()
    in_table = False
    has_module_column = True
    for line in output.splitlines():
        line = line.strip()
        labels = re.findall(r"\b(Available|Used|Remaining)\s*:\s*([^\s(]+)", line, re.IGNORECASE)
        if labels:
            tokens = {label.lower(): value for label, value in labels}
            record = _budget([tokens.get(label, "") for label in ("available", "used", "remaining")], warnings)
            _merge_record(aggregate, "total", record, warnings)
            in_table = False
            continue
        header = re.sub(r"\([^)]*\)", "", line)
        if re.fullmatch(r"(?:(?:Module|Switch)\s+)?Available\s+Used\s+Remaining", header, re.IGNORECASE):
            in_table = True
            has_module_column = bool(re.match(r"(?:Module|Switch)\b", header, re.IGNORECASE))
            continue
        if not in_table or not line or re.fullmatch(r"[-=\s]+", line) or re.fullmatch(
            r"(?:\(\s*[Ww]atts\s*\)\s*)+", line
        ):
            continue
        columns = line.split()
        if not has_module_column:
            _merge_record(aggregate, "total", _budget(columns, warnings), warnings)
            in_table = False
            continue
        if re.fullmatch(r"\d+(?:/\d+)?|Total", columns[0], re.IGNORECASE):
            identifier = columns[0].lower()
            tokens = columns[1:]
            no_poe = len(tokens) == 3 and all(token.lower() == "n/a" for token in tokens)
            record = _empty_budget() if no_poe else _budget(tokens, warnings)
            if identifier == "total":
                _merge_record(aggregate, "total", record, warnings)
            else:
                if no_poe and identifier not in modules:
                    without_poe.add(identifier)
                elif not no_poe:
                    without_poe.discard(identifier)
                _merge_record(modules, identifier, record, warnings)
            continue
        in_table = False

    module_list = [{"module": key, **budget} for key, budget in modules.items()]
    if aggregate:
        return aggregate["total"], module_list, True
    powered_modules = [budget for key, budget in modules.items() if key not in without_poe]
    if powered_modules:
        budget = {
            field: round(sum(module[field] for module in powered_modules), 3)
            if all(module[field] is not None for module in powered_modules) else None
            for field in _BUDGET_FIELDS
        }
        return budget, module_list, False
    warnings.append(t("Kein auswertbares Gesamt-PoE-Budget gemeldet."))
    return _empty_budget(), module_list, False


def build_poe_summary(power_output: str | None, version_output: str, model: str | None) -> dict:
    """Return independent budget readings and documented hardware standards.

    Unknown values stay null. Standards for mixed stacks are the union of all
    documented member capabilities; an unknown member leaves the list unknown.
    ``standards_source`` is display text, never HTML.
    """
    warnings = []
    budget, modules, explicit_total = _read_budgets(power_output, warnings)
    models = hardware_models(version_output, model)
    capabilities = [standards_of(hardware_model) for hardware_model in models]
    supported = True if any(capability for capability in capabilities) else None
    if any(value is not None and value > 0 for value in budget.values()):
        supported = True
    # A master-only model must not describe all members of an otherwise unknown
    # stack. Duplicate model names in a full inventory still count as members.
    _found_table, inventory_members = stack_members(version_output)
    model_lines = re.findall(r"^\s*Model (?:number|name)\s*:", version_output, re.MULTILINE | re.IGNORECASE)
    inventory_complete = len(modules) <= max(1, len(inventory_members), len(model_lines))
    if inventory_members:
        inventory_complete = all(module["module"] in inventory_members for module in modules)
    missing_members = [member for member, hardware_model in inventory_members.items()
                       if member not in {module["module"] for module in modules}
                       and standards_of(hardware_model) != ()]
    if modules and missing_members and not explicit_total:
        budget = _empty_budget()
        warnings.append(t("PoE-Budget ist für den erkannten Switch-Stack unvollständig."))
    if (
        models
        and all(capability is not None for capability in capabilities)
        and None not in inventory_members.values()
        and inventory_complete
    ):
        standards = [STANDARD_LABELS[standard] for standard in STANDARD_LABELS
                     if any(standard in capability for capability in capabilities)]
        source = "Cisco-Dokumentation, Hardwaremodelle: " + ", ".join(models)
        if not standards:
            if supported is True:
                standards = None
                warnings.append(t("Gemeldetes PoE-Budget widerspricht den dokumentierten Hardwarefähigkeiten."))
            else:
                supported = False
        if standards and STANDARD_LABELS["802.3bt-type3"] in standards:
            source += "; IEEE 802.3bt Typ 3 setzt passende Firmware und Konfiguration voraus"
    else:
        standards = None
        source = None
        warnings.append(t("Unterstützte PoE-Versionen sind nicht für alle erkannten Hardwaremodelle verifiziert."))
    return {
        "supported": supported,
        **budget,
        "standards": standards,
        "standards_source": source,
        "modules": modules,
        "warnings": list(dict.fromkeys(warnings)),
    }


# --- Per-port power profiles -----------------------------------------------------------
# Reuse the documented PID catalog, but never its stack union.
# PSE ceilings (not the lower power arriving at the PD after cable losses):
# https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/guide-c07-744813.html
# Type 4 PSEs also support Type 3 PDs; UPOE is a separate Cisco protocol:
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/hardware/install/b_c9300_hig/Product-overview.html
# C9300 UPOE Type 3 requires IOS XE >=16.12.1 AND enabled upoe-plus mode;
# enabling that mode power cycles the member. show version cannot prove it:
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-5/configuration_guide/int_hw/b_175_int_and_hw_9300_cg/configuring_poe.html
# C9200(L)-48PL has 48 PoE+ downlinks with a smaller total power budget, not
# a documented hard cutoff at port 24. The exact-port operational check remains
# necessary. C9300-48UXM/48UN and 3650/3850 mixed-speed U models have UPOE on all
# their copper downlinks, including the slower ports:
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/hardware/install/b-c9200-hig/product_overview.html
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3650/hardware/installation/guide/Cat3650hig_book/HIGOVERV.html
# The 3560X/3750X 24U/48U variants also have UPOE (unlike their P/PF variants):
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3750x_3560x/hardware/installation/guide/3750x_3560x_HIG/HIGOVERV.html
# 2960X-24PSQ-L is an exception with only eight powered copper ports. Without
# a verified physical-port map do not generalize its model-wide PoE+ capability:
# https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/datasheet_c78-728232.html
# Member IDs, not the selected '*' row, identify the target port's hardware:
# https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/16-12/command_reference/b_1612_9300_cr/b_1612_9300_cr_chapter_01101.html
_PROFILES = (
    ("802.3af", "PoE (IEEE 802.3af) – max. 15,4 W", 15.4),
    ("802.3at", "PoE+ (IEEE 802.3at) – max. 30 W", 30),
    ("802.3bt-type3", "PoE++ (IEEE 802.3bt Typ 3) – max. 60 W", 60),
    ("802.3bt-type4", "PoE++ (IEEE 802.3bt Typ 4) – max. 90 W", 90),
    ("cisco-upoe", "Cisco UPOE – max. 60 W", 60),
)
_INTERFACE = re.compile(
    r"(Fa(?:stEthernet)?|Gi(?:gabitEthernet)?|Te(?:nGigabitEthernet)?|"
    r"Tw(?:oGigabitEthernet)?|Fi(?:veGigabitEthernet)?)"
    r"(\d+)/(\d+)(?:/(\d+))?", re.IGNORECASE,
)


def _target_model(version: str, member: str | None) -> tuple[str | None, str | None]:
    if not version or re.search(r"^\s*%", version, re.MULTILINE):
        return None, t("Das Hardwaremodell konnte nicht vom Switch ausgelesen werden.")
    found_table, members = stack_members(version)
    if found_table:
        if member is None:
            return None, t("Das Interface lässt sich keinem eindeutigen Stack-Mitglied zuordnen.")
        model = members.get(member)
        if not model:
            return None, t("Das Hardwaremodell von Stack-Mitglied {member} ist nicht eindeutig belegt.", member=member)
        return model, None
    # Old standalone IOS versions do not display a stack inventory. Restrict
    # that fallback to the default member and exactly one hardware identity.
    # Repeated Model Number sections can denote a same-model stack: do not infer
    # its member mapping from the deduplicated model list.
    models = hardware_models(version, None)
    model_lines = re.findall(r"^\s*Model (?:number|name)\s*:", version, re.MULTILINE | re.IGNORECASE)
    stack_sections = re.search(r"^\s*Switch\s+\d+\s*$", version, re.MULTILINE | re.IGNORECASE)
    if len(models) != 1 or len(model_lines) > 1 or stack_sections or member not in (None, "1"):
        return None, t("Das Hardwaremodell ist für dieses Interface nicht eindeutig belegt.")
    return models[0], None


def _port_reason(model: str, kind: str, member: str | None, slot: int, port: int) -> str | None:
    if re.fullmatch(r"(?:WS-)?C2960X-24PSQ-L", model):
        return t("Dieses Modell hat nur acht PoE-Ports; deren Portzuordnung ist noch nicht verifiziert.")
    standalone = bool(re.match(r"(?:WS-)?C(?:3560|2960L)", model))
    if (member is None) != standalone:
        return t("Die Portnummer lässt sich für dieses Hardwaremodell nicht sicher zuordnen.")
    if slot != 0:
        return t("Uplink-, Modul- und Management-Ports erhalten kein PoE-Leistungsprofil.")
    count = re.search(r"-(?:8X|12X)?(8|16|24|48)[A-Z]", model)
    if not count or not 1 <= port <= int(count[1]):
        return t("Der Port liegt außerhalb der dokumentierten PoE-Downlink-Ports.")
    fast_ethernet = bool(re.match(r"(?:WS-)?C(?:3560(?:V2)?|3750)-(?:24PS|48PS)", model))
    multigig = bool(re.search(r"(?:UX|XU|UN|HX|PXG)|-(?:8X|12X)", model))
    families = {"fa"} if fast_ethernet else {"gi", "te", "tw", "fi"} if multigig else {"gi"}
    if kind.lower()[:2] not in families:
        return t("Dieser Interface-Typ ist kein dokumentierter PoE-Downlink des Modells.")
    return None


def get_poe_capabilities(version_output: str | None, interface: str) -> dict:
    """Return verified power-profile choices for one interface, never a stack union.

    These profiles set a PSE power ceiling, not a protocol or powered-device class.
    Unknown or ambiguous evidence gives no choices and an explanatory reason.
    The device-default choice is deliberately not a standard and is added by
    the caller only after independently verifying that the port supports PoE.
    This function performs no I/O, uses no operational Max/class/power, and does
    not enable switch-wide IEEE 802.3bt mode.
    """
    result = {
        "poe_standard_options": [],
        "poe_standards_source": None,
        "poe_standards_reason": None,
        "poe_hardware_model": None,
    }
    match = _INTERFACE.fullmatch(interface or "")
    if not match:
        result["poe_standards_reason"] = t("Kein unterstütztes physisches PoE-Interface.")
        return result
    kind, first, second, third = match.groups()
    member = str(int(first)) if third is not None else None
    slot, port = (int(second), int(third)) if third is not None else (int(first), int(second))
    model, reason = _target_model(version_output or "", member)
    result["poe_hardware_model"] = model
    if reason:
        result["poe_standards_reason"] = reason
        return result
    standards = standards_of(model)
    if standards is None:
        result["poe_standards_reason"] = t("Für dieses Hardwaremodell sind keine PoE-Standards verifiziert.")
        return result
    if not standards:
        result["poe_standards_reason"] = t("Dieses Hardwaremodell unterstützt kein PoE.")
        return result
    reason = _port_reason(model, kind, member, slot, port)
    if reason:
        result["poe_standards_reason"] = reason
        return result
    standards = set(standards)
    if "802.3bt-type4" in standards:
        standards.add("802.3bt-type3")
    elif "802.3bt-type3" in standards:
        standards.remove("802.3bt-type3")
        result["poe_standards_reason"] = t(
            "IEEE 802.3bt Typ 3 benötigt auf diesem UPOE-Modell passende Firmware und einen "
            "aktivierten 802.3bt-Modus. Dieser Modus ist nicht verifiziert; Cisco UPOE mit "
            "maximal 60 W bleibt auswählbar. Die Auswahl schaltet keinen Protokollmodus um."
        )
    result["poe_standard_options"] = [
        {"id": identifier, "label": t(label), "max_watts": watts}
        for identifier, label, watts in _PROFILES if identifier in standards
    ]
    result["poe_standards_source"] = (
        t("Cisco-Hardwaredokumentation: {model}, Stack-Mitglied {member}, Port {port}", model=model, member=member, port=port)
        if member else t("Cisco-Hardwaredokumentation: {model}, Port {port}", model=model, port=port)
    )
    return result


def port_poe_capabilities(version_output: str, interface: str, supported: bool | None) -> dict:
    capabilities = get_poe_capabilities(version_output, interface)
    if supported is not True:
        return {
            **capabilities,
            "poe_standard_options": [],
            "poe_standards_reason": (
                t("Dieses Interface stellt kein PoE bereit.") if supported is False
                else t("Die PoE-Unterstuetzung dieses Interfaces konnte nicht bestaetigt werden.")
            ),
        }
    options = capabilities["poe_standard_options"]
    if not any(option["id"] == "default" for option in options):
        capabilities["poe_standard_options"] = [
            {"id": "default", "label": t("Geraetestandard"), "max_watts": 0}, *options,
        ]
    return capabilities


def read_optional_poe_capabilities(session: transport.SshSession, interface: str, supported: bool | None) -> dict:
    """Per-port power profiles from a fresh ``show version`` (only for PoE ports)."""
    version_output = ""
    if supported is True and not session.broken:
        try:
            version_output = transport.send_show(session.conn, "show version")
            ensure_show_output(version_output, "show version")
        except transport.SSH_TIMEOUT_ERRORS:
            session.broken = True
            version_output = ""
        except (*transport.SSH_ERRORS, SwitchConnectionError):
            version_output = ""
        if not version_output:
            append_warning(
                session.warnings,
                t("Das Switch-Modell konnte nicht gelesen werden; die unterstuetzten PoE-Standards sind unbekannt."),
            )
    return port_poe_capabilities(version_output, interface, supported)
