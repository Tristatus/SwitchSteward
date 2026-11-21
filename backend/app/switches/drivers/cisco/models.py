"""Cisco model catalog generated from the documented hardware PID allowlist.

Deliberately a conservative allowlist of documented hardware PIDs. Firmware and
configuration can restrict these hardware capabilities further. In particular,
UPOE does not by itself prove IEEE 802.3bt operation. Sources:
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-x-series-switches/datasheet_c78-728232.html
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-s-series-switches/data_sheet_c78-726680.html
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3560-x-series-switches/data_sheet_c78-584733.html
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst3560/hardware/installation/guide/3560hig/higoverview.html
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3750-series-switches/product_data_sheet0900aecd80371991.html
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html
https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/220318-verify-differences-between-poe-802-3at-8.html
https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-2960-l-series-switches/nb-06-cat2960-l-ser-data-sheet-cte-en.html
https://www.cisco.com/c/en_in/products/collateral/switches/catalyst-3650-series-switches/datasheet-c78-729449.html
https://www.cisco.com/c/en_in/products/collateral/switches/catalyst-3850-series-switches/datasheet_c78-720918.html
Type 3 on the listed C9300 U models requires suitable IOS-XE/configuration:
https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-5/configuration_guide/int_hw/b_175_int_and_hw_9300_cg/configuring_poe.html
"""

import re

from ...catalog import Catalog, ModelProfile

_AF, _AT, _BT3, _BT4, _UPOE = "802.3af", "802.3at", "802.3bt-type3", "802.3bt-type4", "cisco-upoe"

# (id, label, full-match PID pattern, PoE standards); the first match wins.
_ENTRIES = (
    ("c2960x-poe", "Catalyst 2960-X PoE+", r"(?:WS-)?C2960X-(?:48[FL]P[DS]|24P[DS]|24PSQ)-L", (_AF, _AT)),
    ("c2960xr-poe", "Catalyst 2960-XR PoE+", r"(?:WS-)?C2960XR-(?:48[FL]P[DS]|24P[DS])-I", (_AF, _AT)),
    ("c2960s-poe", "Catalyst 2960-S PoE+", r"(?:WS-)?C2960S-(?:48[FL]P[DS]|24P[DS])-L", (_AF, _AT)),
    ("c2960l-poe", "Catalyst 2960-L PoE+", r"(?:WS-)?C2960L-(?:8PS|16PS|24PS|48PS|24PQ|48PQ)-LL", (_AF, _AT)),
    ("c3560x-3750x-poe", "Catalyst 3560-X/3750-X PoE+", r"(?:WS-)?C(?:3560X|3750X)-(?:24P|48P|48PF)(?:-[LSE])?",
     (_AF, _AT)),
    ("c3560x-3750x-upoe", "Catalyst 3560-X/3750-X UPOE", r"(?:WS-)?C(?:3560X|3750X)-(?:24U|48U)(?:-[LSE])?",
     (_AF, _AT, _UPOE)),
    ("c3560-poe", "Catalyst 3560 PoE", r"(?:WS-)?C3560(?:G|V2)?-(?:24PS|48PS)(?:-[SE])?", (_AF,)),
    ("c3750-poe", "Catalyst 3750 PoE", r"(?:WS-)?C3750G?-(?:24PS|48PS)(?:-[SE])?", (_AF,)),
    ("c3650-poe", "Catalyst 3650 PoE+",
     r"(?:WS-)?C3650-(?:24PS|48PS|48FS|24PD|24PDM|48PD|48FD|48PQ|48FQ|48FQM|8X24PD|12X48FD)(?:-[LSE])?",
     (_AF, _AT)),
    ("c3650-upoe", "Catalyst 3650 UPOE", r"(?:WS-)?C3650-(?:8X24UQ|12X48UQ|12X48UR|12X48UZ)(?:-[LSE])?",
     (_AF, _AT, _UPOE)),
    ("c3850-poe", "Catalyst 3850 PoE+", r"(?:WS-)?C3850-(?:24P|48P|48F)(?:-[LSE])?", (_AF, _AT)),
    ("c3850-upoe", "Catalyst 3850 UPOE", r"(?:WS-)?C3850-(?:24U|48U|24XU|12X48U)(?:-[LSE])?", (_AF, _AT, _UPOE)),
    ("c9200-poe", "Catalyst 9200 PoE+", r"C9200-(?:24P|24PB|24PXG|48P|48PL|48PB|48PXG)(?:-[AE])?", (_AF, _AT)),
    ("c9200l-poe", "Catalyst 9200L PoE+", r"C9200L-(?:24P|48P|48PL)-(?:4G|4X)(?:-[AE])?", (_AF, _AT)),
    ("c9300-poe", "Catalyst 9300 PoE+", r"C9300-(?:24P|48P)(?:-[AE])?", (_AF, _AT)),
    ("c9300l-poe", "Catalyst 9300L PoE+", r"C9300L-(?:24P|48P|48PF)-(?:4G|4X)(?:-[AE])?", (_AF, _AT)),
    ("c9300-bt", "Catalyst 9300 802.3bt", r"C9300-(?:24H|48H)(?:-[AE])?", (_AF, _AT, _BT4)),
    ("c9300x-bt", "Catalyst 9300X 802.3bt", r"C9300X-(?:24HX|48HX|48HXN)(?:-[AE])?", (_AF, _AT, _BT4)),
    ("c9300-upoe", "Catalyst 9300 UPOE", r"C9300-(?:24U|48U|24UX|48UXM|48UN)(?:-[AE])?", (_AF, _AT, _BT3, _UPOE)),
    ("c9300-upoe-b", "Catalyst 9300B UPOE", r"C9300-(?:24UB|24UXB|48UB)(?:-[AE])?", (_AF, _AT, _UPOE)),
    ("c9300l-upoe", "Catalyst 9300L UPOE", r"C9300L-(?:24UXG|48UXG)-(?:2Q|4X)(?:-[AE])?", (_AF, _AT, _BT3, _UPOE)),
    ("c2960x", "Catalyst 2960-X", r"(?:WS-)?C2960X-(?:(?:24TD|48TD|24TS|48TS)-L|(?:24TS|48TS)-LL)", ()),
    ("c2960xr", "Catalyst 2960-XR", r"(?:WS-)?C2960XR-(?:24TD|48TD|24TS|48TS)-I", ()),
    ("c3650", "Catalyst 3650", r"(?:WS-)?C3650-(?:24TS|48TS|24TD|48TD|48TQ)(?:-[LSE])?", ()),
    ("c3850", "Catalyst 3850", r"(?:WS-)?C3850-(?:24T|48T)(?:-[LSE])?", ()),
    ("c9200", "Catalyst 9200", r"C9200-(?:24T|48T)(?:-[AE])?", ()),
    ("c9200l", "Catalyst 9200L", r"C9200L-(?:24T|48T)-(?:4G|4X)(?:-[AE])?", ()),
    ("c9300", "Catalyst 9300", r"C9300-(?:24T|48T|24S|48S)(?:-[AE])?", ()),
    ("c9300l", "Catalyst 9300L", r"C9300L-(?:24T|48T)-(?:4G|4X)(?:-[AE])?", ()),
    ("c9300x", "Catalyst 9300X", r"C9300X-(?:48TX|12Y|24Y)(?:-[AE])?", ()),
)

CATALOG = Catalog(tuple(
    ModelProfile(
        id=model_id,
        vendor="Cisco",
        label=label,
        match=re.compile(rf"\A(?:{pattern})\Z", re.IGNORECASE),
        poe_standards=standards,
    )
    for model_id, label, pattern, standards in _ENTRIES
))
