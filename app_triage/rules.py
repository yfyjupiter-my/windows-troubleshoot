"""Known bundled-software vendor rules."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorRule:
    name: str
    patterns: tuple[str, ...]
    note: str


KNOWN_VENDORS: list[VendorRule] = [
    VendorRule(
        "WPS (金山办公)",
        (
            r"kingsoft",
            r"\bwps(office|cloud|cloudsvr|\.pic|\.|\b)",
            r"\bkso\w*",
            r"ksolaunch",
            r"wpscenter",
            r"\bkwps",  # ProgIds: KWPS.Document.12 / KET.Sheet.12 / KWPP.Presentation.12
            r"\bket\.",
            r"\bkwpp",
        ),
        "常被捆绑安装，会抢占图片/PDF 默认打开方式并添加自启和后台服务",
    ),
    VendorRule(
        "2345",
        (r"2345",),
        "2345 系列软件常被捆绑安装，会篡改默认浏览器/看图软件并添加自启和弹窗推送",
    ),
    VendorRule(
        "鲁大师",
        (r"ludashi", r"computerz"),
        "常被捆绑安装，带有开机自启、后台常驻和广告弹窗",
    ),
    VendorRule(
        "360",
        (r"\b360(safe|tray|se|sd|chrome|\b)", r"qihoo"),
        "360 系列软件常被捆绑安装，会添加自启项、后台服务并篡改浏览器主页",
    ),
]

_COMPILED: list[tuple[VendorRule, list[re.Pattern[str]]]] = [
    (rule, [re.compile(p, re.IGNORECASE) for p in rule.patterns]) for rule in KNOWN_VENDORS
]


def match_vendor(*texts: str) -> VendorRule | None:
    """Return the first vendor rule whose pattern matches any of the texts."""
    for rule, patterns in _COMPILED:
        for text in texts:
            if not text:
                continue
            if any(p.search(text) for p in patterns):
                return rule
    return None
