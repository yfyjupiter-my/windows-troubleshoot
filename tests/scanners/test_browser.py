import json

from app_triage.models import ActionSpec, Risk
from app_triage.scanners.base import SCANNERS
from app_triage.scanners.browser import scan_browser
from app_triage.sysapi.base import ShortcutInfo
from app_triage.sysapi.fake import FakeSystem

DESKTOP = r"C:\Users\tester\Desktop"
LOCAL = r"C:\Users\tester\AppData\Local"
CHROME_PREFS = LOCAL + r"\Google\Chrome\User Data\Default\Preferences"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def test_registered_under_browser_label():
    assert SCANNERS["browser"][0] == "浏览器劫持"


def test_edge_shortcut_with_url_flagged_and_args_cleaned():
    s = FakeSystem()
    lnk = DESKTOP + r"\Microsoft Edge.lnk"
    s.add_shortcut(lnk, ShortcutInfo(EDGE, "--profile-directory=Default https://www.2345.com"))
    [f] = scan_browser(s)
    assert f.category == "browser"
    assert f.risk is Risk.MEDIUM
    assert f.vendor == "2345"
    assert f.evidence["path"] == lnk
    assert f.actions == [ActionSpec("fix_shortcut_args", lnk, (("args", "--profile-directory=Default"),))]


def test_quoted_url_removed_and_taskbar_pin_scanned():
    s = FakeSystem()
    lnk = (r"C:\Users\tester\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"
           r"\User Pinned\TaskBar\Chrome.lnk")
    s.add_shortcut(lnk, ShortcutInfo(r"C:\Chrome\chrome.exe", '"http://hao123.com/?tn=x"  --new-window'))
    [f] = scan_browser(s)
    assert f.actions[0].param("args") == "--new-window"


def test_url_removal_preserves_other_whitespace_and_quoted_urls():
    s = FakeSystem()
    s.add_shortcut(DESKTOP + r"\A.lnk",
                   ShortcutInfo(EDGE, '--user-data-dir="C:\\a  b" https://www.2345.com'))
    s.add_shortcut(DESKTOP + r"\B.lnk",
                   ShortcutInfo(EDGE, '--x=1  "https://hao123.com/a b"  --y="u http://z"'))
    by = {f.evidence["path"]: f for f in scan_browser(s)}
    assert by[DESKTOP + r"\A.lnk"].actions[0].param("args") == '--user-data-dir="C:\\a  b"'
    # a URL inside a quoted value of another argument is not a URL token
    assert by[DESKTOP + r"\B.lnk"].actions[0].param("args") == '--x=1  --y="u http://z"'


def test_clean_shortcut_ignored():
    s = FakeSystem()
    s.add_shortcut(DESKTOP + r"\Edge.lnk", ShortcutInfo(EDGE, "--profile-directory=Default"))
    s.add_shortcut(DESKTOP + r"\Notepad.lnk", ShortcutInfo(r"C:\Windows\notepad.exe", "https://x.com"))
    s.add_shortcut(DESKTOP + r"\App.lnk", ShortcutInfo(EDGE, "--app=https://mail.example.com"))
    # whitespace-only differences (double space, tab, quoted spaces) are not a URL to remove
    s.add_shortcut(DESKTOP + r"\Spaced.lnk", ShortcutInfo(EDGE, "--profile-directory=Default  --new-window"))
    s.add_shortcut(DESKTOP + r"\Tabbed.lnk", ShortcutInfo(EDGE, '--user-data-dir="C:\\a  b"\t--x '))
    assert scan_browser(s) == []


def prefs(**data):
    return json.dumps(data)


def test_chrome_homepage_hijack_info():
    s = FakeSystem()
    s.add_file(CHROME_PREFS, content=prefs(
        homepage="https://www.hao123.com/?tn=88",
        session={"startup_urls": ["https://www.hao123.com/?tn=88", "https://example.com",
                                  "https://browser.360.cn/ee"]}))
    findings = scan_browser(s)
    assert {f.evidence["url"] for f in findings} == {
        "https://www.hao123.com/?tn=88", "https://browser.360.cn/ee"}
    for f in findings:
        assert f.risk is Risk.INFO and f.actions == []
        assert f.evidence["browser"] == "Chrome"
        assert "浏览器设置" in f.title


def test_edge_preferences_checked_and_missing_skipped():
    s = FakeSystem()
    s.add_file(LOCAL + r"\Microsoft\Edge\User Data\Default\Preferences",
               content=prefs(homepage="http://www.2345.com/?x"))
    [f] = scan_browser(s)
    assert f.evidence["browser"] == "Edge" and f.vendor == "2345"


def test_malformed_preferences_ignored():
    s = FakeSystem()
    s.add_file(CHROME_PREFS, content="{not json")
    s.add_file(LOCAL + r"\Microsoft\Edge\User Data\Default\Preferences", content="[1, 2]")
    assert scan_browser(s) == []


def test_access_denied_desktop_does_not_hide_preferences():
    s = FakeSystem()
    s.add_shortcut(DESKTOP + r"\Edge.lnk", ShortcutInfo(EDGE, "https://2345.com"))
    s.deny(DESKTOP)
    s.add_file(CHROME_PREFS, content=prefs(homepage="https://www.2345.com"))
    [f] = scan_browser(s)
    assert f.evidence["setting"] == "homepage"
