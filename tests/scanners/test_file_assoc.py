from app_triage.models import Risk, make_finding_id
from app_triage.scanners.file_assoc import WATCHED_EXTS, scan_file_assoc
from app_triage.sysapi.fake import FakeSystem

FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
WPS_CMD = r'"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\ksolaunch.exe" "%1"'
PHOTOS = "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc"


def set_assoc(s: FakeSystem, ext: str, progid: str, command: str | None = None,
              openwith: tuple[str, ...] = ()) -> None:
    s.add_key(f"{FILEEXTS}\\{ext}")
    s.add_key(f"{FILEEXTS}\\{ext}\\UserChoice", {"ProgId": progid})
    s.add_key(f"{FILEEXTS}\\{ext}\\OpenWithProgids", {n: b"" for n in openwith})
    if command is not None:
        s.add_key(rf"HKCR\{progid}\shell\open\command", {"": command})


def test_wps_hijacked_jpg_detected():
    s = FakeSystem()
    set_assoc(s, ".jpg", "WPS.PIC.jpg", WPS_CMD, openwith=("WPS.PIC.jpg", PHOTOS, "PhotoViewer.FileAssoc.Tiff"))
    findings = scan_file_assoc(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.id == make_finding_id("file_assoc", ".jpg")
    assert f.category == "file_assoc" and f.risk == Risk.MEDIUM
    assert f.vendor == "WPS (金山办公)"
    assert f.title == ".jpg 的默认打开方式被 WPS (金山办公) 占用"
    assert f.evidence == {"ext": ".jpg", "progid": "WPS.PIC.jpg", "command": WPS_CMD,
                          "openwith": "WPS.PIC.jpg"}
    (a,) = f.actions
    assert a.kind == "reset_file_assoc" and a.target == ".jpg"
    assert a.param("progid") == "WPS.PIC.jpg" and a.param("openwith") == "WPS.PIC.jpg"


def test_photos_association_not_flagged():
    s = FakeSystem()
    set_assoc(s, ".jpg", PHOTOS, r"C:\Windows\System32\rundll32.exe shimgvw.dll")
    assert scan_file_assoc(s) == []


def test_office_ext_wps_is_info():
    s = FakeSystem()
    set_assoc(s, ".docx", "KWPS.Document.12", WPS_CMD)
    set_assoc(s, ".png", "WPS.PIC.png", WPS_CMD)
    by_ext = {f.evidence["ext"]: f for f in scan_file_assoc(s)}
    assert by_ext[".docx"].risk == Risk.INFO
    assert by_ext[".docx"].actions[0].kind == "reset_file_assoc"
    assert by_ext[".png"].risk == Risk.MEDIUM


def test_office_ext_other_vendor_stays_medium():
    s = FakeSystem()
    set_assoc(s, ".txt", "2345Txt", r'"C:\Program Files\2345Soft\txt.exe" "%1"')
    (f,) = scan_file_assoc(s)
    assert f.risk == Risk.MEDIUM and f.vendor == "2345"


def test_denied_userchoice_still_reported():
    s = FakeSystem()
    set_assoc(s, ".jpg", "WPS.PIC.jpg", WPS_CMD)
    s.add_key(r"HKCR\.jpg", {"": "WPS.PIC.jpg"})
    s.deny(FILEEXTS + r"\.jpg\UserChoice")
    (f,) = scan_file_assoc(s)
    assert f.evidence["acl"] == "denied"
    assert f.evidence["progid"] == "WPS.PIC.jpg" and f.evidence["command"] == WPS_CMD
    assert f.actions[0].param("progid") == "WPS.PIC.jpg"


def test_acl_key_absent_when_not_denied():
    s = FakeSystem()
    set_assoc(s, ".jpg", "WPS.PIC.jpg", WPS_CMD)
    (f,) = scan_file_assoc(s)
    assert "acl" not in f.evidence


def test_denied_userchoice_with_no_hkcr_default_yields_nothing():
    s = FakeSystem()
    set_assoc(s, ".jpg", "WPS.PIC.jpg", WPS_CMD)
    s.deny(FILEEXTS + r"\.jpg\UserChoice")
    assert scan_file_assoc(s) == []


def test_missing_keys_are_not_errors():
    s = FakeSystem()
    assert scan_file_assoc(s) == []
    s.add_key(FILEEXTS + r"\.jpg")  # no UserChoice, no HKCR default
    s.add_key(r"HKCR\.png", {"": ""})
    s.add_key(FILEEXTS + r"\.png")
    assert scan_file_assoc(s) == []


def test_missing_userchoice_falls_back_to_hkcr_default():
    s = FakeSystem()
    s.add_key(FILEEXTS + r"\.gif")
    s.add_key(r"HKCR\.gif", {"": "WPS.PIC.gif"})
    s.add_key(r"HKCR\WPS.PIC.gif\shell\open\command", {"": WPS_CMD})
    (f,) = scan_file_assoc(s)
    assert f.evidence["progid"] == "WPS.PIC.gif" and "acl" not in f.evidence


def test_vendor_matched_by_command_only_and_missing_command():
    s = FakeSystem()
    set_assoc(s, ".bmp", "CustomViewer", WPS_CMD)
    set_assoc(s, ".gif", "WPS.PIC.gif")  # progid matches, command key missing
    by_ext = {f.evidence["ext"]: f for f in scan_file_assoc(s)}
    assert by_ext[".bmp"].evidence["command"] == WPS_CMD
    assert by_ext[".gif"].evidence["command"] == ""


def test_denied_command_lookup_treated_as_empty():
    s = FakeSystem()
    set_assoc(s, ".gif", "WPS.PIC.gif", WPS_CMD)
    s.deny(r"HKCR\WPS.PIC.gif\shell")
    (f,) = scan_file_assoc(s)
    assert f.evidence["command"] == ""


def test_openwith_joins_only_vendor_entries_and_empty_when_none():
    s = FakeSystem()
    set_assoc(s, ".jpg", "WPS.PIC.jpg", WPS_CMD, openwith=("WPS.PIC.jpg", "WPS.PIC.png", PHOTOS))
    set_assoc(s, ".png", "WPS.PIC.png", WPS_CMD, openwith=(PHOTOS,))
    by_ext = {f.evidence["ext"]: f for f in scan_file_assoc(s)}
    assert by_ext[".jpg"].evidence["openwith"] == "WPS.PIC.jpg;WPS.PIC.png"
    assert by_ext[".png"].evidence["openwith"] == ""
    assert by_ext[".png"].actions[0].param("openwith") == ""


def test_watched_exts_and_registration():
    assert WATCHED_EXTS[0] == ".jpg" and WATCHED_EXTS[-1] == ".pptx" and len(WATCHED_EXTS) == 18
    from app_triage.scanners.base import SCANNERS
    assert SCANNERS["file_assoc"][0] == "文件默认打开方式"
