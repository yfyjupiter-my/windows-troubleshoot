import pytest

from app_triage.models import Risk, make_finding_id
from app_triage.scanners.autoruns import scan_autoruns
from app_triage.sysapi.base import AccessDenied, ServiceInfo, ShortcutInfo, SignatureInfo, TaskInfo
from app_triage.sysapi.fake import FakeSystem

RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WPS_EXE = r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\wpscloudsvr.exe"
MS = SignatureInfo("valid", "Microsoft Corporation")


def by_source(findings, source):
    return [f for f in findings if f.evidence["source"] == source]


def test_wps_run_value_medium():
    s = FakeSystem()
    s.add_key(RUN, {"WPSCloud": f'"{WPS_EXE}" /tray'})
    s.set_signature(WPS_EXE, SignatureInfo("valid", "Zhuhai Kingsoft Office Software Co., Ltd."))
    (f,) = scan_autoruns(s)
    assert f.id == make_finding_id("autoruns", f"run|{RUN}\\WPSCloud")
    assert f.category == "autoruns" and f.risk == Risk.MEDIUM
    assert f.vendor == "WPS (金山办公)"
    assert f.evidence["source"] == "run"
    assert f.evidence["command"] == f'"{WPS_EXE}" /tray'
    assert f.evidence["exe"] == WPS_EXE
    assert f.evidence["publisher"].startswith("Zhuhai Kingsoft")
    assert f.evidence["signature"] == "valid"
    (a,) = f.actions
    assert a.kind == "delete_reg_value" and a.target == RUN
    assert a.param("name") == "WPSCloud" and not a.high_risk


def test_run_value_risk_levels():
    s = FakeSystem()
    s.add_key(RUN, {"Unsigned": r"C:\Tools\a.exe", "Signed": r"C:\Tools\b.exe",
                    "Office": r"C:\Tools\c.exe", "Ghost": r"C:\Tools\missing.exe"})
    s.set_signature(r"C:\Tools\a.exe", SignatureInfo("unsigned", ""))
    s.set_signature(r"C:\Tools\b.exe", SignatureInfo("valid", "Acme Ltd"))
    s.set_signature(r"C:\Tools\c.exe", MS)
    risks = {f.evidence["command"]: f.risk for f in scan_autoruns(s)}
    assert risks == {r"C:\Tools\a.exe": Risk.LOW, r"C:\Tools\b.exe": Risk.INFO,
                     r"C:\Tools\missing.exe": Risk.LOW}


def test_run_key_variants_and_denied_source_does_not_drop_others():
    s = FakeSystem()
    hklm_once = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    wow = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    s.add_key(hklm_once, {"A": r"C:\t\a.exe"})
    s.add_key(wow, {"B": r"C:\t\b.exe"})
    s.add_key(RUN, {"C": r"C:\t\c.exe", "Bin": b"\x00"})
    s.deny(RUN)
    names = {f.actions[0].param("name") for f in scan_autoruns(s)}
    assert names == {"A", "B"}


def test_microsoft_signed_service_skipped():
    s = FakeSystem()
    s.add_service(ServiceInfo("MsSvc", "MS Service", r"C:\Program Files\Microsoft\ms.exe -k x", "auto", "running"))
    s.set_signature(r"C:\Program Files\Microsoft\ms.exe", MS)
    s.add_service(ServiceInfo("Spooler", "Print Spooler", r"C:\Windows\System32\spoolsv.exe", "auto", "running"))
    assert scan_autoruns(s) == []


def test_third_party_auto_service_high_risk_action():
    s = FakeSystem()
    exe = r"C:\Program Files\Kingsoft\wpscloudsvr.exe"
    s.add_service(ServiceInfo("wpscloudsvr", "WPS Cloud Service", f"{exe} -s", "auto", "running"))
    s.add_service(ServiceInfo("manualsvc", "Manual", r"C:\Program Files\X\x.exe", "manual", "stopped"))
    s.set_signature(exe, SignatureInfo("valid", "Kingsoft"))
    (f,) = scan_autoruns(s)
    assert f.id == make_finding_id("autoruns", "service|wpscloudsvr")
    assert f.evidence["source"] == "service" and f.risk == Risk.MEDIUM
    assert f.evidence["exe"] == exe
    (a,) = f.actions
    assert a.kind == "set_service_start" and a.target == "wpscloudsvr" and a.high_risk
    assert a.param("start") == "disabled" and a.param("previous") == "auto"


def test_service_under_systemroot_compared_case_insensitively():
    s = FakeSystem()
    s.add_service(ServiceInfo("x", "x", r"c:\WINDOWS\system32\foo.exe -k a", "auto", "running"))
    assert scan_autoruns(s) == []


def test_microsoft_tasks_skipped():
    s = FakeSystem()
    s.add_task(TaskInfo(r"\Microsoft\Windows\Defrag\ScheduledDefrag", r"C:\Windows\system32\defrag.exe", True, "Microsoft"))
    s.add_task(TaskInfo(r"\2345UpdateTask", r"C:\Program Files\2345Soft\up.exe /silent", True, "2345"))
    (f,) = scan_autoruns(s)
    assert f.evidence["source"] == "task" and f.vendor == "2345" and f.risk == Risk.MEDIUM
    assert f.id == make_finding_id("autoruns", r"task|\2345UpdateTask")
    (a,) = f.actions
    assert a.kind == "disable_task" and a.target == r"\2345UpdateTask"


def test_winlogon_shell_hijack_high():
    s = FakeSystem()
    s.add_key(WINLOGON, {"Shell": r"explorer.exe, C:\evil\x.exe",
                         "Userinit": r"c:\windows\SYSTEM32\userinit.exe"})
    (f,) = scan_autoruns(s)
    assert f.evidence["source"] == "winlogon" and f.risk == Risk.HIGH
    assert f.id == make_finding_id("autoruns", "winlogon|Shell")
    (a,) = f.actions
    assert a.kind == "set_reg_value" and a.target == WINLOGON and a.high_risk
    assert a.param("name") == "Shell" and a.param("value") == "explorer.exe"


def test_winlogon_userinit_hijack_and_defaults_clean():
    s = FakeSystem()
    s.add_key(WINLOGON, {"Shell": "Explorer.exe", "Userinit": r"C:\Windows\system32\userinit.exe,C:\evil.exe,"})
    (f,) = scan_autoruns(s)
    assert f.evidence["source"] == "winlogon" and f.risk == Risk.HIGH
    assert f.actions[0].param("name") == "Userinit"
    assert f.actions[0].param("value") == r"C:\Windows\system32\userinit.exe,"
    s2 = FakeSystem()
    s2.add_key(WINLOGON, {"Shell": "explorer.exe", "Userinit": r"C:\Windows\system32\userinit.exe,"})
    assert scan_autoruns(s2) == []


def test_ifeo_debugger_high():
    s = FakeSystem()
    s.add_key(IFEO + r"\notepad.exe", {"Debugger": r"C:\evil\dbg.exe"})
    s.add_key(IFEO + r"\calc.exe", {"GlobalFlag": 512})
    (f,) = scan_autoruns(s)
    assert f.evidence["source"] == "ifeo" and f.risk == Risk.HIGH
    assert f.id == make_finding_id("autoruns", f"ifeo|{IFEO}\\notepad.exe")
    (a,) = f.actions
    assert a.kind == "delete_reg_value" and a.target == IFEO + r"\notepad.exe"
    assert a.param("name") == "Debugger" and a.high_risk


def test_startup_shortcut_quarantine_action():
    s = FakeSystem()
    startup = s.known_folders()["Startup"]
    lnk = startup + r"\Ludashi.lnk"
    target = r"C:\Program Files\Ludashi\ComputerZTray.exe"
    s.add_shortcut(lnk, ShortcutInfo(target, "/autorun"))
    s.set_signature(target, SignatureInfo("unsigned", ""))
    s.add_file(startup + r"\desktop.ini", hidden=True, system=True)
    (f,) = scan_autoruns(s)
    assert f.evidence["source"] == "startup" and f.vendor == "鲁大师" and f.risk == Risk.MEDIUM
    assert f.evidence["exe"] == target
    assert f.evidence["command"] == f'"{target}" /autorun'
    assert f.id == make_finding_id("autoruns", f"startup|{lnk}")
    (a,) = f.actions
    assert a.kind == "quarantine_path" and a.target == lnk


def test_startup_plain_file_uses_own_path_and_missing_folder_skipped():
    s = FakeSystem()
    assert scan_autoruns(s) == []
    p = s.known_folders()["CommonStartup"] + r"\helper.bat"
    s.add_file(p)
    (f,) = scan_autoruns(s)
    assert f.evidence["exe"] == p and f.risk == Risk.LOW
    assert f.actions[0].target == p


def test_denied_services_do_not_drop_other_sources():
    s = FakeSystem()
    s.add_key(RUN, {"X": r"C:\t\x.exe"})

    def denied() -> list[ServiceInfo]:
        raise AccessDenied("scm")

    s.list_services = denied
    assert len(scan_autoruns(s)) == 1


# ---- one broken source or entry never loses the rest (R19) ------------------------------------

def _wps_run(s):
    s.add_key(RUN, {"WPSCloud": f'"{WPS_EXE}" /tray'})
    s.set_signature(WPS_EXE, SignatureInfo("valid", "Zhuhai Kingsoft Office Software Co., Ltd."))


def test_task_listing_oserror_keeps_run_finding_and_is_reported():
    from app_triage.scanners.base import PartialScanError, run_scan
    s = FakeSystem()
    _wps_run(s)

    def broken() -> list[TaskInfo]:
        raise OSError("ScheduledTasks: exit code 1")

    s.list_tasks = broken
    with pytest.raises(PartialScanError) as info:
        scan_autoruns(s)
    assert [f.evidence["name"] for f in info.value.findings] == ["WPSCloud"]
    r = run_scan(s, ["autoruns"])
    assert [f.evidence["name"] for f in r.findings] == ["WPSCloud"]
    assert "计划任务" in r.errors["autoruns"] and "OSError" in r.errors["autoruns"]


def test_timeout_and_bad_json_in_services_keep_other_sources():
    import subprocess
    from app_triage.scanners.base import PartialScanError
    for exc in (subprocess.TimeoutExpired("powershell", 180), ValueError("bad json")):
        s = FakeSystem()
        _wps_run(s)

        def broken(exc=exc) -> list[ServiceInfo]:
            raise exc

        s.list_services = broken
        with pytest.raises(PartialScanError) as info:
            scan_autoruns(s)
        assert len(info.value.findings) == 1 and "服务" in str(info.value)


def test_one_broken_entry_does_not_drop_its_siblings():
    from app_triage.scanners.base import PartialScanError
    s = FakeSystem()
    s.add_key(RUN, {"Bad": r"C:\t\bad.exe", "Good": r"C:\t\good.exe"})
    real = s.get_signature

    def flaky(path):
        if path.lower().endswith("bad.exe"):
            raise RuntimeError("com_error")
        return real(path)

    s.get_signature = flaky
    with pytest.raises(PartialScanError) as info:
        scan_autoruns(s)
    assert [f.evidence["name"] for f in info.value.findings] == ["Good"]
    assert "Bad" in str(info.value)


def test_shortcut_com_error_still_reports_the_startup_entry():
    from app_triage.scanners.base import PartialScanError
    s = FakeSystem()
    lnk = s.known_folders()["Startup"] + r"\Thing.lnk"
    s.add_file(lnk)

    def com_error(path):
        raise RuntimeError("(-2147352567, 'Exception occurred.')")

    s.read_shortcut = com_error
    with pytest.raises(PartialScanError) as info:
        scan_autoruns(s)
    (f,) = info.value.findings
    assert f.evidence["source"] == "startup" and f.actions[0].target == lnk
